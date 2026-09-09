//! Bilateral bounded Evidence/provenance preservation for S1 comparisons.
//!
//! Selected support is accepted only when it already belongs to the validated
//! trusted-base or candidate `SemanticSnapshot`. The two histories remain
//! physically separate after deterministic normalization. This module does not
//! mint Evidence, create Findings, infer continuity, or produce dispositions.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::{CanonicalError, content_id};

use crate::business_logic::model::SourceLocation;
use crate::regression::model::{RegressionLimits, RegressionModelError, RevisionPair};
use crate::regression::snapshot::{
    SemanticSnapshot, SnapshotCompositionError, validate_snapshot_pair,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SideSupport {
    evidence_refs: Vec<String>,
    provenance_refs: Vec<String>,
}

impl SideSupport {
    #[must_use]
    pub(crate) fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    #[must_use]
    pub(crate) fn provenance_refs(&self) -> &[String] {
        &self.provenance_refs
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BilateralSupport {
    trusted_base: SideSupport,
    candidate: SideSupport,
}

impl BilateralSupport {
    #[must_use]
    pub(crate) fn trusted_base(&self) -> &SideSupport {
        &self.trusted_base
    }

    #[must_use]
    pub(crate) fn candidate(&self) -> &SideSupport {
        &self.candidate
    }
}

#[derive(Debug)]
pub(crate) enum BilateralSupportError {
    Limits(RegressionModelError),
    Snapshot(SnapshotCompositionError),
    TooManyEvidenceRefs {
        side: &'static str,
        count: usize,
        max: usize,
    },
    TooManyProvenanceRefs {
        side: &'static str,
        count: usize,
        max: usize,
    },
    EmptyEvidenceRef {
        side: &'static str,
    },
    EvidenceRefTooLarge {
        side: &'static str,
        bytes: usize,
        max: usize,
    },
    ProvenanceFieldTooLarge {
        side: &'static str,
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    UnknownEvidenceRef {
        side: &'static str,
        evidence_ref: String,
    },
    UnknownProvenanceRef {
        side: &'static str,
        provenance_ref: String,
    },
    ProvenanceIdentity {
        side: &'static str,
        source: CanonicalError,
    },
    TotalInputBytesExceeded {
        max: usize,
    },
}

impl fmt::Display for BilateralSupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "invalid bilateral-support limits: {error}"),
            Self::Snapshot(error) => write!(formatter, "snapshot pair is not comparable: {error}"),
            Self::TooManyEvidenceRefs { side, count, max } => write!(
                formatter,
                "{side} evidence reference count {count} exceeds configured maximum {max}"
            ),
            Self::TooManyProvenanceRefs { side, count, max } => write!(
                formatter,
                "{side} provenance reference count {count} exceeds configured maximum {max}"
            ),
            Self::EmptyEvidenceRef { side } => {
                write!(formatter, "{side} evidence reference must not be empty")
            }
            Self::EvidenceRefTooLarge { side, bytes, max } => write!(
                formatter,
                "{side} evidence reference size {bytes} exceeds configured maximum {max}"
            ),
            Self::ProvenanceFieldTooLarge {
                side,
                field,
                bytes,
                max,
            } => write!(
                formatter,
                "{side} provenance {field} size {bytes} exceeds configured maximum {max}"
            ),
            Self::UnknownEvidenceRef { side, evidence_ref } => write!(
                formatter,
                "{side} evidence reference is not present in its validated snapshot: {evidence_ref}"
            ),
            Self::UnknownProvenanceRef {
                side,
                provenance_ref,
            } => write!(
                formatter,
                "{side} provenance reference is not present in its validated snapshot: {provenance_ref}"
            ),
            Self::ProvenanceIdentity { side, source } => {
                write!(
                    formatter,
                    "cannot derive {side} provenance identity: {source}"
                )
            }
            Self::TotalInputBytesExceeded { max } => write!(
                formatter,
                "bilateral support input exceeds configured total byte maximum {max}"
            ),
        }
    }
}

impl Error for BilateralSupportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::ProvenanceIdentity { source, .. } => Some(source),
            Self::TooManyEvidenceRefs { .. }
            | Self::TooManyProvenanceRefs { .. }
            | Self::EmptyEvidenceRef { .. }
            | Self::EvidenceRefTooLarge { .. }
            | Self::ProvenanceFieldTooLarge { .. }
            | Self::UnknownEvidenceRef { .. }
            | Self::UnknownProvenanceRef { .. }
            | Self::TotalInputBytesExceeded { .. } => None,
        }
    }
}

/// Preserve selected canonical support for both sides without allowing either
/// side to replace, collapse, or authorize the other.
///
/// Every selected Evidence ID must already be present in the corresponding
/// validated snapshot. Every selected provenance location must already occur in
/// that snapshot's canonical invariant definitions or evaluations. The function
/// validates the exact revision pair and producer/config/schema compatibility
/// before accepting support. Sorting/deduplication occurs independently per side.
#[allow(clippy::too_many_arguments)]
pub(crate) fn preserve_bilateral_support(
    pair: &RevisionPair,
    trusted_base: &SemanticSnapshot,
    trusted_base_evidence_refs: Vec<String>,
    trusted_base_provenance: &[SourceLocation],
    candidate: &SemanticSnapshot,
    candidate_evidence_refs: Vec<String>,
    candidate_provenance: &[SourceLocation],
    limits: RegressionLimits,
) -> Result<BilateralSupport, BilateralSupportError> {
    let limits = limits.validate().map_err(BilateralSupportError::Limits)?;
    validate_snapshot_pair(pair, trusted_base, candidate)
        .map_err(BilateralSupportError::Snapshot)?;

    let base_known_evidence = trusted_base
        .evidence_refs()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let candidate_known_evidence = candidate
        .evidence_refs()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let base_known_provenance = snapshot_provenance_refs("TRUSTED_BASE", trusted_base)?;
    let candidate_known_provenance = snapshot_provenance_refs("CANDIDATE", candidate)?;

    let mut total_input_bytes = 0usize;
    let trusted_base = normalize_side_support(
        "TRUSTED_BASE",
        trusted_base_evidence_refs,
        trusted_base_provenance,
        &base_known_evidence,
        &base_known_provenance,
        limits,
        &mut total_input_bytes,
    )?;
    let candidate = normalize_side_support(
        "CANDIDATE",
        candidate_evidence_refs,
        candidate_provenance,
        &candidate_known_evidence,
        &candidate_known_provenance,
        limits,
        &mut total_input_bytes,
    )?;

    Ok(BilateralSupport {
        trusted_base,
        candidate,
    })
}

fn snapshot_provenance_refs(
    side: &'static str,
    snapshot: &SemanticSnapshot,
) -> Result<BTreeSet<String>, BilateralSupportError> {
    let mut refs = BTreeSet::new();
    for definition in snapshot.invariant_definitions() {
        for location in definition.provenance() {
            refs.insert(provenance_ref(side, location)?);
        }
    }
    for evaluation in snapshot.invariant_evaluations() {
        for location in evaluation.provenance() {
            refs.insert(provenance_ref(side, location)?);
        }
    }
    Ok(refs)
}

#[allow(clippy::too_many_arguments)]
fn normalize_side_support(
    side: &'static str,
    evidence_refs: Vec<String>,
    provenance: &[SourceLocation],
    known_evidence_refs: &BTreeSet<&str>,
    known_provenance_refs: &BTreeSet<String>,
    limits: RegressionLimits,
    total_input_bytes: &mut usize,
) -> Result<SideSupport, BilateralSupportError> {
    if evidence_refs.len() > limits.max_evidence_refs_per_result {
        return Err(BilateralSupportError::TooManyEvidenceRefs {
            side,
            count: evidence_refs.len(),
            max: limits.max_evidence_refs_per_result,
        });
    }
    if provenance.len() > limits.max_provenance_refs_per_result {
        return Err(BilateralSupportError::TooManyProvenanceRefs {
            side,
            count: provenance.len(),
            max: limits.max_provenance_refs_per_result,
        });
    }

    let mut normalized_evidence = BTreeSet::new();
    for evidence_ref in evidence_refs {
        if evidence_ref.trim().is_empty() {
            return Err(BilateralSupportError::EmptyEvidenceRef { side });
        }
        if evidence_ref.len() > limits.max_text_bytes {
            return Err(BilateralSupportError::EvidenceRefTooLarge {
                side,
                bytes: evidence_ref.len(),
                max: limits.max_text_bytes,
            });
        }
        account_input_bytes(
            total_input_bytes,
            evidence_ref.len(),
            limits.max_total_input_bytes,
        )?;
        if !known_evidence_refs.contains(evidence_ref.as_str()) {
            return Err(BilateralSupportError::UnknownEvidenceRef { side, evidence_ref });
        }
        normalized_evidence.insert(evidence_ref);
    }

    let mut normalized_provenance = BTreeSet::new();
    for location in provenance {
        let path = location.path().as_str();
        let content_digest = location.content_digest();
        validate_provenance_text(side, "path", path, limits.max_text_bytes)?;
        validate_provenance_text(
            side,
            "content_digest",
            content_digest,
            limits.max_text_bytes,
        )?;
        account_input_bytes(total_input_bytes, path.len(), limits.max_total_input_bytes)?;
        account_input_bytes(
            total_input_bytes,
            content_digest.len(),
            limits.max_total_input_bytes,
        )?;
        account_input_bytes(
            total_input_bytes,
            2 * std::mem::size_of::<usize>(),
            limits.max_total_input_bytes,
        )?;
        let reference = provenance_ref(side, location)?;
        if !known_provenance_refs.contains(&reference) {
            return Err(BilateralSupportError::UnknownProvenanceRef {
                side,
                provenance_ref: reference,
            });
        }
        normalized_provenance.insert(reference);
    }

    Ok(SideSupport {
        evidence_refs: normalized_evidence.into_iter().collect(),
        provenance_refs: normalized_provenance.into_iter().collect(),
    })
}

fn validate_provenance_text(
    side: &'static str,
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), BilateralSupportError> {
    if value.len() > max {
        return Err(BilateralSupportError::ProvenanceFieldTooLarge {
            side,
            field,
            bytes: value.len(),
            max,
        });
    }
    Ok(())
}

fn provenance_ref(
    side: &'static str,
    location: &SourceLocation,
) -> Result<String, BilateralSupportError> {
    content_id(
        "s1-bilateral-provenance-ref",
        &(
            location.path().as_str(),
            location.start_byte(),
            location.end_byte(),
            location.content_digest(),
        ),
    )
    .map_err(|source| BilateralSupportError::ProvenanceIdentity { side, source })
}

fn account_input_bytes(
    total: &mut usize,
    bytes: usize,
    max: usize,
) -> Result<(), BilateralSupportError> {
    *total = total
        .checked_add(bytes)
        .ok_or(BilateralSupportError::TotalInputBytesExceeded { max })?;
    if *total > max {
        return Err(BilateralSupportError::TotalInputBytesExceeded { max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath};

    fn location(path: &str, start: usize, digest: &str) -> SourceLocation {
        SourceLocation::new(
            NormalizedRepoPath::parse(path, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path"),
            start,
            start + 4,
            digest.to_owned(),
        )
        .expect("source location")
    }

    fn known_provenance(side: &'static str, locations: &[SourceLocation]) -> BTreeSet<String> {
        locations
            .iter()
            .map(|location| provenance_ref(side, location).expect("provenance identity"))
            .collect()
    }

    #[test]
    fn side_normalization_is_deterministic_and_does_not_cross_overwrite() {
        let base_locations = vec![
            location("src/base.ts", 8, "sha256:base-b"),
            location("src/base.ts", 0, "sha256:base-a"),
        ];
        let candidate_locations = vec![location("src/candidate.ts", 4, "sha256:candidate")];
        let base_known_evidence = ["base-only", "shared"].into_iter().collect();
        let candidate_known_evidence = ["candidate-only", "shared"].into_iter().collect();
        let base_known_provenance = known_provenance("TRUSTED_BASE", &base_locations);
        let candidate_known_provenance = known_provenance("CANDIDATE", &candidate_locations);
        let limits = RegressionLimits::default();

        let mut first_total = 0;
        let first_base = normalize_side_support(
            "TRUSTED_BASE",
            vec![
                "shared".to_owned(),
                "base-only".to_owned(),
                "shared".to_owned(),
            ],
            &[base_locations[0].clone(), base_locations[1].clone()],
            &base_known_evidence,
            &base_known_provenance,
            limits,
            &mut first_total,
        )
        .expect("first base support");
        let first_candidate = normalize_side_support(
            "CANDIDATE",
            vec!["shared".to_owned(), "candidate-only".to_owned()],
            &candidate_locations,
            &candidate_known_evidence,
            &candidate_known_provenance,
            limits,
            &mut first_total,
        )
        .expect("first candidate support");
        let first = BilateralSupport {
            trusted_base: first_base,
            candidate: first_candidate,
        };

        let mut second_total = 0;
        let second_base = normalize_side_support(
            "TRUSTED_BASE",
            vec!["base-only".to_owned(), "shared".to_owned()],
            &[base_locations[1].clone(), base_locations[0].clone()],
            &base_known_evidence,
            &base_known_provenance,
            limits,
            &mut second_total,
        )
        .expect("second base support");
        let second_candidate = normalize_side_support(
            "CANDIDATE",
            vec!["candidate-only".to_owned(), "shared".to_owned()],
            &candidate_locations,
            &candidate_known_evidence,
            &candidate_known_provenance,
            limits,
            &mut second_total,
        )
        .expect("second candidate support");
        let second = BilateralSupport {
            trusted_base: second_base,
            candidate: second_candidate,
        };

        assert_eq!(first, second);
        assert_eq!(
            first.trusted_base().evidence_refs(),
            &["base-only".to_owned(), "shared".to_owned()]
        );
        assert_eq!(
            first.candidate().evidence_refs(),
            &["candidate-only".to_owned(), "shared".to_owned()]
        );
        assert_ne!(
            first.trusted_base().provenance_refs(),
            first.candidate().provenance_refs()
        );
    }

    #[test]
    fn unknown_side_evidence_and_provenance_fail_closed() {
        let known_location = location("src/base.ts", 0, "sha256:known");
        let unknown_location = location("src/other.ts", 0, "sha256:unknown");
        let known_evidence = ["known"].into_iter().collect();
        let known_provenance = known_provenance("TRUSTED_BASE", &[known_location]);
        let limits = RegressionLimits::default();

        let mut evidence_total = 0;
        let evidence_error = normalize_side_support(
            "TRUSTED_BASE",
            vec!["forged".to_owned()],
            &[],
            &known_evidence,
            &known_provenance,
            limits,
            &mut evidence_total,
        )
        .expect_err("unknown evidence must fail");
        assert!(matches!(
            evidence_error,
            BilateralSupportError::UnknownEvidenceRef {
                side: "TRUSTED_BASE",
                ..
            }
        ));

        let mut provenance_total = 0;
        let provenance_error = normalize_side_support(
            "TRUSTED_BASE",
            vec![],
            &[unknown_location],
            &known_evidence,
            &known_provenance,
            limits,
            &mut provenance_total,
        )
        .expect_err("unknown provenance must fail");
        assert!(matches!(
            provenance_error,
            BilateralSupportError::UnknownProvenanceRef {
                side: "TRUSTED_BASE",
                ..
            }
        ));
    }

    #[test]
    fn raw_count_caps_apply_before_deduplication() {
        let known_evidence = ["same"].into_iter().collect();
        let known_provenance = BTreeSet::new();
        let limits = RegressionLimits {
            max_evidence_refs_per_result: 1,
            ..RegressionLimits::default()
        };
        let mut total = 0;
        let error = normalize_side_support(
            "CANDIDATE",
            vec!["same".to_owned(), "same".to_owned()],
            &[],
            &known_evidence,
            &known_provenance,
            limits,
            &mut total,
        )
        .expect_err("duplicate input must not bypass count cap");
        assert!(matches!(
            error,
            BilateralSupportError::TooManyEvidenceRefs {
                side: "CANDIDATE",
                count: 2,
                max: 1,
            }
        ));
    }

    #[test]
    fn invalid_evidence_text_and_total_bytes_fail_visible() {
        let known_evidence = ["known", "12345"].into_iter().collect();
        let known_provenance = BTreeSet::new();

        let mut empty_total = 0;
        let empty = normalize_side_support(
            "TRUSTED_BASE",
            vec!["   ".to_owned()],
            &[],
            &known_evidence,
            &known_provenance,
            RegressionLimits::default(),
            &mut empty_total,
        )
        .expect_err("blank evidence must fail");
        assert!(matches!(
            empty,
            BilateralSupportError::EmptyEvidenceRef {
                side: "TRUSTED_BASE"
            }
        ));

        let mut byte_total = 0;
        let byte_limits = RegressionLimits {
            max_total_input_bytes: 4,
            ..RegressionLimits::default()
        };
        let exhausted = normalize_side_support(
            "CANDIDATE",
            vec!["12345".to_owned()],
            &[],
            &known_evidence,
            &known_provenance,
            byte_limits,
            &mut byte_total,
        )
        .expect_err("byte cap exhaustion must fail");
        assert!(matches!(
            exhausted,
            BilateralSupportError::TotalInputBytesExceeded { max: 4 }
        ));
    }

    #[test]
    fn provenance_text_limits_are_enforced_per_field_with_inclusive_boundary() {
        let path_too_large = location("abcde", 0, "d");
        let path_known = known_provenance("TRUSTED_BASE", std::slice::from_ref(&path_too_large));
        let no_evidence = BTreeSet::new();
        let limits = RegressionLimits {
            max_text_bytes: 4,
            ..RegressionLimits::default()
        };
        let mut path_total = 0;
        let path_error = normalize_side_support(
            "TRUSTED_BASE",
            vec![],
            &[path_too_large],
            &no_evidence,
            &path_known,
            limits,
            &mut path_total,
        )
        .expect_err("oversized provenance path must fail");
        assert!(matches!(
            path_error,
            BilateralSupportError::ProvenanceFieldTooLarge {
                side: "TRUSTED_BASE",
                field: "path",
                bytes: 5,
                max: 4,
            }
        ));

        let digest_too_large = location("a", 0, "12345");
        let digest_known = known_provenance("CANDIDATE", std::slice::from_ref(&digest_too_large));
        let mut digest_total = 0;
        let digest_error = normalize_side_support(
            "CANDIDATE",
            vec![],
            &[digest_too_large],
            &no_evidence,
            &digest_known,
            limits,
            &mut digest_total,
        )
        .expect_err("oversized provenance digest must fail");
        assert!(matches!(
            digest_error,
            BilateralSupportError::ProvenanceFieldTooLarge {
                side: "CANDIDATE",
                field: "content_digest",
                bytes: 5,
                max: 4,
            }
        ));

        let at_boundary = location("abcd", 0, "1234");
        let boundary_known = known_provenance("TRUSTED_BASE", std::slice::from_ref(&at_boundary));
        let mut boundary_total = 0;
        let boundary = normalize_side_support(
            "TRUSTED_BASE",
            vec![],
            &[at_boundary],
            &no_evidence,
            &boundary_known,
            limits,
            &mut boundary_total,
        )
        .expect("provenance fields exactly at max_text_bytes must remain valid");
        assert_eq!(boundary.provenance_refs().len(), 1);
    }

    #[test]
    fn provenance_identity_is_stable_and_side_label_is_not_identity_material() {
        let value = location("src/stable.ts", 12, "sha256:stable");
        let base = provenance_ref("TRUSTED_BASE", &value).expect("base provenance");
        let candidate = provenance_ref("CANDIDATE", &value).expect("candidate provenance");
        assert_eq!(base, candidate);
    }
}
