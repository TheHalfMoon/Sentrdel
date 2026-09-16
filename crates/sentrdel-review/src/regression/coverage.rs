//! Stable, bounded pairing for canonical Coverage records across an exact S1 revision pair.
//!
//! This substrate compares Coverage identity and preserves bilateral state/reason/input-digest
//! history. It deliberately creates no security disposition, canonical Finding, policy decision,
//! verification claim, network access, provider access, or target-execution authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::{CanonicalError, content_id};
use sentrdel_schema::coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension};

use crate::regression::model::{
    CoveragePair, CoveragePairCompatibility, RegressionLimits, RegressionModelError,
};

const NONE_IDENTITY: &str = "<NONE>";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoveragePairingSide {
    TrustedBase,
    Candidate,
}

impl CoveragePairingSide {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedBase => "TRUSTED_BASE",
            Self::Candidate => "CANDIDATE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoverageCompatibilityDiagnostic {
    ProducerMismatch {
        capability: String,
        scope: String,
        provider_dimension: String,
        base_producers: Vec<String>,
        candidate_producers: Vec<String>,
    },
    ProviderDimensionMismatch {
        capability: String,
        scope: String,
        producer: String,
        base_dimensions: Vec<String>,
        candidate_dimensions: Vec<String>,
    },
}

impl CoverageCompatibilityDiagnostic {
    fn sort_key(&self) -> (&str, &str, &'static str, &str) {
        match self {
            Self::ProducerMismatch {
                capability,
                scope,
                provider_dimension,
                ..
            } => (capability, scope, "PRODUCER_MISMATCH", provider_dimension),
            Self::ProviderDimensionMismatch {
                capability,
                scope,
                producer,
                ..
            } => (capability, scope, "PROVIDER_DIMENSION_MISMATCH", producer),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoveragePairingOutcome {
    pairs: Vec<CoveragePair>,
    diagnostics: Vec<CoverageCompatibilityDiagnostic>,
}

impl CoveragePairingOutcome {
    #[must_use]
    pub(crate) fn pairs(&self) -> &[CoveragePair] {
        &self.pairs
    }

    #[must_use]
    pub(crate) fn diagnostics(&self) -> &[CoverageCompatibilityDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Debug)]
pub(crate) enum CoveragePairingError {
    Limits(RegressionModelError),
    Canonical(CanonicalError),
    EmptyIdentityField {
        side: CoveragePairingSide,
        coverage_id: String,
        field: &'static str,
    },
    FieldTooLarge {
        side: CoveragePairingSide,
        coverage_id: String,
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    TooManyCoverageRecords {
        side: CoveragePairingSide,
        count: usize,
        max: usize,
    },
    TooManyInputDigests {
        side: CoveragePairingSide,
        coverage_id: String,
        count: usize,
        max: usize,
    },
    TooManyCoveragePairs {
        count: usize,
        max: usize,
    },
    DuplicateCoverageIdentity {
        side: CoveragePairingSide,
        comparison_key: String,
    },
    ConflictingCoverageIdentity {
        side: CoveragePairingSide,
        comparison_key: String,
    },
    TooManyDiagnostics {
        count: usize,
        max: usize,
    },
    TotalInputBytesExceeded {
        max: usize,
    },
    Pair(RegressionModelError),
}

impl fmt::Display for CoveragePairingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "invalid S1 Coverage pairing limits: {error}"),
            Self::Canonical(error) => {
                write!(formatter, "S1 Coverage pairing identity failed: {error}")
            }
            Self::EmptyIdentityField {
                side,
                coverage_id,
                field,
            } => write!(
                formatter,
                "S1 Coverage {} record {coverage_id:?} has empty identity field {field}",
                side.as_str()
            ),
            Self::FieldTooLarge {
                side,
                coverage_id,
                field,
                bytes,
                max,
            } => write!(
                formatter,
                "S1 Coverage {} record {coverage_id:?} field {field} size {bytes} exceeds cap {max}",
                side.as_str()
            ),
            Self::TooManyCoverageRecords { side, count, max } => write!(
                formatter,
                "S1 Coverage {} record count {count} exceeds cap {max}",
                side.as_str()
            ),
            Self::TooManyInputDigests {
                side,
                coverage_id,
                count,
                max,
            } => write!(
                formatter,
                "S1 Coverage {} record {coverage_id:?} input-digest count {count} exceeds cap {max}",
                side.as_str()
            ),
            Self::TooManyCoveragePairs { count, max } => write!(
                formatter,
                "S1 Coverage pair count {count} exceeds pair-result cap {max}"
            ),
            Self::DuplicateCoverageIdentity {
                side,
                comparison_key,
            } => write!(
                formatter,
                "duplicate S1 Coverage semantic identity on {} for comparison key {comparison_key:?}",
                side.as_str()
            ),
            Self::ConflictingCoverageIdentity {
                side,
                comparison_key,
            } => write!(
                formatter,
                "conflicting S1 Coverage semantic identity on {} for comparison key {comparison_key:?}",
                side.as_str()
            ),
            Self::TooManyDiagnostics { count, max } => write!(
                formatter,
                "S1 Coverage compatibility diagnostic count {count} exceeds cap {max}"
            ),
            Self::TotalInputBytesExceeded { max } => {
                write!(
                    formatter,
                    "S1 Coverage pairing input exceeds aggregate byte cap {max}"
                )
            }
            Self::Pair(error) => write!(formatter, "invalid S1 CoveragePair: {error}"),
        }
    }
}

impl Error for CoveragePairingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) | Self::Pair(error) => Some(error),
            Self::Canonical(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalError> for CoveragePairingError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedCoverage {
    capability: String,
    scope: String,
    producer: String,
    provider_dimension: String,
    state: CoverageState,
    reason: Option<String>,
    input_digests: Vec<String>,
}

/// Pair already-canonical snapshot Coverage records by exact
/// capability/scope/producer/provider-dimension identity.
///
/// The function preserves all existing Coverage states and bilateral reason/input-digest
/// history, retains base-only/candidate-only records, rejects duplicate/conflicting semantic
/// identities, and emits typed compatibility diagnostics for producer/provider-dimension drift.
/// It does not assign a security disposition.
pub(crate) fn pair_coverage_records(
    trusted_base: &[CoverageRecord],
    candidate: &[CoverageRecord],
    limits: RegressionLimits,
) -> Result<CoveragePairingOutcome, CoveragePairingError> {
    let limits = limits.validate().map_err(CoveragePairingError::Limits)?;
    let mut accounted_bytes = 0usize;
    let base = normalize_side(
        trusted_base,
        CoveragePairingSide::TrustedBase,
        limits,
        &mut accounted_bytes,
    )?;
    let candidate = normalize_side(
        candidate,
        CoveragePairingSide::Candidate,
        limits,
        &mut accounted_bytes,
    )?;

    let keys = base
        .keys()
        .chain(candidate.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    if keys.len() > limits.max_pair_results {
        return Err(CoveragePairingError::TooManyCoveragePairs {
            count: keys.len(),
            max: limits.max_pair_results,
        });
    }
    let mut pairs = Vec::with_capacity(keys.len());
    for key in keys {
        let base_record = base.get(&key);
        let candidate_record = candidate.get(&key);
        let compatibility = match (base_record, candidate_record) {
            (Some(_), Some(_)) => CoveragePairCompatibility::Compatible,
            (Some(_), None) => CoveragePairCompatibility::BaseOnly,
            (None, Some(_)) => CoveragePairCompatibility::CandidateOnly,
            (None, None) => unreachable!("union key must exist on at least one side"),
        };
        let pair = CoveragePair::new(
            key,
            base_record.map(|record| record.state.clone()),
            candidate_record.map(|record| record.state.clone()),
            base_record.and_then(|record| record.reason.clone()),
            candidate_record.and_then(|record| record.reason.clone()),
            base_record
                .map(|record| record.input_digests.clone())
                .unwrap_or_default(),
            candidate_record
                .map(|record| record.input_digests.clone())
                .unwrap_or_default(),
            compatibility,
            limits,
        )
        .map_err(CoveragePairingError::Pair)?;
        pairs.push(pair);
    }

    let diagnostics = compatibility_diagnostics(&base, &candidate, limits)?;
    Ok(CoveragePairingOutcome { pairs, diagnostics })
}

fn normalize_side(
    records: &[CoverageRecord],
    side: CoveragePairingSide,
    limits: RegressionLimits,
    accounted_bytes: &mut usize,
) -> Result<BTreeMap<String, NormalizedCoverage>, CoveragePairingError> {
    if records.len() > limits.max_snapshot_coverage_records {
        return Err(CoveragePairingError::TooManyCoverageRecords {
            side,
            count: records.len(),
            max: limits.max_snapshot_coverage_records,
        });
    }

    let mut normalized: BTreeMap<String, NormalizedCoverage> = BTreeMap::new();
    for record in records {
        validate_record_text(record, side, limits)?;
        if record.input_digests.len() > limits.max_coverage_input_digests_per_record {
            return Err(CoveragePairingError::TooManyInputDigests {
                side,
                coverage_id: record.coverage_id.clone(),
                count: record.input_digests.len(),
                max: limits.max_coverage_input_digests_per_record,
            });
        }

        account_bytes(
            accounted_bytes,
            record.coverage_id.len(),
            limits.max_total_input_bytes,
        )?;
        account_bytes(
            accounted_bytes,
            record.capability.len(),
            limits.max_total_input_bytes,
        )?;
        account_bytes(
            accounted_bytes,
            record.scope.len(),
            limits.max_total_input_bytes,
        )?;
        if let Some(producer) = record.producer.as_deref() {
            account_bytes(
                accounted_bytes,
                producer.len(),
                limits.max_total_input_bytes,
            )?;
        }
        if let Some(reason) = record.reason_code.as_deref() {
            account_bytes(accounted_bytes, reason.len(), limits.max_total_input_bytes)?;
        }

        let mut input_digests = BTreeSet::new();
        for digest in &record.input_digests {
            validate_text(digest, side, &record.coverage_id, "input_digest", limits)?;
            account_bytes(accounted_bytes, digest.len(), limits.max_total_input_bytes)?;
            input_digests.insert(digest.clone());
        }
        let input_digests = input_digests.into_iter().collect::<Vec<_>>();
        let producer = record
            .producer
            .clone()
            .unwrap_or_else(|| NONE_IDENTITY.to_owned());
        let provider_dimension =
            provider_dimension_name(record.provider_dimension.as_ref()).to_owned();
        let comparison_key = coverage_comparison_key(record)?;
        let value = NormalizedCoverage {
            capability: record.capability.clone(),
            scope: record.scope.clone(),
            producer,
            provider_dimension,
            state: record.state.clone(),
            reason: record.reason_code.clone(),
            input_digests,
        };

        if let Some(existing) = normalized.get(&comparison_key) {
            if existing.state == value.state
                && existing.reason == value.reason
                && existing.input_digests == value.input_digests
            {
                return Err(CoveragePairingError::DuplicateCoverageIdentity {
                    side,
                    comparison_key,
                });
            }
            return Err(CoveragePairingError::ConflictingCoverageIdentity {
                side,
                comparison_key,
            });
        }
        normalized.insert(comparison_key, value);
    }
    Ok(normalized)
}

fn validate_record_text(
    record: &CoverageRecord,
    side: CoveragePairingSide,
    limits: RegressionLimits,
) -> Result<(), CoveragePairingError> {
    validate_text(
        &record.coverage_id,
        side,
        &record.coverage_id,
        "coverage_id",
        limits,
    )?;
    validate_text(
        &record.capability,
        side,
        &record.coverage_id,
        "capability",
        limits,
    )?;
    validate_text(&record.scope, side, &record.coverage_id, "scope", limits)?;
    if let Some(producer) = record.producer.as_deref() {
        validate_text(producer, side, &record.coverage_id, "producer", limits)?;
    }
    if let Some(reason) = record.reason_code.as_deref() {
        validate_text(reason, side, &record.coverage_id, "reason_code", limits)?;
    }
    Ok(())
}

fn validate_text(
    value: &str,
    side: CoveragePairingSide,
    coverage_id: &str,
    field: &'static str,
    limits: RegressionLimits,
) -> Result<(), CoveragePairingError> {
    if value.trim().is_empty() {
        return Err(CoveragePairingError::EmptyIdentityField {
            side,
            coverage_id: coverage_id.to_owned(),
            field,
        });
    }
    if value.len() > limits.max_text_bytes {
        return Err(CoveragePairingError::FieldTooLarge {
            side,
            coverage_id: coverage_id.to_owned(),
            field,
            bytes: value.len(),
            max: limits.max_text_bytes,
        });
    }
    Ok(())
}

fn coverage_comparison_key(record: &CoverageRecord) -> Result<String, CanonicalError> {
    content_id(
        "s1-coverage-comparison-key",
        &(
            record.capability.as_str(),
            record.scope.as_str(),
            record.producer.as_deref().unwrap_or(NONE_IDENTITY),
            provider_dimension_name(record.provider_dimension.as_ref()),
        ),
    )
}

fn compatibility_diagnostics(
    base: &BTreeMap<String, NormalizedCoverage>,
    candidate: &BTreeMap<String, NormalizedCoverage>,
    limits: RegressionLimits,
) -> Result<Vec<CoverageCompatibilityDiagnostic>, CoveragePairingError> {
    let mut diagnostics = Vec::new();

    let base_by_dimension = group_producers_by_dimension(base.values());
    let candidate_by_dimension = group_producers_by_dimension(candidate.values());
    let dimension_keys = base_by_dimension
        .keys()
        .chain(candidate_by_dimension.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for key in dimension_keys {
        if let (Some(base_producers), Some(candidate_producers)) = (
            base_by_dimension.get(&key),
            candidate_by_dimension.get(&key),
        ) && base_producers != candidate_producers
        {
            let (capability, scope, provider_dimension) = key;
            diagnostics.push(CoverageCompatibilityDiagnostic::ProducerMismatch {
                capability,
                scope,
                provider_dimension,
                base_producers: base_producers.iter().cloned().collect(),
                candidate_producers: candidate_producers.iter().cloned().collect(),
            });
        }
    }

    let base_by_producer = group_dimensions_by_producer(base.values());
    let candidate_by_producer = group_dimensions_by_producer(candidate.values());
    let producer_keys = base_by_producer
        .keys()
        .chain(candidate_by_producer.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for key in producer_keys {
        if let (Some(base_dimensions), Some(candidate_dimensions)) =
            (base_by_producer.get(&key), candidate_by_producer.get(&key))
            && base_dimensions != candidate_dimensions
        {
            let (capability, scope, producer) = key;
            diagnostics.push(CoverageCompatibilityDiagnostic::ProviderDimensionMismatch {
                capability,
                scope,
                producer,
                base_dimensions: base_dimensions.iter().cloned().collect(),
                candidate_dimensions: candidate_dimensions.iter().cloned().collect(),
            });
        }
    }

    diagnostics.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    if diagnostics.len() > limits.max_diagnostics {
        return Err(CoveragePairingError::TooManyDiagnostics {
            count: diagnostics.len(),
            max: limits.max_diagnostics,
        });
    }
    Ok(diagnostics)
}

fn group_producers_by_dimension<'a>(
    records: impl Iterator<Item = &'a NormalizedCoverage>,
) -> BTreeMap<(String, String, String), BTreeSet<String>> {
    let mut groups = BTreeMap::new();
    for record in records {
        groups
            .entry((
                record.capability.clone(),
                record.scope.clone(),
                record.provider_dimension.clone(),
            ))
            .or_insert_with(BTreeSet::new)
            .insert(record.producer.clone());
    }
    groups
}

fn group_dimensions_by_producer<'a>(
    records: impl Iterator<Item = &'a NormalizedCoverage>,
) -> BTreeMap<(String, String, String), BTreeSet<String>> {
    let mut groups = BTreeMap::new();
    for record in records {
        groups
            .entry((
                record.capability.clone(),
                record.scope.clone(),
                record.producer.clone(),
            ))
            .or_insert_with(BTreeSet::new)
            .insert(record.provider_dimension.clone());
    }
    groups
}

fn provider_dimension_name(value: Option<&ProviderCoverageDimension>) -> &'static str {
    match value {
        Some(ProviderCoverageDimension::Detection) => "DETECTION",
        Some(ProviderCoverageDimension::StaticPosture) => "STATIC_POSTURE",
        Some(ProviderCoverageDimension::CredentialedLivePosture) => "CREDENTIALED_LIVE_POSTURE",
        Some(ProviderCoverageDimension::CrossLayerBusinessLogic) => "CROSS_LAYER_BUSINESS_LOGIC",
        None => NONE_IDENTITY,
    }
}

fn account_bytes(total: &mut usize, bytes: usize, max: usize) -> Result<(), CoveragePairingError> {
    *total = total
        .checked_add(bytes)
        .ok_or(CoveragePairingError::TotalInputBytesExceeded { max })?;
    if *total > max {
        return Err(CoveragePairingError::TotalInputBytesExceeded { max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::SCHEMA_V1;

    fn record(
        id: &str,
        capability: &str,
        producer: &str,
        dimension: ProviderCoverageDimension,
        state: CoverageState,
        reason: Option<&str>,
        digests: &[&str],
    ) -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: id.to_owned(),
            capability: capability.to_owned(),
            scope: ".".to_owned(),
            producer: Some(producer.to_owned()),
            provider_dimension: Some(dimension),
            state,
            reason_code: reason.map(str::to_owned),
            details: None,
            input_digests: digests.iter().map(|value| (*value).to_owned()).collect(),
            observed_at: "2026-09-16T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn exact_pairing_is_deterministic_and_preserves_every_coverage_state() {
        let states = [
            CoverageState::Covered,
            CoverageState::Partial,
            CoverageState::Unsupported,
            CoverageState::Unavailable,
            CoverageState::Failed,
            CoverageState::TimedOut,
            CoverageState::SkippedByPolicy,
        ];
        let mut base = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                record(
                    &format!("base:{index}"),
                    &format!("CAPABILITY_{index}"),
                    "sentrdel.r3.business-logic",
                    ProviderCoverageDimension::CrossLayerBusinessLogic,
                    state.clone(),
                    Some(&format!("BASE_REASON_{index}")),
                    &["sha256:z", "sha256:a", "sha256:a"],
                )
            })
            .collect::<Vec<_>>();
        let mut candidate = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                record(
                    &format!("candidate:{index}"),
                    &format!("CAPABILITY_{index}"),
                    "sentrdel.r3.business-logic",
                    ProviderCoverageDimension::CrossLayerBusinessLogic,
                    state.clone(),
                    Some(&format!("CANDIDATE_REASON_{index}")),
                    &["sha256:b", "sha256:a"],
                )
            })
            .collect::<Vec<_>>();

        let expected = base
            .iter()
            .zip(candidate.iter())
            .map(|(base_record, candidate_record)| {
                let key = coverage_comparison_key(base_record).expect("comparison key");
                assert_eq!(
                    key,
                    coverage_comparison_key(candidate_record).expect("candidate comparison key")
                );
                (
                    key,
                    (
                        base_record.state.clone(),
                        candidate_record.state.clone(),
                        base_record.reason_code.clone(),
                        candidate_record.reason_code.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let first = pair_coverage_records(&base, &candidate, RegressionLimits::default())
            .expect("coverage pairing");
        base.reverse();
        candidate.rotate_left(3);
        for record in &mut base {
            record.input_digests.reverse();
        }
        for record in &mut candidate {
            record.input_digests.reverse();
        }
        let replay = pair_coverage_records(&base, &candidate, RegressionLimits::default())
            .expect("coverage pairing replay");

        assert_eq!(first, replay);
        assert_eq!(first.pairs().len(), states.len());
        assert!(first.diagnostics().is_empty());
        for pair in first.pairs() {
            let expected = expected
                .get(pair.comparison_key())
                .expect("expected exact Coverage identity");
            assert_eq!(pair.base_state(), Some(&expected.0));
            assert_eq!(pair.candidate_state(), Some(&expected.1));
            assert_eq!(pair.base_reason(), expected.2.as_deref());
            assert_eq!(pair.candidate_reason(), expected.3.as_deref());
            assert_eq!(pair.compatibility(), CoveragePairCompatibility::Compatible);
            assert_eq!(pair.base_input_digests(), ["sha256:a", "sha256:z"]);
            assert_eq!(pair.candidate_input_digests(), ["sha256:a", "sha256:b"]);
        }
    }

    #[test]
    fn base_only_and_candidate_only_records_remain_explicit() {
        let base = vec![record(
            "base:only",
            "BASE_ONLY",
            "producer",
            ProviderCoverageDimension::StaticPosture,
            CoverageState::Failed,
            Some("BASE_FAILED"),
            &["sha256:base"],
        )];
        let candidate = vec![record(
            "candidate:only",
            "CANDIDATE_ONLY",
            "producer",
            ProviderCoverageDimension::StaticPosture,
            CoverageState::Unsupported,
            Some("CANDIDATE_UNSUPPORTED"),
            &["sha256:candidate"],
        )];

        let outcome = pair_coverage_records(&base, &candidate, RegressionLimits::default())
            .expect("one-sided pairing");
        assert_eq!(outcome.pairs().len(), 2);
        let base_only = outcome
            .pairs()
            .iter()
            .find(|pair| pair.base_state().is_some())
            .expect("base only");
        assert_eq!(base_only.candidate_state(), None);
        assert_eq!(
            base_only.compatibility(),
            CoveragePairCompatibility::BaseOnly
        );
        assert_eq!(base_only.base_reason(), Some("BASE_FAILED"));
        let candidate_only = outcome
            .pairs()
            .iter()
            .find(|pair| pair.candidate_state().is_some())
            .expect("candidate only");
        assert_eq!(candidate_only.base_state(), None);
        assert_eq!(
            candidate_only.compatibility(),
            CoveragePairCompatibility::CandidateOnly
        );
        assert_eq!(
            candidate_only.candidate_reason(),
            Some("CANDIDATE_UNSUPPORTED")
        );
    }

    #[test]
    fn producer_disappearance_remains_base_only_without_disposition() {
        let base = vec![record(
            "base:producer-disappeared",
            "BUSINESS_LOGIC",
            "sentrdel.r3.business-logic",
            ProviderCoverageDimension::CrossLayerBusinessLogic,
            CoverageState::Covered,
            Some("BASE_COVERED"),
            &["sha256:base"],
        )];

        let outcome = pair_coverage_records(&base, &[], RegressionLimits::default())
            .expect("producer disappearance remains explicit");
        assert_eq!(outcome.pairs().len(), 1);
        let pair = &outcome.pairs()[0];
        assert_eq!(pair.base_state(), Some(&CoverageState::Covered));
        assert_eq!(pair.candidate_state(), None);
        assert_eq!(pair.compatibility(), CoveragePairCompatibility::BaseOnly);
        assert_eq!(pair.base_reason(), Some("BASE_COVERED"));
        assert!(outcome.diagnostics().is_empty());
    }

    #[test]
    fn provider_dimension_drift_is_not_coerced_into_an_exact_pair() {
        let base = vec![record(
            "base:dimension",
            "PROVIDER_POSTURE",
            "producer",
            ProviderCoverageDimension::StaticPosture,
            CoverageState::Covered,
            None,
            &["sha256:base"],
        )];
        let candidate = vec![record(
            "candidate:dimension",
            "PROVIDER_POSTURE",
            "producer",
            ProviderCoverageDimension::CredentialedLivePosture,
            CoverageState::Covered,
            None,
            &["sha256:candidate"],
        )];

        let outcome = pair_coverage_records(&base, &candidate, RegressionLimits::default())
            .expect("dimension mismatch remains visible");
        assert_eq!(outcome.pairs().len(), 2);
        assert!(
            outcome
                .pairs()
                .iter()
                .all(|pair| { pair.compatibility() != CoveragePairCompatibility::Compatible })
        );
        assert!(matches!(
            outcome.diagnostics(),
            [CoverageCompatibilityDiagnostic::ProviderDimensionMismatch { .. }]
        ));
    }

    #[test]
    fn producer_drift_is_diagnosed_without_identity_coercion() {
        let base = vec![record(
            "base:producer",
            "BUSINESS_LOGIC",
            "producer:v1",
            ProviderCoverageDimension::CrossLayerBusinessLogic,
            CoverageState::Covered,
            None,
            &["sha256:base"],
        )];
        let candidate = vec![record(
            "candidate:producer",
            "BUSINESS_LOGIC",
            "producer:v2",
            ProviderCoverageDimension::CrossLayerBusinessLogic,
            CoverageState::Covered,
            None,
            &["sha256:candidate"],
        )];

        let outcome = pair_coverage_records(&base, &candidate, RegressionLimits::default())
            .expect("producer mismatch remains visible");
        assert_eq!(outcome.pairs().len(), 2);
        assert!(matches!(
            outcome.diagnostics(),
            [CoverageCompatibilityDiagnostic::ProducerMismatch { .. }]
        ));
    }

    #[test]
    fn duplicate_and_conflicting_semantic_identities_fail_closed() {
        let first = record(
            "coverage:first",
            "CAPABILITY",
            "producer",
            ProviderCoverageDimension::StaticPosture,
            CoverageState::Covered,
            Some("COVERED"),
            &["sha256:a"],
        );
        let duplicate = CoverageRecord {
            coverage_id: "coverage:duplicate".to_owned(),
            ..first.clone()
        };
        let duplicate_error = pair_coverage_records(
            &[first.clone(), duplicate],
            &[],
            RegressionLimits::default(),
        )
        .expect_err("duplicate identity must fail");
        assert!(matches!(
            duplicate_error,
            CoveragePairingError::DuplicateCoverageIdentity { .. }
        ));

        let conflicting = CoverageRecord {
            coverage_id: "coverage:conflicting".to_owned(),
            state: CoverageState::Failed,
            reason_code: Some("FAILED".to_owned()),
            ..first.clone()
        };
        let conflict_error =
            pair_coverage_records(&[first, conflicting], &[], RegressionLimits::default())
                .expect_err("conflicting identity must fail");
        assert!(matches!(
            conflict_error,
            CoveragePairingError::ConflictingCoverageIdentity { .. }
        ));
    }

    #[test]
    fn pairing_enforces_count_digest_and_aggregate_byte_caps() {
        let one = record(
            "coverage:one",
            "ONE",
            "producer",
            ProviderCoverageDimension::StaticPosture,
            CoverageState::Covered,
            None,
            &["sha256:a"],
        );
        let two = record(
            "coverage:two",
            "TWO",
            "producer",
            ProviderCoverageDimension::StaticPosture,
            CoverageState::Covered,
            None,
            &["sha256:b"],
        );
        let count_error = pair_coverage_records(
            &[one.clone(), two],
            &[],
            RegressionLimits {
                max_snapshot_coverage_records: 1,
                ..RegressionLimits::default()
            },
        )
        .expect_err("count cap");
        assert!(matches!(
            count_error,
            CoveragePairingError::TooManyCoverageRecords { .. }
        ));

        let digest_error = pair_coverage_records(
            &[CoverageRecord {
                input_digests: vec!["sha256:a".to_owned(), "sha256:b".to_owned()],
                ..one.clone()
            }],
            &[],
            RegressionLimits {
                max_coverage_input_digests_per_record: 1,
                ..RegressionLimits::default()
            },
        )
        .expect_err("digest cap");
        assert!(matches!(
            digest_error,
            CoveragePairingError::TooManyInputDigests { .. }
        ));

        let pair_count_error = pair_coverage_records(
            &[one.clone()],
            &[record(
                "coverage:candidate-only",
                "CANDIDATE_ONLY",
                "producer",
                ProviderCoverageDimension::StaticPosture,
                CoverageState::Partial,
                Some("PARTIAL"),
                &["sha256:candidate"],
            )],
            RegressionLimits {
                max_pair_results: 1,
                ..RegressionLimits::default()
            },
        )
        .expect_err("pair-result cap");
        assert!(matches!(
            pair_count_error,
            CoveragePairingError::TooManyCoveragePairs { count: 2, max: 1 }
        ));

        let byte_error = pair_coverage_records(
            &[one],
            &[],
            RegressionLimits {
                max_total_input_bytes: 8,
                ..RegressionLimits::default()
            },
        )
        .expect_err("aggregate byte cap");
        assert!(matches!(
            byte_error,
            CoveragePairingError::TotalInputBytesExceeded { .. }
        ));
    }
}
