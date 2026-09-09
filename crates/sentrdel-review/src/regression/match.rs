//! Stable keyed invariant matching for S1 semantic snapshots.
//!
//! Matching is exact on Sentrdel-owned stable invariant identity. Definition
//! compatibility is determined from a normalized semantic digest covering kind,
//! source/authority, scope, and requirements. Provenance, lexical similarity,
//! graph proximity, edit distance, and model judgment cannot create identity.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::business_logic::model::InvariantDefinition;
use crate::regression::model::{
    ContinuityBasis, PairPresence, RegressionLimits, RegressionModelError, RevisionPair,
};
use crate::regression::snapshot::{
    SemanticSnapshot, SnapshotCompositionError, derive_invariant_definition_digest,
    validate_snapshot_pair,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvariantDefinitionCompatibility {
    Compatible,
    Conflict,
    Unpaired,
}

impl InvariantDefinitionCompatibility {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "COMPATIBLE",
            Self::Conflict => "INVARIANT_DEFINITION_CONFLICT",
            Self::Unpaired => "UNPAIRED",
        }
    }

    #[must_use]
    pub const fn is_compatible(self) -> bool {
        matches!(self, Self::Compatible)
    }

    #[must_use]
    pub const fn is_conflict(self) -> bool {
        matches!(self, Self::Conflict)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantMatch {
    stable_invariant_id: String,
    pair_presence: PairPresence,
    continuity_basis: ContinuityBasis,
    base_definition_digest: Option<String>,
    candidate_definition_digest: Option<String>,
    definition_compatibility: InvariantDefinitionCompatibility,
}

impl InvariantMatch {
    #[must_use]
    pub fn stable_invariant_id(&self) -> &str {
        &self.stable_invariant_id
    }

    #[must_use]
    pub const fn pair_presence(&self) -> PairPresence {
        self.pair_presence
    }

    #[must_use]
    pub const fn continuity_basis(&self) -> ContinuityBasis {
        self.continuity_basis
    }

    #[must_use]
    pub fn base_definition_digest(&self) -> Option<&str> {
        self.base_definition_digest.as_deref()
    }

    #[must_use]
    pub fn candidate_definition_digest(&self) -> Option<&str> {
        self.candidate_definition_digest.as_deref()
    }

    #[must_use]
    pub const fn definition_compatibility(&self) -> InvariantDefinitionCompatibility {
        self.definition_compatibility
    }

    /// Return true only for an exact stable-ID pair with compatible semantics.
    ///
    /// A definition conflict is deliberately not a valid comparable match even
    /// though both sides share the same stable key.
    #[must_use]
    pub const fn is_comparable_match(&self) -> bool {
        matches!(self.pair_presence, PairPresence::Matched)
            && self.definition_compatibility.is_compatible()
    }
}

#[derive(Debug)]
pub enum InvariantMatchError {
    Limits(RegressionModelError),
    Snapshot(SnapshotCompositionError),
    DuplicateStableId {
        side: &'static str,
        invariant_id: String,
    },
    DefinitionDigest {
        side: &'static str,
        invariant_id: String,
        source: RegressionModelError,
    },
    TooManyMatchResults {
        count: usize,
        max: usize,
    },
}

impl fmt::Display for InvariantMatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "invalid invariant-match limits: {error}"),
            Self::Snapshot(error) => write!(formatter, "snapshot pair is not comparable: {error}"),
            Self::DuplicateStableId { side, invariant_id } => write!(
                formatter,
                "duplicate invariant stable ID on {side}: {invariant_id}"
            ),
            Self::DefinitionDigest {
                side,
                invariant_id,
                source,
            } => write!(
                formatter,
                "cannot derive {side} invariant definition digest for {invariant_id}: {source}"
            ),
            Self::TooManyMatchResults { count, max } => write!(
                formatter,
                "invariant match result count {count} exceeds configured maximum {max}"
            ),
        }
    }
}

impl Error for InvariantMatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::DefinitionDigest { source, .. } => Some(source),
            Self::DuplicateStableId { .. } | Self::TooManyMatchResults { .. } => None,
        }
    }
}

/// Match invariant definitions with exact stable keys and normalized semantics.
///
/// The exact `RevisionPair` and snapshot compatibility contract are validated
/// before any key matching. Output order is stable-ID order. Different stable
/// IDs remain separate base/candidate records; this function performs no fuzzy
/// or graph-assisted continuity inference.
pub fn match_invariants(
    pair: &RevisionPair,
    trusted_base: &SemanticSnapshot,
    candidate: &SemanticSnapshot,
    limits: RegressionLimits,
) -> Result<Vec<InvariantMatch>, InvariantMatchError> {
    let limits = limits.validate().map_err(InvariantMatchError::Limits)?;
    validate_snapshot_pair(pair, trusted_base, candidate).map_err(InvariantMatchError::Snapshot)?;

    let base = index_definitions("TRUSTED_BASE", trusted_base.invariant_definitions())?;
    let candidate = index_definitions("CANDIDATE", candidate.invariant_definitions())?;
    let keys = base
        .keys()
        .copied()
        .chain(candidate.keys().copied())
        .collect::<BTreeSet<_>>();
    if keys.len() > limits.max_pair_results {
        return Err(InvariantMatchError::TooManyMatchResults {
            count: keys.len(),
            max: limits.max_pair_results,
        });
    }

    keys.into_iter()
        .map(
            |invariant_id| match (base.get(invariant_id), candidate.get(invariant_id)) {
                (Some(base_definition), Some(candidate_definition)) => {
                    paired_match(invariant_id, base_definition, candidate_definition)
                }
                (Some(base_definition), None) => single_side_match(
                    invariant_id,
                    "TRUSTED_BASE",
                    base_definition,
                    PairPresence::BaseOnly,
                ),
                (None, Some(candidate_definition)) => single_side_match(
                    invariant_id,
                    "CANDIDATE",
                    candidate_definition,
                    PairPresence::CandidateOnly,
                ),
                (None, None) => unreachable!("union key must exist in at least one snapshot"),
            },
        )
        .collect()
}

fn index_definitions<'a>(
    side: &'static str,
    definitions: &'a [InvariantDefinition],
) -> Result<BTreeMap<&'a str, &'a InvariantDefinition>, InvariantMatchError> {
    let mut indexed = BTreeMap::new();
    for definition in definitions {
        let invariant_id = definition.invariant_id().as_str();
        if indexed.insert(invariant_id, definition).is_some() {
            return Err(InvariantMatchError::DuplicateStableId {
                side,
                invariant_id: invariant_id.to_owned(),
            });
        }
    }
    Ok(indexed)
}

fn paired_match(
    invariant_id: &str,
    base: &InvariantDefinition,
    candidate: &InvariantDefinition,
) -> Result<InvariantMatch, InvariantMatchError> {
    let base_digest = definition_digest("TRUSTED_BASE", invariant_id, base)?;
    let candidate_digest = definition_digest("CANDIDATE", invariant_id, candidate)?;
    let compatibility = if base_digest == candidate_digest {
        InvariantDefinitionCompatibility::Compatible
    } else {
        InvariantDefinitionCompatibility::Conflict
    };

    Ok(InvariantMatch {
        stable_invariant_id: invariant_id.to_owned(),
        pair_presence: PairPresence::Matched,
        continuity_basis: ContinuityBasis::ExactStableId,
        base_definition_digest: Some(base_digest),
        candidate_definition_digest: Some(candidate_digest),
        definition_compatibility: compatibility,
    })
}

fn single_side_match(
    invariant_id: &str,
    side: &'static str,
    definition: &InvariantDefinition,
    pair_presence: PairPresence,
) -> Result<InvariantMatch, InvariantMatchError> {
    let digest = definition_digest(side, invariant_id, definition)?;
    let (base_definition_digest, candidate_definition_digest) = match pair_presence {
        PairPresence::BaseOnly => (Some(digest), None),
        PairPresence::CandidateOnly => (None, Some(digest)),
        PairPresence::Matched => unreachable!("single-side invariant cannot be matched"),
    };

    Ok(InvariantMatch {
        stable_invariant_id: invariant_id.to_owned(),
        pair_presence,
        continuity_basis: ContinuityBasis::Unmatched,
        base_definition_digest,
        candidate_definition_digest,
        definition_compatibility: InvariantDefinitionCompatibility::Unpaired,
    })
}

fn definition_digest(
    side: &'static str,
    invariant_id: &str,
    definition: &InvariantDefinition,
) -> Result<String, InvariantMatchError> {
    derive_invariant_definition_digest(definition).map_err(|source| {
        InvariantMatchError::DefinitionDigest {
            side,
            invariant_id: invariant_id.to_owned(),
            source,
        }
    })
}
