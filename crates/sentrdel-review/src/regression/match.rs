//! Stable keyed invariant and semantic-object continuity matching for S1 snapshots.
//!
//! Matching is exact on Sentrdel-owned stable identity. Invariant definition
//! compatibility is determined from a normalized semantic digest covering kind,
//! source/authority, scope, and requirements. Canonical graph node/edge identity
//! establishes object continuity; provenance, lexical similarity, graph proximity,
//! edit distance, confidence, and model judgment cannot create identity.

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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SemanticObjectKind {
    EvaluationPath,
    Observation,
    GraphNode,
    GraphEdge,
}

impl SemanticObjectKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EvaluationPath => "EVALUATION_PATH",
            Self::Observation => "OBSERVATION",
            Self::GraphNode => "GRAPH_NODE",
            Self::GraphEdge => "GRAPH_EDGE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticObjectMatch {
    object_kind: SemanticObjectKind,
    stable_object_id: String,
    pair_presence: PairPresence,
    continuity_basis: ContinuityBasis,
}

impl SemanticObjectMatch {
    #[must_use]
    pub const fn object_kind(&self) -> SemanticObjectKind {
        self.object_kind
    }

    #[must_use]
    pub fn stable_object_id(&self) -> &str {
        &self.stable_object_id
    }

    #[must_use]
    pub const fn pair_presence(&self) -> PairPresence {
        self.pair_presence
    }

    #[must_use]
    pub const fn continuity_basis(&self) -> ContinuityBasis {
        self.continuity_basis
    }
}

#[derive(Debug)]
pub enum SemanticObjectMatchError {
    Limits(RegressionModelError),
    Snapshot(SnapshotCompositionError),
    TooManySemanticObjects {
        object_kind: SemanticObjectKind,
        count: usize,
        max: usize,
    },
}

impl fmt::Display for SemanticObjectMatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => {
                write!(formatter, "invalid semantic-object match limits: {error}")
            }
            Self::Snapshot(error) => write!(formatter, "snapshot pair is not comparable: {error}"),
            Self::TooManySemanticObjects {
                object_kind,
                count,
                max,
            } => write!(
                formatter,
                "{} continuity result count {count} exceeds configured maximum {max}",
                object_kind.as_str()
            ),
        }
    }
}

impl Error for SemanticObjectMatchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) => Some(error),
            Self::Snapshot(error) => Some(error),
            Self::TooManySemanticObjects { .. } => None,
        }
    }
}

/// Establish exact continuity for semantic objects already carried by a snapshot.
///
/// The exact revision pair and snapshot compatibility contract are validated
/// before continuity handling. Evaluation path IDs, referenced observation IDs,
/// graph node IDs, and graph edge IDs are keyed only by their existing canonical
/// stable identities. Same-ID objects are `MATCHED` with `EXACT_STABLE_ID`;
/// one-sided IDs remain explicitly unmatched. Invariant-definition identity is
/// handled separately by the stricter S1-T009 matcher.
///
/// This function does not infer rename continuity, compare graph neighborhoods,
/// interpret mutable graph metadata, or create graph/security dispositions.
/// Existing `GraphProjection::diff` remains bounded comparison context for
/// S1-T021 and never becomes identity authority here.
pub fn match_semantic_objects(
    pair: &RevisionPair,
    trusted_base: &SemanticSnapshot,
    candidate: &SemanticSnapshot,
    limits: RegressionLimits,
) -> Result<Vec<SemanticObjectMatch>, SemanticObjectMatchError> {
    let limits = limits
        .validate()
        .map_err(SemanticObjectMatchError::Limits)?;
    validate_snapshot_pair(pair, trusted_base, candidate)
        .map_err(SemanticObjectMatchError::Snapshot)?;

    let (base_path_ids, base_observation_ids) = evaluation_semantic_ids(trusted_base);
    let (candidate_path_ids, candidate_observation_ids) = evaluation_semantic_ids(candidate);
    let base_node_ids = trusted_base
        .graph_nodes()
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let candidate_node_ids = candidate
        .graph_nodes()
        .iter()
        .map(|node| node.node_id.as_str())
        .collect::<BTreeSet<_>>();
    let base_edge_ids = trusted_base
        .graph_edges()
        .iter()
        .map(|edge| edge.edge_id.as_str())
        .collect::<BTreeSet<_>>();
    let candidate_edge_ids = candidate
        .graph_edges()
        .iter()
        .map(|edge| edge.edge_id.as_str())
        .collect::<BTreeSet<_>>();

    let mut matches = match_semantic_id_sets(
        SemanticObjectKind::EvaluationPath,
        &base_path_ids,
        &candidate_path_ids,
        limits.max_pair_results,
    )?;
    matches.extend(match_semantic_id_sets(
        SemanticObjectKind::Observation,
        &base_observation_ids,
        &candidate_observation_ids,
        limits.max_pair_results,
    )?);
    matches.extend(match_semantic_id_sets(
        SemanticObjectKind::GraphNode,
        &base_node_ids,
        &candidate_node_ids,
        limits.max_graph_nodes,
    )?);
    matches.extend(match_semantic_id_sets(
        SemanticObjectKind::GraphEdge,
        &base_edge_ids,
        &candidate_edge_ids,
        limits.max_graph_edges,
    )?);
    Ok(matches)
}

fn evaluation_semantic_ids(snapshot: &SemanticSnapshot) -> (BTreeSet<&str>, BTreeSet<&str>) {
    let mut path_ids = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();
    for evaluation in snapshot.invariant_evaluations() {
        if let Some(path_id) = evaluation.path_id() {
            path_ids.insert(path_id.as_str());
        }
        observation_ids.extend(
            evaluation
                .supporting_observation_ids()
                .iter()
                .map(|value| value.as_str()),
        );
        observation_ids.extend(
            evaluation
                .contradicting_observation_ids()
                .iter()
                .map(|value| value.as_str()),
        );
    }
    (path_ids, observation_ids)
}

fn match_semantic_id_sets(
    object_kind: SemanticObjectKind,
    base_ids: &BTreeSet<&str>,
    candidate_ids: &BTreeSet<&str>,
    max_results: usize,
) -> Result<Vec<SemanticObjectMatch>, SemanticObjectMatchError> {
    let ids = base_ids
        .iter()
        .copied()
        .chain(candidate_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    if ids.len() > max_results {
        return Err(SemanticObjectMatchError::TooManySemanticObjects {
            object_kind,
            count: ids.len(),
            max: max_results,
        });
    }

    Ok(ids
        .into_iter()
        .map(|stable_object_id| {
            let in_base = base_ids.contains(stable_object_id);
            let in_candidate = candidate_ids.contains(stable_object_id);
            let (pair_presence, continuity_basis) = match (in_base, in_candidate) {
                (true, true) => (PairPresence::Matched, ContinuityBasis::ExactStableId),
                (true, false) => (PairPresence::BaseOnly, ContinuityBasis::Unmatched),
                (false, true) => (PairPresence::CandidateOnly, ContinuityBasis::Unmatched),
                (false, false) => unreachable!("union ID must exist in at least one snapshot"),
            };
            SemanticObjectMatch {
                object_kind,
                stable_object_id: stable_object_id.to_owned(),
                pair_presence,
                continuity_basis,
            }
        })
        .collect())
}
