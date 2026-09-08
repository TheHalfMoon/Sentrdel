//! Bounded composition of canonical R3 semantic snapshot inputs for S1.
//!
//! This module binds already-validated revision contracts to existing R3
//! invariant/evaluation, canonical Coverage/Evidence, and canonical graph records.
//! It grants no Finding, policy, kernel, graph-confidence, model, network,
//! provider-credential, target-execution, or external-engine authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::canonical::content_id;
use sentrdel_schema::coverage::CoverageRecord;
use sentrdel_schema::evidence::{Evidence, EvidenceValidationError};
use sentrdel_schema::graph::{GraphContractError, GraphEdge, GraphNode};
use serde_json::{Value, json};

use crate::business_logic::graph::R3GraphRecords;
use crate::business_logic::model::{
    ActorIdentityKind, DataOperationKind, GuardKind, HttpMethod, InvariantDefinition,
    InvariantEvaluation, InvariantEvaluationState, InvariantKind, InvariantRequirement,
    InvariantSource, ResourceKind, ResourceRef, SourceLocation,
};
use crate::business_logic::producer::{
    BusinessLogicProducerOutput, R3_BUSINESS_LOGIC_PRODUCER_ID, R3_BUSINESS_LOGIC_PRODUCER_VERSION,
};
use crate::regression::model::{
    ProducerContractIdentity, RegressionLimits, RegressionModelError, RevisionIdentity,
    RevisionPair, SemanticSnapshotContract, SnapshotCompatibility,
};

const R3_SNAPSHOT_CAPABILITY_SCOPE: &str = "BUSINESS_LOGIC";
const S1_SNAPSHOT_INPUT_DIGEST_FORMAT: &str = "sentrdel.s1.semantic-snapshot-input/v1";

/// Derive the bounded canonical digest that a `RevisionIdentity` must bind for
/// this exact normalized semantic input set.
///
/// The helper is crate-private because S1-T008 does not freeze a public digest
/// API. It exists so the trusted revision boundary can bind the same semantic
/// records that `SemanticSnapshot::compose` independently re-derives and checks.
pub(crate) fn derive_snapshot_input_digest(
    mut invariant_definitions: Vec<InvariantDefinition>,
    mut invariant_evaluations: Vec<InvariantEvaluation>,
    producer_output: &BusinessLogicProducerOutput,
    graph_records: &R3GraphRecords,
    limits: RegressionLimits,
) -> Result<String, SnapshotCompositionError> {
    let limits = limits
        .validate()
        .map_err(SnapshotCompositionError::Limits)?;
    normalize_and_validate_semantic_inputs(
        &mut invariant_definitions,
        &mut invariant_evaluations,
        limits,
    )?;

    let mut coverage_records = producer_output.coverage().to_vec();
    let mut evidence = producer_output.evidence().to_vec();
    normalize_and_validate_producer_output(
        &mut coverage_records,
        &mut evidence,
        &invariant_evaluations,
        limits,
    )?;

    let mut graph_nodes = graph_records.nodes().to_vec();
    let mut graph_edges = graph_records.edges().to_vec();
    normalize_and_validate_graph_records(&mut graph_nodes, &mut graph_edges, limits)?;
    enforce_bounded_semantic_input_bytes(
        &invariant_definitions,
        &invariant_evaluations,
        &coverage_records,
        &evidence,
        &graph_nodes,
        &graph_edges,
        limits,
    )?;

    derive_normalized_snapshot_input_digest(
        &invariant_definitions,
        &invariant_evaluations,
        &coverage_records,
        &evidence,
        &graph_nodes,
        &graph_edges,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticSnapshot {
    contract: SemanticSnapshotContract,
    invariant_definitions: Vec<InvariantDefinition>,
    invariant_evaluations: Vec<InvariantEvaluation>,
    coverage_records: Vec<CoverageRecord>,
    evidence_refs: Vec<String>,
    graph_nodes: Vec<GraphNode>,
    graph_edges: Vec<GraphEdge>,
    input_bytes: usize,
}

impl SemanticSnapshot {
    /// Compose one bounded semantic snapshot from existing canonical R3 outputs.
    ///
    /// The snapshot contract is constructed inside this trusted boundary from the
    /// exact revision plus runtime-owned configuration identity and the fixed R3
    /// producer/schema identity. Callers cannot supply a declaration that differs
    /// from the canonical records being composed.
    ///
    /// Inputs are normalized by stable identity before storage. Canonical Evidence
    /// and graph identities are revalidated at this boundary; Coverage/Evidence
    /// must come from the sealed R3 producer output type rather than caller-built
    /// wire records. No comparison disposition is produced here.
    #[allow(clippy::too_many_arguments)]
    pub fn compose(
        revision: RevisionIdentity,
        producer_configuration_digest: impl Into<String>,
        configuration_identity: Vec<String>,
        mut invariant_definitions: Vec<InvariantDefinition>,
        mut invariant_evaluations: Vec<InvariantEvaluation>,
        producer_output: BusinessLogicProducerOutput,
        graph_records: R3GraphRecords,
        limits: RegressionLimits,
    ) -> Result<Self, SnapshotCompositionError> {
        let limits = limits
            .validate()
            .map_err(SnapshotCompositionError::Limits)?;
        let producer_contract = ProducerContractIdentity::new(
            R3_BUSINESS_LOGIC_PRODUCER_ID,
            R3_BUSINESS_LOGIC_PRODUCER_VERSION,
            producer_configuration_digest,
            R3_SNAPSHOT_CAPABILITY_SCOPE,
            SCHEMA_V1,
            limits,
        )
        .map_err(SnapshotCompositionError::Contract)?;
        let contract = SemanticSnapshotContract::new(
            revision,
            SCHEMA_V1,
            vec![producer_contract],
            configuration_identity,
            limits,
        )
        .map_err(SnapshotCompositionError::Contract)?;

        normalize_and_validate_semantic_inputs(
            &mut invariant_definitions,
            &mut invariant_evaluations,
            limits,
        )?;

        let (mut evidence, mut coverage_records) = producer_output.into_parts();
        normalize_and_validate_producer_output(
            &mut coverage_records,
            &mut evidence,
            &invariant_evaluations,
            limits,
        )?;
        let evidence_refs = evidence
            .iter()
            .map(|record| record.evidence_id().to_owned())
            .collect::<Vec<_>>();

        let (mut graph_nodes, mut graph_edges) = graph_records.into_parts();
        normalize_and_validate_graph_records(&mut graph_nodes, &mut graph_edges, limits)?;

        let derived_snapshot_input_digest = derive_normalized_snapshot_input_digest(
            &invariant_definitions,
            &invariant_evaluations,
            &coverage_records,
            &evidence,
            &graph_nodes,
            &graph_edges,
        )?;
        let declared_snapshot_input_digest = contract.revision().snapshot_input_digest();
        if declared_snapshot_input_digest != derived_snapshot_input_digest {
            return Err(SnapshotCompositionError::SnapshotInputDigestMismatch {
                declared: declared_snapshot_input_digest.to_owned(),
                derived: derived_snapshot_input_digest,
            });
        }

        let mut input_bytes = 0usize;
        account_debug_bytes(&mut input_bytes, &contract, limits)?;
        for record in &invariant_definitions {
            account_debug_bytes(&mut input_bytes, record, limits)?;
        }
        for record in &invariant_evaluations {
            account_debug_bytes(&mut input_bytes, record, limits)?;
        }
        for record in &coverage_records {
            account_debug_bytes(&mut input_bytes, record, limits)?;
        }
        for record in &evidence {
            account_debug_bytes(&mut input_bytes, record, limits)?;
        }
        for record in &graph_nodes {
            account_debug_bytes(&mut input_bytes, record, limits)?;
        }
        for record in &graph_edges {
            account_debug_bytes(&mut input_bytes, record, limits)?;
        }

        Ok(Self {
            contract,
            invariant_definitions,
            invariant_evaluations,
            coverage_records,
            evidence_refs,
            graph_nodes,
            graph_edges,
            input_bytes,
        })
    }

    #[must_use]
    pub fn contract(&self) -> &SemanticSnapshotContract {
        &self.contract
    }

    #[must_use]
    pub fn invariant_definitions(&self) -> &[InvariantDefinition] {
        &self.invariant_definitions
    }

    #[must_use]
    pub fn invariant_evaluations(&self) -> &[InvariantEvaluation] {
        &self.invariant_evaluations
    }

    #[must_use]
    pub fn coverage_records(&self) -> &[CoverageRecord] {
        &self.coverage_records
    }

    #[must_use]
    pub fn evidence_refs(&self) -> &[String] {
        &self.evidence_refs
    }

    #[must_use]
    pub fn graph_nodes(&self) -> &[GraphNode] {
        &self.graph_nodes
    }

    #[must_use]
    pub fn graph_edges(&self) -> &[GraphEdge] {
        &self.graph_edges
    }

    #[must_use]
    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    #[must_use]
    pub fn compatibility_with(&self, other: &Self) -> SnapshotCompatibility {
        self.contract.compatibility_with(&other.contract)
    }
}

/// Validate the exact revision binding and frozen producer/config/schema
/// compatibility before any later S1 matching or disposition logic executes.
pub fn validate_snapshot_pair(
    pair: &RevisionPair,
    trusted_base: &SemanticSnapshot,
    candidate: &SemanticSnapshot,
) -> Result<(), SnapshotCompositionError> {
    if trusted_base.contract().revision() != pair.trusted_base() {
        return Err(SnapshotCompositionError::RevisionPairMismatch {
            side: "TRUSTED_BASE",
        });
    }
    if candidate.contract().revision() != pair.candidate() {
        return Err(SnapshotCompositionError::RevisionPairMismatch { side: "CANDIDATE" });
    }

    let compatibility = trusted_base.compatibility_with(candidate);
    if !compatibility.is_compatible() {
        return Err(SnapshotCompositionError::IncompatibleSnapshots(
            compatibility,
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum SnapshotCompositionError {
    Limits(RegressionModelError),
    Contract(RegressionModelError),
    TooManyCollectionItems {
        field: &'static str,
        count: usize,
        max: usize,
    },
    DuplicateInvariantId(String),
    DuplicateEvaluationId(String),
    DuplicateCoverageId(String),
    DuplicateEvidenceId(String),
    DuplicateGraphNodeId(String),
    DuplicateGraphEdgeId(String),
    UnknownInvariantReference {
        evaluation_id: String,
        invariant_id: String,
    },
    EvidenceRecordCountMismatch {
        expected: usize,
        actual: usize,
    },
    EvidenceEvaluationBindingMismatch {
        evidence_id: String,
    },
    EvidenceEvaluationMultiplicityMismatch {
        evaluation_id: String,
        count: usize,
    },
    SnapshotInputDigestMismatch {
        declared: String,
        derived: String,
    },
    UnexpectedCoverageSchema(String),
    UnexpectedCoverageProducer(Option<String>),
    UnexpectedEvidenceProducer {
        producer_id: String,
        producer_version: String,
    },
    UnexpectedEvidenceSchema(String),
    InvalidEvidenceIdentity(String),
    Evidence(EvidenceValidationError),
    Graph(GraphContractError),
    TotalInputBytesExceeded {
        max: usize,
    },
    RevisionPairMismatch {
        side: &'static str,
    },
    IncompatibleSnapshots(SnapshotCompatibility),
}

impl fmt::Display for SnapshotCompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "invalid S1 snapshot limits: {error}"),
            Self::Contract(error) => write!(formatter, "invalid S1 snapshot contract: {error}"),
            Self::TooManyCollectionItems { field, count, max } => write!(
                formatter,
                "S1 snapshot collection {field} count {count} exceeds cap {max}"
            ),
            Self::DuplicateInvariantId(value) => {
                write!(formatter, "duplicate S1 snapshot invariant id {value:?}")
            }
            Self::DuplicateEvaluationId(value) => {
                write!(formatter, "duplicate S1 snapshot evaluation id {value:?}")
            }
            Self::DuplicateCoverageId(value) => {
                write!(formatter, "duplicate S1 snapshot Coverage id {value:?}")
            }
            Self::DuplicateEvidenceId(value) => {
                write!(formatter, "duplicate S1 snapshot Evidence id {value:?}")
            }
            Self::DuplicateGraphNodeId(value) => {
                write!(formatter, "duplicate S1 snapshot graph node id {value:?}")
            }
            Self::DuplicateGraphEdgeId(value) => {
                write!(formatter, "duplicate S1 snapshot graph edge id {value:?}")
            }
            Self::UnknownInvariantReference {
                evaluation_id,
                invariant_id,
            } => write!(
                formatter,
                "S1 snapshot evaluation {evaluation_id:?} references missing invariant {invariant_id:?}"
            ),
            Self::EvidenceRecordCountMismatch { expected, actual } => write!(
                formatter,
                "S1 snapshot Evidence count {actual} does not match expected R3 evaluation-bound count {expected}"
            ),
            Self::EvidenceEvaluationBindingMismatch { evidence_id } => write!(
                formatter,
                "S1 snapshot Evidence {evidence_id:?} is not bound to exactly one supplied evaluation/invariant subject pair"
            ),
            Self::EvidenceEvaluationMultiplicityMismatch {
                evaluation_id,
                count,
            } => write!(
                formatter,
                "S1 snapshot evaluation {evaluation_id:?} has {count} Evidence records; expected exactly 2"
            ),
            Self::SnapshotInputDigestMismatch { declared, derived } => write!(
                formatter,
                "S1 snapshot semantic-input digest mismatch: revision declared {declared:?}, derived {derived:?}"
            ),
            Self::UnexpectedCoverageSchema(value) => write!(
                formatter,
                "S1 snapshot Coverage uses unsupported canonical schema {value:?}"
            ),
            Self::UnexpectedCoverageProducer(value) => write!(
                formatter,
                "S1 snapshot Coverage has unexpected producer {value:?}"
            ),
            Self::UnexpectedEvidenceProducer {
                producer_id,
                producer_version,
            } => write!(
                formatter,
                "S1 snapshot Evidence has unexpected producer {producer_id:?}@{producer_version:?}"
            ),
            Self::UnexpectedEvidenceSchema(value) => write!(
                formatter,
                "S1 snapshot Evidence uses unsupported canonical schema {value:?}"
            ),
            Self::InvalidEvidenceIdentity(value) => write!(
                formatter,
                "S1 snapshot Evidence identity failed canonical verification: {value:?}"
            ),
            Self::Evidence(error) => write!(formatter, "invalid S1 snapshot Evidence: {error}"),
            Self::Graph(error) => write!(formatter, "invalid S1 snapshot graph record: {error}"),
            Self::TotalInputBytesExceeded { max } => {
                write!(
                    formatter,
                    "S1 snapshot input exceeds aggregate byte cap {max}"
                )
            }
            Self::RevisionPairMismatch { side } => write!(
                formatter,
                "S1 snapshot revision does not match the validated RevisionPair {side} identity"
            ),
            Self::IncompatibleSnapshots(value) => write!(
                formatter,
                "S1 snapshots are incompatible before comparison: {value:?}"
            ),
        }
    }
}

impl Error for SnapshotCompositionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) | Self::Contract(error) => Some(error),
            Self::Evidence(error) => Some(error),
            Self::Graph(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EvidenceValidationError> for SnapshotCompositionError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

impl From<GraphContractError> for SnapshotCompositionError {
    fn from(value: GraphContractError) -> Self {
        Self::Graph(value)
    }
}

fn enforce_count(
    field: &'static str,
    count: usize,
    max: usize,
) -> Result<(), SnapshotCompositionError> {
    if count > max {
        return Err(SnapshotCompositionError::TooManyCollectionItems { field, count, max });
    }
    Ok(())
}

fn reject_duplicate_invariant_ids(
    records: &[InvariantDefinition],
) -> Result<(), SnapshotCompositionError> {
    for pair in records.windows(2) {
        if pair[0].invariant_id() == pair[1].invariant_id() {
            return Err(SnapshotCompositionError::DuplicateInvariantId(
                pair[0].invariant_id().as_str().to_owned(),
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_evaluation_ids(
    records: &[InvariantEvaluation],
) -> Result<(), SnapshotCompositionError> {
    for pair in records.windows(2) {
        if pair[0].evaluation_id() == pair[1].evaluation_id() {
            return Err(SnapshotCompositionError::DuplicateEvaluationId(
                pair[0].evaluation_id().as_str().to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_evaluation_references(
    definitions: &[InvariantDefinition],
    evaluations: &[InvariantEvaluation],
) -> Result<(), SnapshotCompositionError> {
    let definition_ids = definitions
        .iter()
        .map(|record| record.invariant_id().as_str())
        .collect::<BTreeSet<_>>();
    for evaluation in evaluations {
        if !definition_ids.contains(evaluation.invariant_id().as_str()) {
            return Err(SnapshotCompositionError::UnknownInvariantReference {
                evaluation_id: evaluation.evaluation_id().as_str().to_owned(),
                invariant_id: evaluation.invariant_id().as_str().to_owned(),
            });
        }
    }
    Ok(())
}

fn normalize_and_validate_semantic_inputs(
    invariant_definitions: &mut [InvariantDefinition],
    invariant_evaluations: &mut [InvariantEvaluation],
    limits: RegressionLimits,
) -> Result<(), SnapshotCompositionError> {
    enforce_count(
        "invariant_definitions",
        invariant_definitions.len(),
        limits.max_snapshot_invariants,
    )?;
    enforce_count(
        "invariant_evaluations",
        invariant_evaluations.len(),
        limits.max_snapshot_evaluations,
    )?;
    invariant_definitions.sort_by(|left, right| {
        left.invariant_id()
            .as_str()
            .cmp(right.invariant_id().as_str())
    });
    reject_duplicate_invariant_ids(invariant_definitions)?;
    invariant_evaluations.sort_by(|left, right| {
        left.evaluation_id()
            .as_str()
            .cmp(right.evaluation_id().as_str())
    });
    reject_duplicate_evaluation_ids(invariant_evaluations)?;
    validate_evaluation_references(invariant_definitions, invariant_evaluations)
}

fn normalize_and_validate_producer_output(
    coverage_records: &mut [CoverageRecord],
    evidence: &mut [Evidence],
    invariant_evaluations: &[InvariantEvaluation],
    limits: RegressionLimits,
) -> Result<(), SnapshotCompositionError> {
    enforce_count(
        "coverage_records",
        coverage_records.len(),
        limits.max_snapshot_coverage_records,
    )?;
    let max_evidence_records = limits.max_snapshot_evaluations.checked_mul(2).ok_or(
        SnapshotCompositionError::TotalInputBytesExceeded {
            max: limits.max_total_input_bytes,
        },
    )?;
    enforce_count("evidence_records", evidence.len(), max_evidence_records)?;

    coverage_records.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
    reject_duplicate_coverage_ids(coverage_records)?;
    validate_coverage_records(coverage_records)?;

    evidence.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    reject_duplicate_evidence_ids(evidence)?;
    validate_evidence_records(evidence)?;
    validate_evidence_evaluation_bindings(evidence, invariant_evaluations, limits)
}

fn normalize_and_validate_graph_records(
    graph_nodes: &mut [GraphNode],
    graph_edges: &mut [GraphEdge],
    limits: RegressionLimits,
) -> Result<(), SnapshotCompositionError> {
    enforce_count("graph_nodes", graph_nodes.len(), limits.max_graph_nodes)?;
    enforce_count("graph_edges", graph_edges.len(), limits.max_graph_edges)?;
    graph_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    graph_edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
    reject_duplicate_graph_node_ids(graph_nodes)?;
    reject_duplicate_graph_edge_ids(graph_edges)?;
    validate_graph_records(graph_nodes, graph_edges)
}

fn reject_duplicate_coverage_ids(
    records: &[CoverageRecord],
) -> Result<(), SnapshotCompositionError> {
    for pair in records.windows(2) {
        if pair[0].coverage_id == pair[1].coverage_id {
            return Err(SnapshotCompositionError::DuplicateCoverageId(
                pair[0].coverage_id.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_coverage_records(records: &[CoverageRecord]) -> Result<(), SnapshotCompositionError> {
    for record in records {
        if record.schema_version != SCHEMA_V1 {
            return Err(SnapshotCompositionError::UnexpectedCoverageSchema(
                record.schema_version.clone(),
            ));
        }
        if record.producer.as_deref() != Some(R3_BUSINESS_LOGIC_PRODUCER_ID) {
            return Err(SnapshotCompositionError::UnexpectedCoverageProducer(
                record.producer.clone(),
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_evidence_ids(records: &[Evidence]) -> Result<(), SnapshotCompositionError> {
    for pair in records.windows(2) {
        if pair[0].evidence_id() == pair[1].evidence_id() {
            return Err(SnapshotCompositionError::DuplicateEvidenceId(
                pair[0].evidence_id().to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_evidence_records(records: &[Evidence]) -> Result<(), SnapshotCompositionError> {
    for record in records {
        let producer = record.producer();
        if producer.id != R3_BUSINESS_LOGIC_PRODUCER_ID
            || producer.version != R3_BUSINESS_LOGIC_PRODUCER_VERSION
        {
            return Err(SnapshotCompositionError::UnexpectedEvidenceProducer {
                producer_id: producer.id.clone(),
                producer_version: producer.version.clone(),
            });
        }
        if record.claim().schema_version != SCHEMA_V1 {
            return Err(SnapshotCompositionError::UnexpectedEvidenceSchema(
                record.claim().schema_version.clone(),
            ));
        }
        if !record.verify_identity()? {
            return Err(SnapshotCompositionError::InvalidEvidenceIdentity(
                record.evidence_id().to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_evidence_evaluation_bindings(
    records: &[Evidence],
    evaluations: &[InvariantEvaluation],
    limits: RegressionLimits,
) -> Result<(), SnapshotCompositionError> {
    let expected = evaluations.len().checked_mul(2).ok_or(
        SnapshotCompositionError::TotalInputBytesExceeded {
            max: limits.max_total_input_bytes,
        },
    )?;
    if records.len() != expected {
        return Err(SnapshotCompositionError::EvidenceRecordCountMismatch {
            expected,
            actual: records.len(),
        });
    }

    let evaluation_by_id = evaluations
        .iter()
        .map(|evaluation| (evaluation.evaluation_id().as_str(), evaluation))
        .collect::<BTreeMap<_, _>>();
    let mut counts = BTreeMap::<&str, usize>::new();

    for record in records {
        let subjects = &record.claim().subjects;
        let mut evaluation_subjects = subjects
            .iter()
            .filter(|subject| subject.kind == "invariant_evaluation");
        let Some(evaluation_subject) = evaluation_subjects.next() else {
            return Err(
                SnapshotCompositionError::EvidenceEvaluationBindingMismatch {
                    evidence_id: record.evidence_id().to_owned(),
                },
            );
        };
        if evaluation_subjects.next().is_some() {
            return Err(
                SnapshotCompositionError::EvidenceEvaluationBindingMismatch {
                    evidence_id: record.evidence_id().to_owned(),
                },
            );
        }
        let Some(evaluation) = evaluation_by_id.get(evaluation_subject.id.as_str()) else {
            return Err(
                SnapshotCompositionError::EvidenceEvaluationBindingMismatch {
                    evidence_id: record.evidence_id().to_owned(),
                },
            );
        };

        let mut invariant_subjects = subjects
            .iter()
            .filter(|subject| subject.kind == "invariant");
        let invariant_matches = invariant_subjects
            .next()
            .is_some_and(|subject| subject.id == evaluation.invariant_id().as_str())
            && invariant_subjects.next().is_none();
        if !invariant_matches {
            return Err(
                SnapshotCompositionError::EvidenceEvaluationBindingMismatch {
                    evidence_id: record.evidence_id().to_owned(),
                },
            );
        }

        let mut path_subjects = subjects
            .iter()
            .filter(|subject| subject.kind == "cross_layer_path");
        let path_matches = match evaluation.path_id() {
            Some(path_id) => {
                path_subjects
                    .next()
                    .is_some_and(|subject| subject.id == path_id.as_str())
                    && path_subjects.next().is_none()
            }
            None => path_subjects.next().is_none(),
        };
        if !path_matches {
            return Err(
                SnapshotCompositionError::EvidenceEvaluationBindingMismatch {
                    evidence_id: record.evidence_id().to_owned(),
                },
            );
        }

        *counts
            .entry(evaluation.evaluation_id().as_str())
            .or_default() += 1;
    }

    for evaluation in evaluations {
        let count = counts
            .get(evaluation.evaluation_id().as_str())
            .copied()
            .unwrap_or(0);
        if count != 2 {
            return Err(
                SnapshotCompositionError::EvidenceEvaluationMultiplicityMismatch {
                    evaluation_id: evaluation.evaluation_id().as_str().to_owned(),
                    count,
                },
            );
        }
    }
    Ok(())
}

fn reject_duplicate_graph_node_ids(records: &[GraphNode]) -> Result<(), SnapshotCompositionError> {
    for pair in records.windows(2) {
        if pair[0].node_id == pair[1].node_id {
            return Err(SnapshotCompositionError::DuplicateGraphNodeId(
                pair[0].node_id.as_str().to_owned(),
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_graph_edge_ids(records: &[GraphEdge]) -> Result<(), SnapshotCompositionError> {
    for pair in records.windows(2) {
        if pair[0].edge_id == pair[1].edge_id {
            return Err(SnapshotCompositionError::DuplicateGraphEdgeId(
                pair[0].edge_id.as_str().to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_graph_records(
    nodes: &[GraphNode],
    edges: &[GraphEdge],
) -> Result<(), SnapshotCompositionError> {
    let node_ids = nodes
        .iter()
        .map(|node| &node.node_id)
        .collect::<BTreeSet<_>>();
    for node in nodes {
        node.validate()?;
    }
    for edge in edges {
        edge.validate()?;
        if !node_ids.contains(&edge.source) || !node_ids.contains(&edge.target) {
            return Err(SnapshotCompositionError::Graph(
                GraphContractError::EdgeIdentityMismatch,
            ));
        }
    }
    Ok(())
}

fn enforce_bounded_semantic_input_bytes(
    invariant_definitions: &[InvariantDefinition],
    invariant_evaluations: &[InvariantEvaluation],
    coverage_records: &[CoverageRecord],
    evidence: &[Evidence],
    graph_nodes: &[GraphNode],
    graph_edges: &[GraphEdge],
    limits: RegressionLimits,
) -> Result<(), SnapshotCompositionError> {
    let mut input_bytes = 0usize;
    for record in invariant_definitions {
        account_debug_bytes(&mut input_bytes, record, limits)?;
    }
    for record in invariant_evaluations {
        account_debug_bytes(&mut input_bytes, record, limits)?;
    }
    for record in coverage_records {
        account_debug_bytes(&mut input_bytes, record, limits)?;
    }
    for record in evidence {
        account_debug_bytes(&mut input_bytes, record, limits)?;
    }
    for record in graph_nodes {
        account_debug_bytes(&mut input_bytes, record, limits)?;
    }
    for record in graph_edges {
        account_debug_bytes(&mut input_bytes, record, limits)?;
    }
    Ok(())
}

fn derive_normalized_snapshot_input_digest(
    invariant_definitions: &[InvariantDefinition],
    invariant_evaluations: &[InvariantEvaluation],
    coverage_records: &[CoverageRecord],
    evidence: &[Evidence],
    graph_nodes: &[GraphNode],
    graph_edges: &[GraphEdge],
) -> Result<String, SnapshotCompositionError> {
    let material = json!({
        "format": S1_SNAPSHOT_INPUT_DIGEST_FORMAT,
        "invariant_definitions": invariant_definitions
            .iter()
            .map(invariant_definition_material)
            .collect::<Vec<_>>(),
        "invariant_evaluations": invariant_evaluations
            .iter()
            .map(invariant_evaluation_material)
            .collect::<Vec<_>>(),
        "coverage_records": coverage_records,
        "evidence_records": evidence,
        "graph_nodes": graph_nodes,
        "graph_edges": graph_edges,
    });
    content_id("s1-semantic-snapshot-input", &material)
        .map_err(|error| SnapshotCompositionError::Contract(error.into()))
}

fn invariant_definition_material(record: &InvariantDefinition) -> Value {
    let scope = record.scope();
    json!({
        "invariant_id": record.invariant_id().as_str(),
        "kind": invariant_kind_name(record.kind()),
        "source": invariant_source_name(record.source()),
        "scope": {
            "route_pattern": scope.route_pattern(),
            "http_methods": scope.http_methods().iter().copied().map(http_method_name).collect::<Vec<_>>(),
            "resource": scope.resource().map(resource_material),
            "operation_kinds": scope.operation_kinds().iter().copied().map(data_operation_kind_name).collect::<Vec<_>>(),
            "target_paths": scope.target_paths().iter().map(|path| path.as_str()).collect::<Vec<_>>(),
        },
        "requirements": invariant_requirement_material(record.requirements()),
        "provenance": record.provenance().iter().map(source_location_material).collect::<Vec<_>>(),
    })
}

fn invariant_evaluation_material(record: &InvariantEvaluation) -> Value {
    json!({
        "evaluation_id": record.evaluation_id().as_str(),
        "invariant_id": record.invariant_id().as_str(),
        "path_id": record.path_id().map(|value| value.as_str()),
        "state": invariant_evaluation_state_name(record.state()),
        "supporting_observation_ids": record.supporting_observation_ids().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "contradicting_observation_ids": record.contradicting_observation_ids().iter().map(|value| value.as_str()).collect::<Vec<_>>(),
        "coverage_reasons": record.coverage_reasons(),
        "provenance": record.provenance().iter().map(source_location_material).collect::<Vec<_>>(),
    })
}

fn invariant_requirement_material(requirement: &InvariantRequirement) -> Value {
    match requirement {
        InvariantRequirement::TenantBinding {
            resource_tenant_field,
            required_actor_identity,
        } => json!({
            "kind": "TENANT_BINDING",
            "resource_tenant_field": resource_tenant_field,
            "required_actor_identity": actor_identity_kind_name(*required_actor_identity),
        }),
        InvariantRequirement::RequiredRole { required_roles } => json!({
            "kind": "REQUIRED_ROLE",
            "required_roles": required_roles,
        }),
        InvariantRequirement::ProtectedProperties {
            protected_properties,
            mutation_operations,
        } => json!({
            "kind": "PROTECTED_PROPERTIES",
            "protected_properties": protected_properties,
            "mutation_operations": mutation_operations.iter().copied().map(data_operation_kind_name).collect::<Vec<_>>(),
        }),
        InvariantRequirement::ElevatedClientContext {
            allowed_server_contexts,
            required_guard_kinds,
        } => json!({
            "kind": "ELEVATED_CLIENT_CONTEXT",
            "allowed_server_contexts": allowed_server_contexts,
            "required_guard_kinds": required_guard_kinds.iter().copied().map(guard_kind_name).collect::<Vec<_>>(),
        }),
    }
}

fn source_location_material(location: &SourceLocation) -> Value {
    json!({
        "path": location.path().as_str(),
        "start_byte": location.start_byte(),
        "end_byte": location.end_byte(),
        "content_digest": location.content_digest(),
    })
}

fn resource_material(resource: &ResourceRef) -> Value {
    json!({
        "provider": resource.provider(),
        "namespace": resource.namespace(),
        "resource_name": resource.resource_name(),
        "resource_kind": resource_kind_name(resource.resource_kind()),
        "r2_subject": resource.r2_subject(),
    })
}

fn invariant_kind_name(kind: InvariantKind) -> &'static str {
    match kind {
        InvariantKind::TenantBinding => "TENANT_BINDING",
        InvariantKind::RequiredRole => "REQUIRED_ROLE",
        InvariantKind::ProtectedProperties => "PROTECTED_PROPERTIES",
        InvariantKind::ElevatedClientContext => "ELEVATED_CLIENT_CONTEXT",
    }
}

fn invariant_source_name(source: InvariantSource) -> &'static str {
    match source {
        InvariantSource::BuiltIn => "BUILT_IN",
        InvariantSource::ProjectDeclaration => "PROJECT_DECLARATION",
    }
}

fn invariant_evaluation_state_name(state: InvariantEvaluationState) -> &'static str {
    match state {
        InvariantEvaluationState::Satisfied => "SATISFIED",
        InvariantEvaluationState::Violated => "VIOLATED",
        InvariantEvaluationState::Unknown => "UNKNOWN",
        InvariantEvaluationState::NotApplicable => "NOT_APPLICABLE",
    }
}

fn http_method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Head => "HEAD",
        HttpMethod::OtherSupported => "OTHER_SUPPORTED",
    }
}

fn data_operation_kind_name(kind: DataOperationKind) -> &'static str {
    match kind {
        DataOperationKind::Read => "READ",
        DataOperationKind::Insert => "INSERT",
        DataOperationKind::Update => "UPDATE",
        DataOperationKind::Upsert => "UPSERT",
        DataOperationKind::Delete => "DELETE",
        DataOperationKind::Rpc => "RPC",
        DataOperationKind::OtherSupported => "OTHER_SUPPORTED",
    }
}

fn resource_kind_name(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Table => "TABLE",
        ResourceKind::View => "VIEW",
        ResourceKind::Function => "FUNCTION",
        ResourceKind::StorageObject => "STORAGE_OBJECT",
        ResourceKind::ApplicationResource => "APPLICATION_RESOURCE",
        ResourceKind::OtherSupported => "OTHER_SUPPORTED",
    }
}

fn actor_identity_kind_name(kind: ActorIdentityKind) -> &'static str {
    match kind {
        ActorIdentityKind::AuthenticatedUser => "AUTHENTICATED_USER",
        ActorIdentityKind::Tenant => "TENANT",
        ActorIdentityKind::Role => "ROLE",
        ActorIdentityKind::Service => "SERVICE",
        ActorIdentityKind::Anonymous => "ANONYMOUS",
        ActorIdentityKind::RequestControlled => "REQUEST_CONTROLLED",
        ActorIdentityKind::Unknown => "UNKNOWN",
    }
}

fn guard_kind_name(kind: GuardKind) -> &'static str {
    match kind {
        GuardKind::Authentication => "AUTHENTICATION",
        GuardKind::RequiredRole => "REQUIRED_ROLE",
        GuardKind::TenantBinding => "TENANT_BINDING",
        GuardKind::OwnershipBinding => "OWNERSHIP_BINDING",
        GuardKind::ObjectMembership => "OBJECT_MEMBERSHIP",
        GuardKind::PropertyAllowlist => "PROPERTY_ALLOWLIST",
        GuardKind::PropertyDenylistRequirement => "PROPERTY_DENYLIST_REQUIREMENT",
        GuardKind::ElevatedClientBoundary => "ELEVATED_CLIENT_BOUNDARY",
        GuardKind::CustomInvariantRequirement => "CUSTOM_INVARIANT_REQUIREMENT",
    }
}

fn account_debug_bytes<T: fmt::Debug>(
    total: &mut usize,
    value: &T,
    limits: RegressionLimits,
) -> Result<(), SnapshotCompositionError> {
    // Debug bytes are used only as a conservative internal work/accounting bound.
    // They never participate in semantic identity, comparison authority, or output.
    let bytes = format!("{value:?}").len();
    *total = total
        .checked_add(bytes)
        .ok_or(SnapshotCompositionError::TotalInputBytesExceeded {
            max: limits.max_total_input_bytes,
        })?;
    if *total > limits.max_total_input_bytes {
        return Err(SnapshotCompositionError::TotalInputBytesExceeded {
            max: limits.max_total_input_bytes,
        });
    }
    Ok(())
}
