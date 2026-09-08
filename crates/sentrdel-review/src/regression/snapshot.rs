//! Bounded composition of canonical R3 semantic snapshot inputs for S1.
//!
//! This module binds already-validated revision contracts to existing R3
//! invariant/evaluation, canonical Coverage/Evidence, and canonical graph records.
//! It grants no Finding, policy, kernel, graph-confidence, model, network,
//! provider-credential, target-execution, or external-engine authority.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::CoverageRecord;
use sentrdel_schema::evidence::{Evidence, EvidenceValidationError};
use sentrdel_schema::graph::{GraphContractError, GraphEdge, GraphNode};

use crate::business_logic::graph::R3GraphRecords;
use crate::business_logic::model::{InvariantDefinition, InvariantEvaluation};
use crate::business_logic::producer::{
    BusinessLogicProducerOutput, R3_BUSINESS_LOGIC_PRODUCER_ID,
    R3_BUSINESS_LOGIC_PRODUCER_VERSION,
};
use crate::regression::model::{
    RegressionLimits, RegressionModelError, RevisionPair, SemanticSnapshotContract,
    SnapshotCompatibility,
};

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
    /// Inputs are normalized by stable identity before storage. Canonical Evidence
    /// and graph identities are revalidated at this boundary; Coverage/Evidence
    /// must come from the sealed R3 producer output type rather than caller-built
    /// wire records. No comparison disposition is produced here.
    pub fn compose(
        contract: SemanticSnapshotContract,
        mut invariant_definitions: Vec<InvariantDefinition>,
        mut invariant_evaluations: Vec<InvariantEvaluation>,
        producer_output: BusinessLogicProducerOutput,
        graph_records: R3GraphRecords,
        limits: RegressionLimits,
    ) -> Result<Self, SnapshotCompositionError> {
        let limits = limits.validate().map_err(SnapshotCompositionError::Limits)?;

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
        reject_duplicate_invariant_ids(&invariant_definitions)?;

        invariant_evaluations.sort_by(|left, right| {
            left.evaluation_id()
                .as_str()
                .cmp(right.evaluation_id().as_str())
        });
        reject_duplicate_evaluation_ids(&invariant_evaluations)?;
        validate_evaluation_references(&invariant_definitions, &invariant_evaluations)?;

        let (mut evidence, mut coverage_records) = producer_output.into_parts();
        enforce_count(
            "coverage_records",
            coverage_records.len(),
            limits.max_snapshot_coverage_records,
        )?;
        let max_evidence_records = limits
            .max_snapshot_evaluations
            .checked_mul(2)
            .ok_or(SnapshotCompositionError::TotalInputBytesExceeded {
                max: limits.max_total_input_bytes,
            })?;
        enforce_count("evidence_records", evidence.len(), max_evidence_records)?;

        coverage_records.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
        reject_duplicate_coverage_ids(&coverage_records)?;
        validate_coverage_records(&coverage_records)?;

        evidence.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        reject_duplicate_evidence_ids(&evidence)?;
        validate_evidence_records(&evidence)?;
        let evidence_refs = evidence
            .iter()
            .map(|record| record.evidence_id().to_owned())
            .collect::<Vec<_>>();

        let (mut graph_nodes, mut graph_edges) = graph_records.into_parts();
        enforce_count("graph_nodes", graph_nodes.len(), limits.max_graph_nodes)?;
        enforce_count("graph_edges", graph_edges.len(), limits.max_graph_edges)?;
        graph_nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        graph_edges.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        reject_duplicate_graph_node_ids(&graph_nodes)?;
        reject_duplicate_graph_edge_ids(&graph_edges)?;
        validate_graph_records(&graph_nodes, &graph_edges)?;

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
        return Err(SnapshotCompositionError::RevisionPairMismatch {
            side: "CANDIDATE",
        });
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
                write!(formatter, "S1 snapshot input exceeds aggregate byte cap {max}")
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
            Self::Limits(error) => Some(error),
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
    let node_ids = nodes.iter().map(|node| &node.node_id).collect::<BTreeSet<_>>();
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
