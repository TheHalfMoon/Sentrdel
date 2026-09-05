//! Bounded mapping from validated R3 observations into canonical graph records.
//!
//! This module creates only `sentrdel-schema` graph interchange records. It does
//! not own a graph runtime, perform traversal, infer cross-layer equivalence, or
//! grant Evidence/Finding authority. Callers may project the returned records
//! through the existing `sentrdel-graph` runtime.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use sentrdel_schema::{
    canonical::{CanonicalError, content_id},
    graph::{
        GraphConfidenceBasis, GraphConfidenceSource, GraphContractError, GraphEdge, GraphEdgeId,
        GraphNode, GraphNodeId, GraphNodeKind, GraphProvenanceId, GraphRelation,
    },
};

use super::model::{
    DataOperation, DataOperationKind, InvariantDefinition, ResourceKind, ResourceRef,
    RouteObservation, SourceLocation,
};

pub const DEFAULT_MAX_R3_GRAPH_NODES: usize = 4_096;
pub const DEFAULT_MAX_R3_GRAPH_EDGES: usize = 8_192;
pub const DEFAULT_MAX_R3_GRAPH_PROVENANCE_IDS: usize = 64;

/// R3 maps records into the existing graph interchange/runtime boundary only.
pub const R3_GRAPH_CREATES_SECOND_RUNTIME: bool = false;
/// R3 remains a thin security/evidence graph mapping rather than a universal CPG.
pub const R3_GRAPH_MAPPING_IS_UNIVERSAL_CPG: bool = false;
/// Producer-local graph confidence cannot mint Evidence epistemic authority.
pub const R3_GRAPH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY: bool = false;

const GRAPH_PRODUCER: &str = "sentrdel-review:r3-graph-map";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R3GraphLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_provenance_ids_per_record: usize,
}

impl Default for R3GraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_R3_GRAPH_NODES,
            max_edges: DEFAULT_MAX_R3_GRAPH_EDGES,
            max_provenance_ids_per_record: DEFAULT_MAX_R3_GRAPH_PROVENANCE_IDS,
        }
    }
}

impl R3GraphLimits {
    fn validate(self) -> Result<Self, R3GraphMappingError> {
        if self.max_nodes == 0
            || self.max_edges == 0
            || self.max_provenance_ids_per_record == 0
        {
            return Err(R3GraphMappingError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R3GraphRecords {
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

impl R3GraphRecords {
    #[must_use]
    pub fn nodes(&self) -> &[GraphNode] {
        &self.nodes
    }

    #[must_use]
    pub fn edges(&self) -> &[GraphEdge] {
        &self.edges
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<GraphNode>, Vec<GraphEdge>) {
        (self.nodes, self.edges)
    }
}

#[derive(Debug)]
pub enum R3GraphMappingError {
    InvalidLimits,
    NodeLimitExceeded { maximum: usize },
    EdgeLimitExceeded { maximum: usize },
    ProvenanceLimitExceeded { maximum: usize },
    Canonical(CanonicalError),
    GraphContract(GraphContractError),
}

impl fmt::Display for R3GraphMappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("R3 graph mapping limits must be non-zero"),
            Self::NodeLimitExceeded { maximum } => {
                write!(formatter, "R3 graph node cap {maximum} exceeded")
            }
            Self::EdgeLimitExceeded { maximum } => {
                write!(formatter, "R3 graph edge cap {maximum} exceeded")
            }
            Self::ProvenanceLimitExceeded { maximum } => write!(
                formatter,
                "R3 graph provenance-per-record cap {maximum} exceeded"
            ),
            Self::Canonical(error) => write!(formatter, "R3 graph identity failed: {error}"),
            Self::GraphContract(error) => write!(formatter, "R3 graph record failed: {error}"),
        }
    }
}

impl Error for R3GraphMappingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::GraphContract(error) => Some(error),
            Self::InvalidLimits
            | Self::NodeLimitExceeded { .. }
            | Self::EdgeLimitExceeded { .. }
            | Self::ProvenanceLimitExceeded { .. } => None,
        }
    }
}

impl From<CanonicalError> for R3GraphMappingError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

impl From<GraphContractError> for R3GraphMappingError {
    fn from(value: GraphContractError) -> Self {
        Self::GraphContract(value)
    }
}

/// Map only R3 observations whose semantics fit the existing graph vocabulary.
///
/// Deliberately not mapped here: actors, guards, values, provider-client
/// authority, R2 subjects, and cross-layer equivalence. Their current R3 IR
/// remains authoritative until later linking/correlation tasks can prove a
/// semantically valid relationship without overloading graph node kinds.
pub fn map_validated_observations(
    routes: &[RouteObservation],
    data_operations: &[DataOperation],
    invariants: &[InvariantDefinition],
    limits: R3GraphLimits,
) -> Result<R3GraphRecords, R3GraphMappingError> {
    let limits = limits.validate()?;
    let confidence = confidence_source()?;
    let mut nodes = BTreeMap::<GraphNodeId, GraphNode>::new();
    let mut edges = BTreeMap::<GraphEdgeId, GraphEdge>::new();

    for route in routes {
        let route_node = GraphNode::new(
            GraphNodeKind::Symbol,
            format!("r3:route:{}", route.route_id().as_str()),
            BTreeMap::new(),
            provenance_ids(route.provenance())?,
        )?;
        let route_id = route_node.node_id.clone();
        insert_node(&mut nodes, route_node, limits)?;

        if let Some(handler_key) = route.handler_semantic_key() {
            let handler_node = GraphNode::new(
                GraphNodeKind::Symbol,
                format!("r3:handler:{handler_key}"),
                BTreeMap::new(),
                provenance_ids(route.provenance())?,
            )?;
            let handler_id = handler_node.node_id.clone();
            insert_node(&mut nodes, handler_node, limits)?;
            insert_edge(
                &mut edges,
                GraphEdge::new(
                    route_id,
                    handler_id,
                    GraphRelation::Refs,
                    confidence.clone(),
                    provenance_ids(route.provenance())?,
                    BTreeMap::new(),
                )?,
                limits,
            )?;
        }
    }

    for operation in data_operations {
        let resource_node = GraphNode::new(
            GraphNodeKind::Resource,
            resource_semantic_key(operation.resource())?,
            BTreeMap::new(),
            provenance_ids(operation.provenance())?,
        )?;
        let resource_id = resource_node.node_id.clone();
        insert_node(&mut nodes, resource_node, limits)?;

        let Some(relation) = data_relation(operation.operation_kind()) else {
            continue;
        };
        let Some(handler) = operation.handler_symbol() else {
            continue;
        };

        let handler_node = GraphNode::new(
            GraphNodeKind::Symbol,
            format!("r3:semantic-symbol:{}", handler.as_str()),
            BTreeMap::new(),
            provenance_ids(operation.provenance())?,
        )?;
        let handler_id = handler_node.node_id.clone();
        insert_node(&mut nodes, handler_node, limits)?;
        insert_edge(
            &mut edges,
            GraphEdge::new(
                handler_id,
                resource_id,
                relation,
                confidence.clone(),
                provenance_ids(operation.provenance())?,
                BTreeMap::new(),
            )?,
            limits,
        )?;
    }

    for invariant in invariants {
        insert_node(
            &mut nodes,
            GraphNode::new(
                GraphNodeKind::Invariant,
                format!("r3:invariant:{}", invariant.invariant_id().as_str()),
                BTreeMap::new(),
                provenance_ids(invariant.provenance())?,
            )?,
            limits,
        )?;
    }

    Ok(R3GraphRecords {
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
    })
}

fn confidence_source() -> Result<GraphConfidenceSource, R3GraphMappingError> {
    Ok(GraphConfidenceSource::new(
        GRAPH_PRODUCER,
        Some(env!("CARGO_PKG_VERSION").to_owned()),
        GraphConfidenceBasis::Extracted,
    )?)
}

fn provenance_ids(
    provenance: &[SourceLocation],
) -> Result<Vec<GraphProvenanceId>, R3GraphMappingError> {
    provenance
        .iter()
        .map(|location| {
            let digest = content_id(
                "r3-graph-source",
                &(
                    location.path().as_str(),
                    location.start_byte(),
                    location.end_byte(),
                    location.content_digest(),
                ),
            )?;
            Ok(GraphProvenanceId::new(format!("r3-source:{digest}"))?)
        })
        .collect()
}

fn resource_semantic_key(resource: &ResourceRef) -> Result<String, R3GraphMappingError> {
    let digest = content_id(
        "r3-graph-resource",
        &(
            resource.provider(),
            resource.namespace(),
            resource.resource_name(),
            resource_kind_tag(resource.resource_kind()),
        ),
    )?;
    Ok(format!("r3:resource:{digest}"))
}

const fn resource_kind_tag(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Table => "table",
        ResourceKind::View => "view",
        ResourceKind::Function => "function",
        ResourceKind::StorageObject => "storage-object",
        ResourceKind::ApplicationResource => "application-resource",
        ResourceKind::OtherSupported => "other-supported",
    }
}

const fn data_relation(kind: DataOperationKind) -> Option<GraphRelation> {
    match kind {
        DataOperationKind::Read => Some(GraphRelation::ReadsFrom),
        DataOperationKind::Insert
        | DataOperationKind::Update
        | DataOperationKind::Upsert
        | DataOperationKind::Delete => Some(GraphRelation::WritesTo),
        DataOperationKind::Rpc | DataOperationKind::OtherSupported => None,
    }
}

fn insert_node(
    nodes: &mut BTreeMap<GraphNodeId, GraphNode>,
    node: GraphNode,
    limits: R3GraphLimits,
) -> Result<(), R3GraphMappingError> {
    if let Some(existing) = nodes.get_mut(&node.node_id) {
        merge_provenance(
            &mut existing.provenance_ids,
            node.provenance_ids,
            limits.max_provenance_ids_per_record,
        )?;
        existing.validate()?;
        return Ok(());
    }
    if nodes.len() >= limits.max_nodes {
        return Err(R3GraphMappingError::NodeLimitExceeded {
            maximum: limits.max_nodes,
        });
    }
    node.validate()?;
    nodes.insert(node.node_id.clone(), node);
    Ok(())
}

fn insert_edge(
    edges: &mut BTreeMap<GraphEdgeId, GraphEdge>,
    edge: GraphEdge,
    limits: R3GraphLimits,
) -> Result<(), R3GraphMappingError> {
    if let Some(existing) = edges.get_mut(&edge.edge_id) {
        merge_provenance(
            &mut existing.provenance_ids,
            edge.provenance_ids,
            limits.max_provenance_ids_per_record,
        )?;
        existing.validate()?;
        return Ok(());
    }
    if edges.len() >= limits.max_edges {
        return Err(R3GraphMappingError::EdgeLimitExceeded {
            maximum: limits.max_edges,
        });
    }
    edge.validate()?;
    edges.insert(edge.edge_id.clone(), edge);
    Ok(())
}

fn merge_provenance(
    existing: &mut Vec<GraphProvenanceId>,
    additional: Vec<GraphProvenanceId>,
    maximum: usize,
) -> Result<(), R3GraphMappingError> {
    let merged = existing
        .iter()
        .cloned()
        .chain(additional)
        .collect::<BTreeSet<_>>();
    if merged.len() > maximum {
        return Err(R3GraphMappingError::ProvenanceLimitExceeded { maximum });
    }
    *existing = merged.into_iter().collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::coverage::CoverageState;

    use crate::{
        business_logic::model::{
            BusinessLogicLimits, FrameworkFamily, HttpMethod, InvariantKind, InvariantRequirement,
            InvariantScope, InvariantSource, StableSemanticId,
        },
        view::NormalizedRepoPath,
    };

    fn id(namespace: &str, value: &str) -> StableSemanticId {
        StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
            .expect("stable semantic id")
    }

    fn location(path: &str, start: usize) -> SourceLocation {
        SourceLocation::new(
            NormalizedRepoPath::parse(path, 4_096).expect("normalized path"),
            start,
            start + 8,
            format!("sha256:{start:064x}"),
        )
        .expect("source location")
    }

    fn route(provenance: Vec<SourceLocation>) -> RouteObservation {
        RouteObservation::new(
            id("r3.route", "users"),
            FrameworkFamily::Express,
            HttpMethod::Get,
            "/users/:id",
            Some("src/routes/users.js::handler".to_owned()),
            Vec::new(),
            provenance,
            CoverageState::Covered,
            BusinessLogicLimits::default(),
        )
        .expect("route")
    }

    fn operation(kind: DataOperationKind, provenance: Vec<SourceLocation>) -> DataOperation {
        DataOperation::new(
            id("r3.operation", match kind {
                DataOperationKind::Read => "read",
                DataOperationKind::Insert => "insert",
                DataOperationKind::Update => "update",
                DataOperationKind::Upsert => "upsert",
                DataOperationKind::Delete => "delete",
                DataOperationKind::Rpc => "rpc",
                DataOperationKind::OtherSupported => "other",
            }),
            kind,
            ResourceRef::new(
                Some("supabase".to_owned()),
                Some("public".to_owned()),
                "profiles",
                ResourceKind::Table,
                None,
                BusinessLogicLimits::default(),
            )
            .expect("resource"),
            None,
            Vec::new(),
            None,
            None,
            None,
            Some(id("r3.handler", "users")),
            provenance,
            CoverageState::Covered,
            BusinessLogicLimits::default(),
        )
        .expect("operation")
    }

    fn invariant(provenance: Vec<SourceLocation>) -> InvariantDefinition {
        InvariantDefinition::new(
            id("r3.invariant", "admin-role"),
            InvariantKind::RequiredRole,
            InvariantSource::BuiltIn,
            InvariantScope::new(
                None,
                Vec::new(),
                None,
                Vec::new(),
                Vec::new(),
                BusinessLogicLimits::default(),
            )
            .expect("scope"),
            InvariantRequirement::RequiredRole {
                required_roles: vec!["admin".to_owned()],
            },
            provenance,
            BusinessLogicLimits::default(),
        )
        .expect("invariant")
    }

    #[test]
    fn maps_only_semantically_valid_existing_graph_vocabulary() {
        let records = map_validated_observations(
            &[route(vec![location("src/routes/users.js", 0)])],
            &[
                operation(DataOperationKind::Read, vec![location("src/data/users.js", 10)]),
                operation(DataOperationKind::Update, vec![location("src/data/users.js", 20)]),
            ],
            &[invariant(vec![location("src/security/invariants.rs", 30)])],
            R3GraphLimits::default(),
        )
        .expect("graph records");

        assert!(records.nodes().iter().any(|node| node.node_kind == GraphNodeKind::Symbol));
        assert!(records.nodes().iter().any(|node| node.node_kind == GraphNodeKind::Resource));
        assert!(records.nodes().iter().any(|node| node.node_kind == GraphNodeKind::Invariant));
        assert!(records.edges().iter().any(|edge| edge.relation == GraphRelation::Refs));
        assert!(records.edges().iter().any(|edge| edge.relation == GraphRelation::ReadsFrom));
        assert!(records.edges().iter().any(|edge| edge.relation == GraphRelation::WritesTo));
        assert!(records
            .edges()
            .iter()
            .all(|edge| edge.confidence_source.basis == GraphConfidenceBasis::Extracted));
    }

    #[test]
    fn unsupported_operation_semantics_do_not_invent_graph_relations() {
        for kind in [DataOperationKind::Rpc, DataOperationKind::OtherSupported] {
            let records = map_validated_observations(
                &[],
                &[operation(kind, vec![location("src/data/rpc.js", 0)])],
                &[],
                R3GraphLimits::default(),
            )
            .expect("graph records");
            assert_eq!(records.nodes().len(), 1);
            assert!(records.edges().is_empty());
            assert_eq!(records.nodes()[0].node_kind, GraphNodeKind::Resource);
        }
    }

    #[test]
    fn mapping_is_deterministic_and_deduplicates_stable_records() {
        let first = route(vec![location("src/routes/users.js", 0)]);
        let second = route(vec![location("src/routes/users.js", 16)]);
        let forward = map_validated_observations(
            &[first.clone(), second.clone()],
            &[],
            &[],
            R3GraphLimits::default(),
        )
        .expect("forward mapping");
        let reverse = map_validated_observations(
            &[second, first],
            &[],
            &[],
            R3GraphLimits::default(),
        )
        .expect("reverse mapping");
        assert_eq!(forward, reverse);
        assert_eq!(forward.nodes().len(), 2);
        assert_eq!(forward.edges().len(), 1);
        assert_eq!(forward.edges()[0].provenance_ids.len(), 2);
    }

    #[test]
    fn graph_caps_fail_closed_before_unbounded_projection() {
        let error = map_validated_observations(
            &[route(vec![location("src/routes/users.js", 0)])],
            &[],
            &[],
            R3GraphLimits {
                max_nodes: 1,
                ..R3GraphLimits::default()
            },
        )
        .expect_err("route plus handler must exceed one-node cap");
        assert!(matches!(
            error,
            R3GraphMappingError::NodeLimitExceeded { maximum: 1 }
        ));

        assert!(matches!(
            map_validated_observations(
                &[],
                &[],
                &[],
                R3GraphLimits {
                    max_nodes: 0,
                    ..R3GraphLimits::default()
                }
            ),
            Err(R3GraphMappingError::InvalidLimits)
        ));
    }

    #[test]
    fn provenance_cap_fails_visible_on_deduplicated_records() {
        let error = map_validated_observations(
            &[
                route(vec![location("src/routes/users.js", 0)]),
                route(vec![location("src/routes/users.js", 16)]),
            ],
            &[],
            &[],
            R3GraphLimits {
                max_provenance_ids_per_record: 1,
                ..R3GraphLimits::default()
            },
        )
        .expect_err("distinct provenance must not be silently dropped");
        assert!(matches!(
            error,
            R3GraphMappingError::ProvenanceLimitExceeded { maximum: 1 }
        ));
    }

    #[test]
    fn graph_mapping_preserves_authority_ceilings() {
        const { assert!(!R3_GRAPH_CREATES_SECOND_RUNTIME) };
        const { assert!(!R3_GRAPH_MAPPING_IS_UNIVERSAL_CPG) };
        const { assert!(!R3_GRAPH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY) };
        const { assert!(!super::super::R3_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!super::super::R3_PROVIDER_CREDENTIALS_ALLOWED) };
        const { assert!(!super::super::R3_DIRECT_FINDING_CREATION_ALLOWED) };
    }
}
