use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use petgraph::{
    Direction,
    graph::{DiGraph, NodeIndex},
    visit::EdgeRef,
};

use crate::{
    GraphContractError, GraphEdge, GraphEdgeId, GraphNode, GraphNodeId, GraphRelation,
    validate_edge, validate_node,
};

/// Hard cap for caller-requested reverse-reachability depth.
///
/// The graph is untrusted analysis data. A bounded public traversal API keeps a
/// hostile or accidental request from turning a local blast-radius query into
/// unbounded work. The cap is intentionally far above normal review use.
pub const MAX_BLAST_RADIUS_DEPTH: usize = 64;

/// A validated in-memory projection of canonical Sentrdel graph records.
///
/// `petgraph` owns only ephemeral adjacency/index mechanics. Stable object
/// identity, provenance, confidence and semantic validation remain owned by
/// Sentrdel schema records. The projection is built in stable-ID order so the
/// same record set has deterministic observable behavior independent of input
/// iteration order.
pub struct GraphProjection {
    graph: DiGraph<GraphNodeId, GraphEdgeId>,
    node_indices: BTreeMap<GraphNodeId, NodeIndex>,
    nodes: BTreeMap<GraphNodeId, GraphNode>,
    edges: BTreeMap<GraphEdgeId, GraphEdge>,
}

impl GraphProjection {
    /// Build one directed graph projection from canonical records.
    ///
    /// Duplicate stable identities and edges whose endpoints are absent fail
    /// closed. Callers must choose which current revisions enter the projection;
    /// this type never guesses between multiple records for one stable identity.
    pub fn from_records(
        nodes: impl IntoIterator<Item = GraphNode>,
        edges: impl IntoIterator<Item = GraphEdge>,
    ) -> Result<Self, GraphProjectionError> {
        let mut canonical_nodes = BTreeMap::new();
        for node in nodes {
            validate_node(&node)?;
            let node_id = node.node_id.clone();
            if canonical_nodes.insert(node_id.clone(), node).is_some() {
                return Err(GraphProjectionError::DuplicateNodeId(node_id));
            }
        }

        let mut canonical_edges = BTreeMap::new();
        for edge in edges {
            validate_edge(&edge)?;
            let edge_id = edge.edge_id.clone();
            if canonical_edges.insert(edge_id.clone(), edge).is_some() {
                return Err(GraphProjectionError::DuplicateEdgeId(edge_id));
            }
        }

        let mut graph = DiGraph::with_capacity(canonical_nodes.len(), canonical_edges.len());
        let mut node_indices = BTreeMap::new();
        for node_id in canonical_nodes.keys() {
            let index = graph.add_node(node_id.clone());
            node_indices.insert(node_id.clone(), index);
        }

        for (edge_id, edge) in &canonical_edges {
            let source = node_indices.get(&edge.source).copied().ok_or_else(|| {
                GraphProjectionError::MissingEndpointNode {
                    edge_id: edge_id.clone(),
                    node_id: edge.source.clone(),
                }
            })?;
            let target = node_indices.get(&edge.target).copied().ok_or_else(|| {
                GraphProjectionError::MissingEndpointNode {
                    edge_id: edge_id.clone(),
                    node_id: edge.target.clone(),
                }
            })?;
            graph.add_edge(source, target, edge_id.clone());
        }

        Ok(Self {
            graph,
            node_indices,
            nodes: canonical_nodes,
            edges: canonical_edges,
        })
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn node(&self, node_id: &GraphNodeId) -> Option<&GraphNode> {
        self.nodes.get(node_id)
    }

    pub fn edge(&self, edge_id: &GraphEdgeId) -> Option<&GraphEdge> {
        self.edges.get(edge_id)
    }

    /// Stable-ID ordered node identities.
    pub fn node_ids(&self) -> impl Iterator<Item = &GraphNodeId> {
        self.nodes.keys()
    }

    /// Stable-ID ordered edge identities.
    pub fn edge_ids(&self) -> impl Iterator<Item = &GraphEdgeId> {
        self.edges.keys()
    }

    /// Return bounded reverse reachability from `seed` over explicitly allowed
    /// relations.
    ///
    /// Each hit contains one deterministic shortest witness path whose directed
    /// edges lead from the affected node toward the seed. The result states
    /// graph reachability only; it does not claim runtime causality or security
    /// impact beyond the provenance carried by the underlying records.
    pub fn reverse_reachability(
        &self,
        seed: &GraphNodeId,
        max_depth: usize,
        allowed_relations: &BTreeSet<GraphRelation>,
    ) -> Result<Vec<ReverseReachabilityHit>, GraphProjectionError> {
        if max_depth > MAX_BLAST_RADIUS_DEPTH {
            return Err(GraphProjectionError::DepthLimitExceeded {
                requested: max_depth,
                maximum: MAX_BLAST_RADIUS_DEPTH,
            });
        }
        if !self.node_indices.contains_key(seed) {
            return Err(GraphProjectionError::UnknownSeedNode(seed.clone()));
        }
        if max_depth == 0 || allowed_relations.is_empty() {
            return Ok(Vec::new());
        }

        let mut seen = BTreeSet::from([seed.clone()]);
        let mut paths = BTreeMap::from([(seed.clone(), Vec::<GraphEdgeId>::new())]);
        let mut frontier = vec![seed.clone()];
        let mut hits = Vec::new();

        for depth in 1..=max_depth {
            let mut candidates = Vec::new();
            for target_id in &frontier {
                let target_index = self.node_indices[target_id];
                for edge_ref in self.graph.edges_directed(target_index, Direction::Incoming) {
                    let edge_id = edge_ref.weight().clone();
                    let edge = &self.edges[&edge_id];
                    if !allowed_relations.contains(&edge.relation) {
                        continue;
                    }
                    let source_id = self.graph[edge_ref.source()].clone();
                    candidates.push((source_id, edge_id, target_id.clone()));
                }
            }

            candidates.sort();
            let mut next_frontier = Vec::new();
            for (source_id, edge_id, target_id) in candidates {
                if !seen.insert(source_id.clone()) {
                    continue;
                }

                let mut witness_edge_ids = vec![edge_id.clone()];
                witness_edge_ids.extend(
                    paths
                        .get(&target_id)
                        .expect("frontier nodes always have a witness path")
                        .iter()
                        .cloned(),
                );
                paths.insert(source_id.clone(), witness_edge_ids.clone());
                next_frontier.push(source_id.clone());
                hits.push(ReverseReachabilityHit {
                    node_id: source_id,
                    depth,
                    via_edge_id: edge_id,
                    witness_edge_ids,
                });
            }

            if next_frontier.is_empty() {
                break;
            }
            next_frontier.sort();
            frontier = next_frontier;
        }

        hits.sort_by(|left, right| {
            left.depth
                .cmp(&right.depth)
                .then_with(|| left.node_id.cmp(&right.node_id))
                .then_with(|| left.via_edge_id.cmp(&right.via_edge_id))
        });
        Ok(hits)
    }

    /// Compare this projection (`before`) with `after` by stable identity.
    ///
    /// Mutable attributes, provenance and edge confidence are deliberately not
    /// part of stable IDs, so they surface as `modified_*` records instead of
    /// misleading remove/add pairs.
    pub fn diff(&self, after: &Self) -> GraphDiff {
        let mut diff = GraphDiff::default();

        for (node_id, before_node) in &self.nodes {
            match after.nodes.get(node_id) {
                None => diff.removed_nodes.push(before_node.clone()),
                Some(after_node) if before_node != after_node => {
                    diff.modified_nodes.push(GraphNodeChange {
                        node_id: node_id.clone(),
                        before: before_node.clone(),
                        after: after_node.clone(),
                    });
                }
                Some(_) => {}
            }
        }
        for (node_id, after_node) in &after.nodes {
            if !self.nodes.contains_key(node_id) {
                diff.added_nodes.push(after_node.clone());
            }
        }

        for (edge_id, before_edge) in &self.edges {
            match after.edges.get(edge_id) {
                None => diff.removed_edges.push(before_edge.clone()),
                Some(after_edge) if before_edge != after_edge => {
                    diff.modified_edges.push(GraphEdgeChange {
                        edge_id: edge_id.clone(),
                        before: before_edge.clone(),
                        after: after_edge.clone(),
                    });
                }
                Some(_) => {}
            }
        }
        for (edge_id, after_edge) in &after.edges {
            if !self.edges.contains_key(edge_id) {
                diff.added_edges.push(after_edge.clone());
            }
        }

        diff
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReverseReachabilityHit {
    pub node_id: GraphNodeId,
    pub depth: usize,
    pub via_edge_id: GraphEdgeId,
    pub witness_edge_ids: Vec<GraphEdgeId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphNodeChange {
    pub node_id: GraphNodeId,
    pub before: GraphNode,
    pub after: GraphNode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphEdgeChange {
    pub edge_id: GraphEdgeId,
    pub before: GraphEdge,
    pub after: GraphEdge,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphDiff {
    pub added_nodes: Vec<GraphNode>,
    pub removed_nodes: Vec<GraphNode>,
    pub modified_nodes: Vec<GraphNodeChange>,
    pub added_edges: Vec<GraphEdge>,
    pub removed_edges: Vec<GraphEdge>,
    pub modified_edges: Vec<GraphEdgeChange>,
}

impl GraphDiff {
    pub fn is_empty(&self) -> bool {
        self.added_nodes.is_empty()
            && self.removed_nodes.is_empty()
            && self.modified_nodes.is_empty()
            && self.added_edges.is_empty()
            && self.removed_edges.is_empty()
            && self.modified_edges.is_empty()
    }
}

#[derive(Debug)]
pub enum GraphProjectionError {
    Contract(GraphContractError),
    DuplicateNodeId(GraphNodeId),
    DuplicateEdgeId(GraphEdgeId),
    MissingEndpointNode {
        edge_id: GraphEdgeId,
        node_id: GraphNodeId,
    },
    UnknownSeedNode(GraphNodeId),
    DepthLimitExceeded {
        requested: usize,
        maximum: usize,
    },
}

impl fmt::Display for GraphProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "graph projection contract failed: {error}"),
            Self::DuplicateNodeId(node_id) => write!(
                formatter,
                "graph projection contains duplicate node identity {}",
                node_id.as_str()
            ),
            Self::DuplicateEdgeId(edge_id) => write!(
                formatter,
                "graph projection contains duplicate edge identity {}",
                edge_id.as_str()
            ),
            Self::MissingEndpointNode { edge_id, node_id } => write!(
                formatter,
                "graph edge {} references missing projection node {}",
                edge_id.as_str(),
                node_id.as_str()
            ),
            Self::UnknownSeedNode(node_id) => write!(
                formatter,
                "reverse reachability seed {} is not present in the projection",
                node_id.as_str()
            ),
            Self::DepthLimitExceeded { requested, maximum } => write!(
                formatter,
                "reverse reachability depth {requested} exceeds maximum {maximum}"
            ),
        }
    }
}

impl Error for GraphProjectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::DuplicateNodeId(_)
            | Self::DuplicateEdgeId(_)
            | Self::MissingEndpointNode { .. }
            | Self::UnknownSeedNode(_)
            | Self::DepthLimitExceeded { .. } => None,
        }
    }
}

impl From<GraphContractError> for GraphProjectionError {
    fn from(error: GraphContractError) -> Self {
        Self::Contract(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GraphConfidenceBasis, GraphConfidenceSource, GraphNodeKind, GraphProvenanceId};

    fn provenance(value: &str) -> GraphProvenanceId {
        GraphProvenanceId::new(value).expect("valid provenance")
    }

    fn node(kind: GraphNodeKind, key: &str) -> GraphNode {
        GraphNode::new(
            kind,
            key,
            BTreeMap::new(),
            vec![provenance("evidence:t033")],
        )
        .expect("valid node")
    }

    fn edge(source: &GraphNode, target: &GraphNode, relation: GraphRelation) -> GraphEdge {
        GraphEdge::new(
            source.node_id.clone(),
            target.node_id.clone(),
            relation,
            GraphConfidenceSource::new(
                "fixture-producer",
                Some("1.0.0".to_owned()),
                GraphConfidenceBasis::Extracted,
            )
            .expect("valid confidence"),
            vec![provenance("evidence:t033")],
            BTreeMap::new(),
        )
        .expect("valid edge")
    }

    #[test]
    fn projection_is_stable_across_input_order() {
        let api = node(GraphNodeKind::Symbol, "crate::api");
        let service = node(GraphNodeKind::Symbol, "crate::service");
        let database = node(GraphNodeKind::Resource, "db:users");
        let calls = edge(&api, &service, GraphRelation::Calls);
        let reads = edge(&service, &database, GraphRelation::ReadsFrom);

        let forward = GraphProjection::from_records(
            vec![api.clone(), service.clone(), database.clone()],
            vec![calls.clone(), reads.clone()],
        )
        .expect("projection");
        let reverse =
            GraphProjection::from_records(vec![database, service, api], vec![reads, calls])
                .expect("projection");

        assert_eq!(
            forward.node_ids().cloned().collect::<Vec<_>>(),
            reverse.node_ids().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            forward.edge_ids().cloned().collect::<Vec<_>>(),
            reverse.edge_ids().cloned().collect::<Vec<_>>()
        );
        assert!(forward.diff(&reverse).is_empty());
    }

    #[test]
    fn projection_rejects_missing_edge_endpoint() {
        let source = node(GraphNodeKind::Symbol, "crate::source");
        let target = node(GraphNodeKind::Symbol, "crate::target");
        let relation = edge(&source, &target, GraphRelation::Calls);

        let result = GraphProjection::from_records(vec![source], vec![relation]);
        assert!(matches!(
            result,
            Err(GraphProjectionError::MissingEndpointNode { node_id, .. })
                if node_id == target.node_id
        ));
    }

    #[test]
    fn reverse_reachability_is_bounded_filtered_and_cycle_safe() {
        let api = node(GraphNodeKind::Symbol, "crate::api");
        let service = node(GraphNodeKind::Symbol, "crate::service");
        let helper = node(GraphNodeKind::Symbol, "crate::helper");
        let database = node(GraphNodeKind::Resource, "db:users");

        let api_calls_service = edge(&api, &service, GraphRelation::Calls);
        let helper_calls_service = edge(&helper, &service, GraphRelation::Calls);
        let service_reads_database = edge(&service, &database, GraphRelation::ReadsFrom);
        let service_calls_api = edge(&service, &api, GraphRelation::Calls);

        let projection = GraphProjection::from_records(
            vec![
                api.clone(),
                service.clone(),
                helper.clone(),
                database.clone(),
            ],
            vec![
                service_reads_database.clone(),
                helper_calls_service.clone(),
                api_calls_service.clone(),
                service_calls_api,
            ],
        )
        .expect("projection");

        let relations = BTreeSet::from([GraphRelation::Calls, GraphRelation::ReadsFrom]);
        let hits = projection
            .reverse_reachability(&database.node_id, 3, &relations)
            .expect("reachability");

        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].node_id, service.node_id);
        assert_eq!(hits[0].depth, 1);
        assert_eq!(
            hits[0].witness_edge_ids,
            vec![service_reads_database.edge_id]
        );

        let depth_two = &hits[1..];
        assert!(depth_two.iter().all(|hit| hit.depth == 2));
        assert_eq!(
            depth_two
                .iter()
                .map(|hit| hit.node_id.clone())
                .collect::<Vec<_>>(),
            {
                let mut ids = vec![api.node_id.clone(), helper.node_id.clone()];
                ids.sort();
                ids
            }
        );

        let calls_only = BTreeSet::from([GraphRelation::Calls]);
        assert!(
            projection
                .reverse_reachability(&database.node_id, 3, &calls_only)
                .expect("filtered reachability")
                .is_empty()
        );
    }

    #[test]
    fn reverse_reachability_rejects_unbounded_depth() {
        let seed = node(GraphNodeKind::Symbol, "crate::seed");
        let projection = GraphProjection::from_records(vec![seed.clone()], Vec::<GraphEdge>::new())
            .expect("projection");

        let result = projection.reverse_reachability(
            &seed.node_id,
            MAX_BLAST_RADIUS_DEPTH + 1,
            &BTreeSet::from([GraphRelation::Calls]),
        );
        assert!(matches!(
            result,
            Err(GraphProjectionError::DepthLimitExceeded { .. })
        ));
    }

    #[test]
    fn graph_diff_preserves_stable_identity_for_metadata_changes() {
        let service = node(GraphNodeKind::Symbol, "crate::service");
        let database = node(GraphNodeKind::Resource, "db:users");
        let reads = edge(&service, &database, GraphRelation::ReadsFrom);

        let before = GraphProjection::from_records(
            vec![service.clone(), database.clone()],
            vec![reads.clone()],
        )
        .expect("before");

        let mut changed_service = service.clone();
        changed_service
            .attributes
            .insert("owner".to_owned(), "security".into());
        changed_service
            .provenance_ids
            .push(provenance("evidence:t033:second"));
        changed_service
            .validate()
            .expect("changed node remains valid");

        let mut changed_reads = reads.clone();
        changed_reads.confidence_source = GraphConfidenceSource::new(
            "fixture-producer",
            Some("1.0.1".to_owned()),
            GraphConfidenceBasis::Inferred,
        )
        .expect("changed confidence");
        changed_reads
            .validate()
            .expect("changed edge remains valid");

        let after = GraphProjection::from_records(
            vec![database, changed_service.clone()],
            vec![changed_reads.clone()],
        )
        .expect("after");
        let diff = before.diff(&after);

        assert!(diff.added_nodes.is_empty());
        assert!(diff.removed_nodes.is_empty());
        assert!(diff.added_edges.is_empty());
        assert!(diff.removed_edges.is_empty());
        assert_eq!(diff.modified_nodes.len(), 1);
        assert_eq!(diff.modified_nodes[0].node_id, changed_service.node_id);
        assert_eq!(diff.modified_edges.len(), 1);
        assert_eq!(diff.modified_edges[0].edge_id, changed_reads.edge_id);
    }
}
