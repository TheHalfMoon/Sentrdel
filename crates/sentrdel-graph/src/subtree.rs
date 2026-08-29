use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use crate::{GraphEdge, GraphNode, GraphNodeId, GraphProjection, GraphRelation};

pub const MAX_PROVENANCE_SUBTREE_DEPTH: usize = 32;
pub const MAX_PROVENANCE_SUBTREE_NODES: usize = 4_096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceSubtreeNode {
    pub depth: usize,
    pub node: GraphNode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceSubtree {
    pub root: GraphNodeId,
    pub nodes: Vec<ProvenanceSubtreeNode>,
    pub edges: Vec<GraphEdge>,
}

impl GraphProjection {
    /// Return a deterministic, bounded outgoing subtree rooted at `root`.
    ///
    /// The query preserves each node/edge's canonical provenance metadata and
    /// reports graph structure only. It does not promote graph confidence into
    /// Evidence authority, infer causality, or manufacture proof state.
    pub fn provenance_subtree(
        &self,
        root: &GraphNodeId,
        max_depth: usize,
        allowed_relations: &BTreeSet<GraphRelation>,
    ) -> Result<ProvenanceSubtree, ProvenanceSubtreeError> {
        if max_depth > MAX_PROVENANCE_SUBTREE_DEPTH {
            return Err(ProvenanceSubtreeError::DepthLimitExceeded {
                requested: max_depth,
                maximum: MAX_PROVENANCE_SUBTREE_DEPTH,
            });
        }
        if self.node(root).is_none() {
            return Err(ProvenanceSubtreeError::UnknownRoot(root.clone()));
        }

        let mut depths = BTreeMap::from([(root.clone(), 0usize)]);
        let mut frontier = vec![root.clone()];
        let mut selected_edges = BTreeMap::new();

        for depth in 1..=max_depth {
            if frontier.is_empty() || allowed_relations.is_empty() {
                break;
            }

            let frontier_set: BTreeSet<_> = frontier.into_iter().collect();
            let mut candidates = Vec::new();
            for edge_id in self.edge_ids() {
                let edge = self.edge(edge_id).expect("indexed edge must exist");
                if frontier_set.contains(&edge.source) && allowed_relations.contains(&edge.relation)
                {
                    candidates.push(edge.clone());
                }
            }
            candidates.sort_by(|left, right| left.edge_id.cmp(&right.edge_id));

            let mut next_frontier = BTreeSet::new();
            for edge in candidates {
                selected_edges.insert(edge.edge_id.clone(), edge.clone());
                if !depths.contains_key(&edge.target) {
                    if depths.len() >= MAX_PROVENANCE_SUBTREE_NODES {
                        return Err(ProvenanceSubtreeError::NodeLimitExceeded {
                            maximum: MAX_PROVENANCE_SUBTREE_NODES,
                        });
                    }
                    depths.insert(edge.target.clone(), depth);
                    next_frontier.insert(edge.target.clone());
                }
            }
            frontier = next_frontier.into_iter().collect();
        }

        let nodes = depths
            .into_iter()
            .map(|(node_id, depth)| ProvenanceSubtreeNode {
                depth,
                node: self
                    .node(&node_id)
                    .expect("selected node must exist in validated projection")
                    .clone(),
            })
            .collect();

        Ok(ProvenanceSubtree {
            root: root.clone(),
            nodes,
            edges: selected_edges.into_values().collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceSubtreeError {
    UnknownRoot(GraphNodeId),
    DepthLimitExceeded { requested: usize, maximum: usize },
    NodeLimitExceeded { maximum: usize },
}

impl fmt::Display for ProvenanceSubtreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRoot(root) => {
                write!(
                    formatter,
                    "provenance subtree root is not present: {}",
                    root.as_str()
                )
            }
            Self::DepthLimitExceeded { requested, maximum } => write!(
                formatter,
                "provenance subtree depth {requested} exceeds maximum {maximum}"
            ),
            Self::NodeLimitExceeded { maximum } => write!(
                formatter,
                "provenance subtree exceeds maximum node count {maximum}"
            ),
        }
    }
}

impl Error for ProvenanceSubtreeError {}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        GraphConfidenceBasis, GraphConfidenceSource, GraphEdge, GraphNodeKind, GraphProvenanceId,
        stable_edge_id,
    };

    fn provenance(id: &str) -> GraphProvenanceId {
        GraphProvenanceId::new(id).expect("provenance")
    }

    fn node(kind: GraphNodeKind, key: &str, provenance_id: &str) -> GraphNode {
        GraphNode::new(kind, key, BTreeMap::new(), vec![provenance(provenance_id)]).expect("node")
    }

    fn edge(source: &GraphNode, relation: GraphRelation, target: &GraphNode) -> GraphEdge {
        GraphEdge::new(
            source.node_id.clone(),
            target.node_id.clone(),
            relation,
            GraphConfidenceSource::new(
                "fixture",
                Some("1".to_owned()),
                GraphConfidenceBasis::Extracted,
            )
            .expect("confidence"),
            vec![provenance("evidence:edge")],
            BTreeMap::new(),
        )
        .expect("edge")
    }

    #[test]
    fn subtree_preserves_evidence_and_provenance_metadata_in_stable_order() {
        let finding = node(GraphNodeKind::Finding, "finding:a", "finding:canonical");
        let evidence = node(GraphNodeKind::Evidence, "evidence:a", "evidence:canonical");
        let file = node(GraphNodeKind::File, "src/lib.rs", "evidence:file");
        let supports = edge(&finding, GraphRelation::Supports, &evidence);
        let detected = edge(&evidence, GraphRelation::DetectedAs, &file);
        let projection = GraphProjection::from_records(
            vec![file.clone(), evidence.clone(), finding.clone()],
            vec![detected.clone(), supports.clone()],
        )
        .expect("projection");

        let relations = BTreeSet::from([GraphRelation::Supports, GraphRelation::DetectedAs]);
        let subtree = projection
            .provenance_subtree(&finding.node_id, 2, &relations)
            .expect("subtree");

        assert_eq!(subtree.root, finding.node_id);
        assert_eq!(subtree.nodes.len(), 3);
        assert!(subtree.nodes.iter().any(|entry| {
            entry.depth == 1
                && entry.node.node_id == evidence.node_id
                && entry.node.provenance_ids == vec![provenance("evidence:canonical")]
        }));
        assert_eq!(subtree.edges.len(), 2);
        assert_eq!(
            subtree
                .edges
                .iter()
                .map(|value| value.edge_id.clone())
                .collect::<Vec<_>>(),
            {
                let mut ids = vec![detected.edge_id, supports.edge_id];
                ids.sort();
                ids
            }
        );
    }

    #[test]
    fn relation_filter_and_depth_are_fail_closed_and_deterministic() {
        let root = node(GraphNodeKind::Finding, "finding:a", "finding:canonical");
        let evidence = node(GraphNodeKind::Evidence, "evidence:a", "evidence:canonical");
        let unsupported = edge(&root, GraphRelation::Calls, &evidence);
        let projection =
            GraphProjection::from_records(vec![root.clone(), evidence], vec![unsupported])
                .expect("projection");

        let subtree = projection
            .provenance_subtree(&root.node_id, 1, &BTreeSet::from([GraphRelation::Supports]))
            .expect("subtree");
        assert_eq!(subtree.nodes.len(), 1);
        assert!(subtree.edges.is_empty());

        assert!(matches!(
            projection.provenance_subtree(
                &root.node_id,
                MAX_PROVENANCE_SUBTREE_DEPTH + 1,
                &BTreeSet::new()
            ),
            Err(ProvenanceSubtreeError::DepthLimitExceeded { .. })
        ));
    }

    #[test]
    fn stable_edge_identity_is_unchanged_by_subtree_queries() {
        let root = node(GraphNodeKind::Finding, "finding:a", "finding:canonical");
        let evidence = node(GraphNodeKind::Evidence, "evidence:a", "evidence:canonical");
        let link = edge(&root, GraphRelation::Supports, &evidence);
        let expected = stable_edge_id(&root.node_id, GraphRelation::Supports, &evidence.node_id)
            .expect("stable edge");
        assert_eq!(link.edge_id, expected);
    }
}
