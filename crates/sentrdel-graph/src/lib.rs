#![forbid(unsafe_code)]
//! Thin evidence/property graph boundary; this crate is not a universal CPG.
//!
//! `sentrdel-schema` owns the versioned interchange representation. This crate
//! is the graph-domain entry point for stable identity derivation, provenance
//! validation, producer-local confidence metadata, deterministic `petgraph`
//! projection, bounded reverse reachability, stable graph diff, and bounded
//! SCIP artifact ingestion. Persistence lives in `sentrdel-store`.

mod projection;
mod scip;

pub use projection::{
    GraphDiff, GraphEdgeChange, GraphNodeChange, GraphProjection, GraphProjectionError,
    MAX_BLAST_RADIUS_DEPTH, ReverseReachabilityHit,
};
pub use scip::{
    MAX_SCIP_DOCUMENTS, MAX_SCIP_OCCURRENCES, MAX_SCIP_PATH_BYTES, MAX_SCIP_SYMBOL_BYTES,
    SCIP_REFERENCE_CAPABILITY, ScipArtifact, ScipCoverageGap, ScipDocument, ScipIngestionError,
    ScipIngestionRequest, ScipIngestionResult, ScipOccurrence, ScipOccurrenceRole, ScipPosition,
    ScipProducerQualification, ScipRange, ingest_scip, scip_coverage_gap,
};
pub use sentrdel_schema::graph::{
    GraphConfidenceBasis, GraphConfidenceSource, GraphContractError, GraphEdge, GraphEdgeId,
    GraphNode, GraphNodeId, GraphNodeKind, GraphProvenanceId, GraphRelation,
};

/// Sentrdel intentionally owns a thin security/evidence graph rather than a
/// universal code property graph.
pub const UNIVERSAL_CPG: bool = false;

/// Derive the canonical stable identity for a graph node.
///
/// Identity is domain-separated R1 SHA-256 over `(node_kind, semantic_key)`.
/// Mutable attributes and provenance do not change semantic identity.
pub fn stable_node_id(
    node_kind: GraphNodeKind,
    semantic_key: &str,
) -> Result<GraphNodeId, GraphContractError> {
    sentrdel_schema::graph::derive_graph_node_id(node_kind, semantic_key)
}

/// Derive the canonical stable identity for one directed graph edge.
///
/// Identity is domain-separated R1 SHA-256 over `(source, relation, target)`.
/// Confidence, provenance, and attributes remain observable metadata rather
/// than silently changing the semantic edge identity.
pub fn stable_edge_id(
    source: &GraphNodeId,
    relation: GraphRelation,
    target: &GraphNodeId,
) -> Result<GraphEdgeId, GraphContractError> {
    sentrdel_schema::graph::derive_graph_edge_id(source, relation, target)
}

/// Revalidate an untrusted graph-node interchange record before graph-domain
/// code relies on its claimed identity or provenance.
pub fn validate_node(record: &GraphNode) -> Result<(), GraphContractError> {
    record.validate()
}

/// Revalidate an untrusted graph-edge interchange record before graph-domain
/// code relies on its claimed directed identity, provenance, or confidence.
pub fn validate_edge(record: &GraphEdge) -> Result<(), GraphContractError> {
    record.validate()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn provenance(value: &str) -> GraphProvenanceId {
        GraphProvenanceId::new(value).expect("valid provenance")
    }

    fn node(kind: GraphNodeKind, key: &str) -> GraphNode {
        GraphNode::new(
            kind,
            key,
            BTreeMap::new(),
            vec![provenance("evidence:fixture")],
        )
        .expect("valid graph node")
    }

    #[test]
    fn graph_domain_api_preserves_stable_directed_identity() {
        let source = node(GraphNodeKind::Symbol, "crate::source");
        let target = node(GraphNodeKind::Symbol, "crate::target");

        assert_eq!(
            stable_node_id(GraphNodeKind::Symbol, "crate::source").expect("node id"),
            source.node_id
        );

        let forward = stable_edge_id(&source.node_id, GraphRelation::Calls, &target.node_id)
            .expect("forward edge id");
        let reverse = stable_edge_id(&target.node_id, GraphRelation::Calls, &source.node_id)
            .expect("reverse edge id");
        assert_ne!(forward, reverse);
    }

    #[test]
    fn graph_domain_revalidation_rejects_stale_claimed_identity() {
        let mut forged = node(GraphNodeKind::Resource, "db:users");
        forged.semantic_key = "db:admins".to_owned();

        assert!(matches!(
            validate_node(&forged),
            Err(GraphContractError::NodeIdentityMismatch)
        ));
    }

    #[test]
    fn confidence_is_explicit_without_epistemic_escalation() {
        let confidence = GraphConfidenceSource::new(
            "fixture-producer",
            Some("1.0.0".to_owned()),
            GraphConfidenceBasis::Inferred,
        )
        .expect("confidence");
        assert_eq!(confidence.basis, GraphConfidenceBasis::Inferred);
        assert_ne!(confidence.basis, GraphConfidenceBasis::Extracted);
    }
}
