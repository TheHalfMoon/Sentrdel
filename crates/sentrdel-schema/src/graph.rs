//! Versioned security-graph interchange contracts and stable identities.
//!
//! The R1 graph is a thin evidence/property graph, not a universal CPG. Graph
//! confidence is producer-local metadata and is deliberately separate from
//! Evidence epistemic authority: no confidence value in this module can mint
//! FACT or VERIFIED Evidence.

use crate::{
    SCHEMA_V1,
    canonical::{CanonicalError, canonical_json_bytes, content_id},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error, fmt};

const GRAPH_NODE_NAMESPACE: &str = "graph-node";
const GRAPH_EDGE_NAMESPACE: &str = "graph-edge";

/// Stable content identity for one graph node.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct GraphNodeId(String);

impl GraphNodeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable content identity for one directed graph edge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct GraphEdgeId(String);

impl GraphEdgeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Stable reference to evidence, an event, a producer record, or another
/// provenance-bearing canonical object.
///
/// Provenance references are intentionally not restricted to one identifier
/// namespace. Callers must bind them to the authoritative object type at the
/// ingestion/reconciliation boundary that owns that object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct GraphProvenanceId(String);

impl GraphProvenanceId {
    pub fn new(value: impl Into<String>) -> Result<Self, GraphContractError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GraphContractError::BlankProvenanceId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Initial R1 node vocabulary. These classes describe graph shape only; they
/// do not confer Finding, policy, or epistemic authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphNodeKind {
    Project,
    File,
    Symbol,
    Reference,
    Resource,
    Dependency,
    Workflow,
    Provider,
    McpServer,
    McpTool,
    AgentAction,
    Evidence,
    Finding,
    Invariant,
}

/// Initial R1 directed relation vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphRelation {
    Refs,
    Calls,
    DependsOn,
    ReadsFrom,
    WritesTo,
    FlowsTo,
    AffectedBy,
    Supports,
    Contradicts,
    DetectedAs,
    Invokes,
    CrossesTrustBoundary,
}

/// Producer-local confidence vocabulary for a graph relationship.
///
/// This is not an `EpistemicClass`. `Extracted` does not mean FACT,
/// `Inferred` does not gain deterministic authority, and no variant maps to
/// VERIFIED. Evidence authority remains owned by the Evidence boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphConfidenceBasis {
    Extracted,
    Inferred,
    Ambiguous,
}

/// Identifies who supplied an edge's confidence assertion and what local basis
/// that producer assigned to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphConfidenceSource {
    pub producer: String,
    pub producer_version: Option<String>,
    pub basis: GraphConfidenceBasis,
}

impl GraphConfidenceSource {
    pub fn new(
        producer: impl Into<String>,
        producer_version: Option<String>,
        basis: GraphConfidenceBasis,
    ) -> Result<Self, GraphContractError> {
        let value = Self {
            producer: producer.into(),
            producer_version,
            basis,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), GraphContractError> {
        if self.producer.trim().is_empty() {
            return Err(GraphContractError::BlankConfidenceProducer);
        }
        if self
            .producer_version
            .as_deref()
            .is_some_and(|version| version.trim().is_empty())
        {
            return Err(GraphContractError::BlankConfidenceProducerVersion);
        }
        Ok(())
    }
}

/// Canonical R1 graph node wire record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    pub schema_version: String,
    pub node_id: GraphNodeId,
    pub node_kind: GraphNodeKind,
    pub semantic_key: String,
    pub attributes: BTreeMap<String, Value>,
    pub provenance_ids: Vec<GraphProvenanceId>,
}

impl GraphNode {
    pub fn new(
        node_kind: GraphNodeKind,
        semantic_key: impl Into<String>,
        attributes: BTreeMap<String, Value>,
        provenance_ids: Vec<GraphProvenanceId>,
    ) -> Result<Self, GraphContractError> {
        let semantic_key = semantic_key.into();
        validate_semantic_key(&semantic_key)?;
        validate_attributes(&attributes)?;
        validate_provenance(&provenance_ids)?;
        let node_id = derive_graph_node_id(node_kind, &semantic_key)?;

        Ok(Self {
            schema_version: SCHEMA_V1.to_owned(),
            node_id,
            node_kind,
            semantic_key,
            attributes,
            provenance_ids,
        })
    }

    /// Revalidate an untrusted wire/persistence record and its claimed stable
    /// identity before graph algorithms or persistence rely on it.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        if self.schema_version != SCHEMA_V1 {
            return Err(GraphContractError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        validate_semantic_key(&self.semantic_key)?;
        validate_attributes(&self.attributes)?;
        validate_provenance(&self.provenance_ids)?;
        let expected = derive_graph_node_id(self.node_kind, &self.semantic_key)?;
        if self.node_id != expected {
            return Err(GraphContractError::NodeIdentityMismatch);
        }
        Ok(())
    }
}

/// Canonical R1 directed graph edge wire record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    pub schema_version: String,
    pub edge_id: GraphEdgeId,
    pub source: GraphNodeId,
    pub target: GraphNodeId,
    pub relation: GraphRelation,
    pub confidence_source: GraphConfidenceSource,
    pub provenance_ids: Vec<GraphProvenanceId>,
    pub attributes: BTreeMap<String, Value>,
}

impl GraphEdge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: GraphNodeId,
        target: GraphNodeId,
        relation: GraphRelation,
        confidence_source: GraphConfidenceSource,
        provenance_ids: Vec<GraphProvenanceId>,
        attributes: BTreeMap<String, Value>,
    ) -> Result<Self, GraphContractError> {
        validate_node_id(&source)?;
        validate_node_id(&target)?;
        confidence_source.validate()?;
        validate_provenance(&provenance_ids)?;
        validate_attributes(&attributes)?;
        let edge_id = derive_graph_edge_id(&source, relation, &target)?;

        Ok(Self {
            schema_version: SCHEMA_V1.to_owned(),
            edge_id,
            source,
            target,
            relation,
            confidence_source,
            provenance_ids,
            attributes,
        })
    }

    /// Revalidate an untrusted wire/persistence record and its claimed stable
    /// directed identity before graph algorithms or persistence rely on it.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        if self.schema_version != SCHEMA_V1 {
            return Err(GraphContractError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        validate_node_id(&self.source)?;
        validate_node_id(&self.target)?;
        self.confidence_source.validate()?;
        validate_provenance(&self.provenance_ids)?;
        validate_attributes(&self.attributes)?;
        let expected = derive_graph_edge_id(&self.source, self.relation, &self.target)?;
        if self.edge_id != expected {
            return Err(GraphContractError::EdgeIdentityMismatch);
        }
        Ok(())
    }
}

/// Derive a stable node identity from semantic identity only. Mutable graph
/// metadata is deliberately excluded so T033 can report metadata changes on
/// the same node rather than silently turning them into remove/add operations.
pub fn derive_graph_node_id(
    node_kind: GraphNodeKind,
    semantic_key: &str,
) -> Result<GraphNodeId, GraphContractError> {
    validate_semantic_key(semantic_key)?;
    Ok(GraphNodeId(content_id(
        GRAPH_NODE_NAMESPACE,
        &(node_kind, semantic_key),
    )?))
}

/// Derive a stable directed edge identity from source, relation, and target.
/// Confidence, provenance, and attributes are intentionally excluded from the
/// identity so changes to those fields remain observable metadata changes.
pub fn derive_graph_edge_id(
    source: &GraphNodeId,
    relation: GraphRelation,
    target: &GraphNodeId,
) -> Result<GraphEdgeId, GraphContractError> {
    validate_node_id(source)?;
    validate_node_id(target)?;
    Ok(GraphEdgeId(content_id(
        GRAPH_EDGE_NAMESPACE,
        &(source.as_str(), relation, target.as_str()),
    )?))
}

#[derive(Debug)]
pub enum GraphContractError {
    BlankSemanticKey,
    BlankProvenanceId,
    MissingProvenance,
    DuplicateProvenanceId(String),
    BlankConfidenceProducer,
    BlankConfidenceProducerVersion,
    InvalidNodeId(String),
    UnsupportedSchemaVersion(String),
    NodeIdentityMismatch,
    EdgeIdentityMismatch,
    Canonical(CanonicalError),
}

impl fmt::Display for GraphContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankSemanticKey => formatter.write_str("graph semantic key must not be blank"),
            Self::BlankProvenanceId => formatter.write_str("graph provenance id must not be blank"),
            Self::MissingProvenance => {
                formatter.write_str("graph records require explicit provenance")
            }
            Self::DuplicateProvenanceId(id) => {
                write!(formatter, "graph provenance id is duplicated: {id:?}")
            }
            Self::BlankConfidenceProducer => {
                formatter.write_str("graph confidence producer must not be blank")
            }
            Self::BlankConfidenceProducerVersion => {
                formatter.write_str("graph confidence producer version must not be blank")
            }
            Self::InvalidNodeId(id) => write!(
                formatter,
                "graph node id must use canonical R1 sha256:<64 lowercase hex> form: {id:?}"
            ),
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported graph schema version: {version:?}")
            }
            Self::NodeIdentityMismatch => {
                formatter.write_str("graph node id does not match its canonical semantic identity")
            }
            Self::EdgeIdentityMismatch => {
                formatter.write_str("graph edge id does not match its canonical directed identity")
            }
            Self::Canonical(error) => write!(formatter, "graph canonicalization failed: {error}"),
        }
    }
}

impl Error for GraphContractError {}

impl From<CanonicalError> for GraphContractError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

fn validate_semantic_key(semantic_key: &str) -> Result<(), GraphContractError> {
    if semantic_key.trim().is_empty() {
        return Err(GraphContractError::BlankSemanticKey);
    }
    Ok(())
}

fn validate_attributes(attributes: &BTreeMap<String, Value>) -> Result<(), GraphContractError> {
    canonical_json_bytes(attributes)?;
    Ok(())
}

fn validate_provenance(provenance: &[GraphProvenanceId]) -> Result<(), GraphContractError> {
    if provenance.is_empty() {
        return Err(GraphContractError::MissingProvenance);
    }

    let mut seen = std::collections::BTreeSet::new();
    for id in provenance {
        if id.as_str().trim().is_empty() {
            return Err(GraphContractError::BlankProvenanceId);
        }
        if !seen.insert(id.as_str()) {
            return Err(GraphContractError::DuplicateProvenanceId(
                id.as_str().to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_node_id(id: &GraphNodeId) -> Result<(), GraphContractError> {
    if !is_canonical_sha256_id(id.as_str()) {
        return Err(GraphContractError::InvalidNodeId(id.as_str().to_owned()));
    }
    Ok(())
}

fn is_canonical_sha256_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(id: &str) -> GraphProvenanceId {
        GraphProvenanceId::new(id).expect("provenance")
    }

    fn confidence(basis: GraphConfidenceBasis) -> GraphConfidenceSource {
        GraphConfidenceSource::new("fixture-producer", Some("1.0.0".to_owned()), basis)
            .expect("confidence")
    }

    fn node(kind: GraphNodeKind, key: &str) -> GraphNode {
        GraphNode::new(
            kind,
            key,
            BTreeMap::new(),
            vec![provenance("evidence:fixture")],
        )
        .expect("node")
    }

    #[test]
    fn node_identity_is_stable_domain_separated_and_kind_sensitive() {
        let file_a = derive_graph_node_id(GraphNodeKind::File, "src/lib.rs").expect("file id");
        let file_b = derive_graph_node_id(GraphNodeKind::File, "src/lib.rs").expect("file id");
        let symbol =
            derive_graph_node_id(GraphNodeKind::Symbol, "src/lib.rs").expect("symbol id");

        assert_eq!(file_a, file_b);
        assert_ne!(file_a, symbol);
        assert!(is_canonical_sha256_id(file_a.as_str()));
    }

    #[test]
    fn edge_identity_preserves_direction_and_relation() {
        let source = node(GraphNodeKind::File, "src/a.rs").node_id;
        let target = node(GraphNodeKind::File, "src/b.rs").node_id;

        let refs = derive_graph_edge_id(&source, GraphRelation::Refs, &target).expect("edge id");
        let reversed =
            derive_graph_edge_id(&target, GraphRelation::Refs, &source).expect("edge id");
        let calls = derive_graph_edge_id(&source, GraphRelation::Calls, &target).expect("edge id");

        assert_ne!(refs, reversed);
        assert_ne!(refs, calls);
    }

    #[test]
    fn mutable_edge_metadata_does_not_change_semantic_edge_identity() {
        let source = node(GraphNodeKind::Symbol, "crate::source").node_id;
        let target = node(GraphNodeKind::Symbol, "crate::target").node_id;
        let first = GraphEdge::new(
            source.clone(),
            target.clone(),
            GraphRelation::Calls,
            confidence(GraphConfidenceBasis::Extracted),
            vec![provenance("evidence:first")],
            BTreeMap::new(),
        )
        .expect("first edge");

        let mut changed_attributes = BTreeMap::new();
        changed_attributes.insert("call_site".to_owned(), Value::String("src/lib.rs:7".to_owned()));
        let second = GraphEdge::new(
            source,
            target,
            GraphRelation::Calls,
            confidence(GraphConfidenceBasis::Ambiguous),
            vec![provenance("evidence:second")],
            changed_attributes,
        )
        .expect("second edge");

        assert_eq!(first.edge_id, second.edge_id);
        assert_ne!(first.confidence_source, second.confidence_source);
        assert_ne!(first.provenance_ids, second.provenance_ids);
        assert_ne!(first.attributes, second.attributes);
    }

    #[test]
    fn untrusted_records_fail_closed_on_identity_and_provenance() {
        let mut valid = node(GraphNodeKind::Resource, "db:users");
        valid.node_id = GraphNodeId("sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned());
        assert!(matches!(
            valid.validate(),
            Err(GraphContractError::NodeIdentityMismatch)
        ));

        assert!(matches!(
            GraphNode::new(
                GraphNodeKind::Resource,
                "db:users",
                BTreeMap::new(),
                Vec::new()
            ),
            Err(GraphContractError::MissingProvenance)
        ));
    }

    #[test]
    fn confidence_is_graph_metadata_not_evidence_epistemic_authority() {
        let encoded = serde_json::to_string(&confidence(GraphConfidenceBasis::Extracted))
            .expect("serialize confidence");
        assert!(encoded.contains("EXTRACTED"));
        assert!(!encoded.contains("FACT"));
        assert!(!encoded.contains("VERIFIED"));
    }

    #[test]
    fn canonical_graph_attributes_reject_floating_point_numbers() {
        let mut attributes = BTreeMap::new();
        attributes.insert("score".to_owned(), serde_json::json!(0.5));
        let error = GraphNode::new(
            GraphNodeKind::Reference,
            "reference:fixture",
            attributes,
            vec![provenance("evidence:fixture")],
        )
        .expect_err("floating attributes must fail canonical validation");
        assert!(matches!(error, GraphContractError::Canonical(_)));
    }

    #[test]
    fn duplicate_or_blank_provenance_and_blank_confidence_fail_closed() {
        assert!(matches!(
            GraphProvenanceId::new("   "),
            Err(GraphContractError::BlankProvenanceId)
        ));
        assert!(matches!(
            GraphNode::new(
                GraphNodeKind::Project,
                "project:fixture",
                BTreeMap::new(),
                vec![provenance("evidence:x"), provenance("evidence:x")]
            ),
            Err(GraphContractError::DuplicateProvenanceId(_))
        ));
        assert!(matches!(
            GraphConfidenceSource::new(" ", None, GraphConfidenceBasis::Inferred),
            Err(GraphContractError::BlankConfidenceProducer)
        ));
    }
}
