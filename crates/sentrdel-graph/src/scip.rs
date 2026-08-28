use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use sentrdel_schema::coverage::{CoverageRecord, CoverageState};

use crate::{
    GraphConfidenceBasis, GraphConfidenceSource, GraphContractError, GraphEdge, GraphNode,
    GraphNodeKind, GraphProvenanceId, GraphRelation,
};

pub const SCIP_REFERENCE_CAPABILITY: &str = "graph.scip.references";
pub const MAX_SCIP_DOCUMENTS: usize = 100_000;
pub const MAX_SCIP_OCCURRENCES: usize = 1_000_000;
pub const MAX_SCIP_PATH_BYTES: usize = 4_096;
pub const MAX_SCIP_SYMBOL_BYTES: usize = 16_384;

/// Trusted qualification assigned outside the untrusted SCIP artifact.
///
/// This value MUST NOT be inferred from `ToolInfo.name`, command-line arguments,
/// repository content, or an indexer's self-description. The qualification ID
/// is persisted as graph provenance so downstream consumers can distinguish the
/// artifact from the authority that classified its semantic precision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScipProducerQualification {
    /// A qualified compiler/language-server-backed producer whose emitted
    /// definition/reference facts may be represented as extracted graph data.
    CompilerBacked { qualification_id: String },
    /// A qualified syntax/heuristic producer. Its graph relations remain
    /// explicitly inferred and never gain compiler-level semantic certainty.
    Heuristic { qualification_id: String },
}

impl ScipProducerQualification {
    fn qualification_id(&self) -> &str {
        match self {
            Self::CompilerBacked { qualification_id }
            | Self::Heuristic { qualification_id } => qualification_id,
        }
    }

    fn basis(&self) -> GraphConfidenceBasis {
        match self {
            Self::CompilerBacked { .. } => GraphConfidenceBasis::Extracted,
            Self::Heuristic { .. } => GraphConfidenceBasis::Inferred,
        }
    }

    fn is_heuristic(&self) -> bool {
        matches!(self, Self::Heuristic { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScipOccurrenceRole {
    Definition,
    Reference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScipPosition {
    pub line: u32,
    pub character: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScipRange {
    pub start: ScipPosition,
    pub end: ScipPosition,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScipOccurrence {
    /// Canonical SCIP symbol string supplied by the adapter.
    pub symbol: String,
    pub range: ScipRange,
    pub role: ScipOccurrenceRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScipDocument {
    /// SCIP document path relative to the index project root.
    pub relative_path: String,
    pub language: String,
    pub occurrences: Vec<ScipOccurrence>,
}

/// Adapter-normalized view of a SCIP index artifact.
///
/// T034 intentionally does not select or embed a protobuf decoder or language
/// indexer. A separately qualified adapter may decode a bounded SCIP payload
/// into this structure, after which this module owns validation and graph
/// ingestion. The digest is over the original artifact bytes, not this Rust
/// structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScipArtifact {
    pub artifact_digest: String,
    pub producer_name: String,
    pub producer_version: Option<String>,
    pub documents: Vec<ScipDocument>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScipIngestionRequest {
    pub artifact: ScipArtifact,
    pub producer_qualification: ScipProducerQualification,
    pub scope: String,
    /// Caller-supplied observation time. Ingestion is otherwise deterministic
    /// and performs no clock access.
    pub observed_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScipIngestionResult {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub coverage: CoverageRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScipCoverageGap {
    Unsupported,
    Unavailable,
    Failed,
    TimedOut,
    SkippedByPolicy,
}

impl ScipCoverageGap {
    fn state(self) -> CoverageState {
        match self {
            Self::Unsupported => CoverageState::Unsupported,
            Self::Unavailable => CoverageState::Unavailable,
            Self::Failed => CoverageState::Failed,
            Self::TimedOut => CoverageState::TimedOut,
            Self::SkippedByPolicy => CoverageState::SkippedByPolicy,
        }
    }

    fn reason_code(self) -> &'static str {
        match self {
            Self::Unsupported => "SCIP_INDEXER_UNSUPPORTED",
            Self::Unavailable => "SCIP_ARTIFACT_UNAVAILABLE",
            Self::Failed => "SCIP_INDEXER_FAILED",
            Self::TimedOut => "SCIP_INDEXER_TIMED_OUT",
            Self::SkippedByPolicy => "SCIP_SKIPPED_BY_POLICY",
        }
    }
}

/// Build an explicit graph-semantic coverage gap without requiring or running
/// any language indexer.
pub fn scip_coverage_gap(
    scope: impl Into<String>,
    observed_at: impl Into<String>,
    producer: Option<String>,
    gap: ScipCoverageGap,
) -> Result<CoverageRecord, ScipIngestionError> {
    let scope = scope.into();
    let observed_at = observed_at.into();
    validate_scope_and_time(&scope, &observed_at)?;
    if producer.as_deref().is_some_and(|value| value.trim().is_empty()) {
        return Err(ScipIngestionError::BlankProducerName);
    }

    Ok(CoverageRecord {
        schema_version: sentrdel_schema::SCHEMA_V1.to_owned(),
        coverage_id: format!("coverage:scip-references:{scope}"),
        capability: SCIP_REFERENCE_CAPABILITY.to_owned(),
        scope,
        producer,
        provider_dimension: None,
        state: gap.state(),
        reason_code: Some(gap.reason_code().to_owned()),
        details: Some(
            "SCIP semantic coverage is a gap; absence or failure of an optional indexer is not a clean security result"
                .to_owned(),
        ),
        input_digests: Vec::new(),
        observed_at,
    })
}

/// Ingest a validated, adapter-normalized SCIP artifact into the thin Sentrdel
/// graph.
///
/// The function performs no filesystem reads, subprocess execution, network
/// access, index generation, or protobuf decoding. Producer qualification is a
/// trusted caller input and is never inferred from artifact-controlled text.
pub fn ingest_scip(
    request: ScipIngestionRequest,
) -> Result<ScipIngestionResult, ScipIngestionError> {
    validate_request(&request)?;

    let ScipIngestionRequest {
        artifact,
        producer_qualification,
        scope,
        observed_at,
    } = request;

    let qualification_id = producer_qualification.qualification_id().to_owned();
    let basis = producer_qualification.basis();
    let is_heuristic = producer_qualification.is_heuristic();
    let confidence = GraphConfidenceSource::new(
        artifact.producer_name.clone(),
        artifact.producer_version.clone(),
        basis,
    )?;
    let provenance_ids = vec![
        GraphProvenanceId::new(format!("scip:{}", artifact.artifact_digest))?,
        GraphProvenanceId::new(format!("source-qualification:{qualification_id}"))?,
    ];

    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();

    for document in artifact.documents {
        let file = GraphNode::new(
            GraphNodeKind::File,
            format!("scip-file:{}", document.relative_path),
            BTreeMap::new(),
            provenance_ids.clone(),
        )?;
        nodes.insert(file.node_id.clone(), file);

        let mut sorted_occurrences = document.occurrences;
        sorted_occurrences.sort();
        sorted_occurrences.dedup();

        for occurrence in sorted_occurrences {
            let symbol_key = symbol_semantic_key(&document.relative_path, &occurrence.symbol);
            let symbol = GraphNode::new(
                GraphNodeKind::Symbol,
                symbol_key,
                BTreeMap::new(),
                provenance_ids.clone(),
            )?;
            let symbol_id = symbol.node_id.clone();
            nodes.entry(symbol_id.clone()).or_insert(symbol);

            if occurrence.role == ScipOccurrenceRole::Definition {
                continue;
            }

            let reference = GraphNode::new(
                GraphNodeKind::Reference,
                reference_semantic_key(
                    &document.relative_path,
                    &occurrence.symbol,
                    occurrence.range,
                ),
                BTreeMap::new(),
                provenance_ids.clone(),
            )?;
            let reference_id = reference.node_id.clone();
            nodes.entry(reference_id.clone()).or_insert(reference);

            let edge = GraphEdge::new(
                reference_id,
                symbol_id,
                GraphRelation::Refs,
                confidence.clone(),
                provenance_ids.clone(),
                BTreeMap::new(),
            )?;
            edges.entry(edge.edge_id.clone()).or_insert(edge);
        }
    }

    let is_empty = nodes.is_empty();
    let state = if is_empty || is_heuristic {
        CoverageState::Partial
    } else {
        CoverageState::Covered
    };
    let reason_code = if is_empty {
        Some("SCIP_EMPTY_INDEX".to_owned())
    } else if is_heuristic {
        Some("SCIP_HEURISTIC_PRODUCER".to_owned())
    } else {
        None
    };
    let details = if is_heuristic {
        format!(
            "SCIP reference graph ingested under qualification {qualification_id}; producer is heuristic, relations remain INFERRED, and graph-semantic coverage is PARTIAL"
        )
    } else {
        format!(
            "SCIP reference graph ingested under qualification {qualification_id}; producer is separately qualified as compiler/language-server-backed and coverage applies only to the declared artifact scope"
        )
    };

    let producer = match artifact.producer_version.as_deref() {
        Some(version) => format!("{}@{version}", artifact.producer_name),
        None => artifact.producer_name,
    };

    Ok(ScipIngestionResult {
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
        coverage: CoverageRecord {
            schema_version: sentrdel_schema::SCHEMA_V1.to_owned(),
            coverage_id: format!("coverage:scip-references:{}", artifact.artifact_digest),
            capability: SCIP_REFERENCE_CAPABILITY.to_owned(),
            scope,
            producer: Some(producer),
            provider_dimension: None,
            state,
            reason_code,
            details: Some(details),
            input_digests: vec![artifact.artifact_digest],
            observed_at,
        },
    })
}

#[derive(Debug)]
pub enum ScipIngestionError {
    BlankScope,
    BlankObservedAt,
    InvalidArtifactDigest(String),
    BlankProducerName,
    BlankProducerVersion,
    BlankQualificationId,
    TooManyDocuments {
        actual: usize,
        maximum: usize,
    },
    TooManyOccurrences {
        actual: usize,
        maximum: usize,
    },
    InvalidDocumentPath(String),
    DuplicateDocumentPath(String),
    BlankLanguage(String),
    InvalidSymbol(String),
    InvalidRange {
        path: String,
        range: ScipRange,
    },
    Graph(GraphContractError),
}

impl fmt::Display for ScipIngestionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankScope => formatter.write_str("SCIP ingestion scope must not be blank"),
            Self::BlankObservedAt => {
                formatter.write_str("SCIP ingestion observed_at must not be blank")
            }
            Self::InvalidArtifactDigest(digest) => write!(
                formatter,
                "SCIP artifact digest must use sha256:<64 lowercase hex> form: {digest:?}"
            ),
            Self::BlankProducerName => {
                formatter.write_str("SCIP producer name must not be blank")
            }
            Self::BlankProducerVersion => {
                formatter.write_str("SCIP producer version must not be blank when present")
            }
            Self::BlankQualificationId => {
                formatter.write_str("SCIP producer qualification id must not be blank")
            }
            Self::TooManyDocuments { actual, maximum } => write!(
                formatter,
                "SCIP artifact contains {actual} documents, exceeding maximum {maximum}"
            ),
            Self::TooManyOccurrences { actual, maximum } => write!(
                formatter,
                "SCIP artifact contains {actual} occurrences, exceeding maximum {maximum}"
            ),
            Self::InvalidDocumentPath(path) => {
                write!(formatter, "invalid canonical SCIP relative path: {path:?}")
            }
            Self::DuplicateDocumentPath(path) => {
                write!(formatter, "duplicate SCIP document path: {path:?}")
            }
            Self::BlankLanguage(path) => {
                write!(formatter, "SCIP document language is blank for {path:?}")
            }
            Self::InvalidSymbol(symbol) => {
                write!(formatter, "invalid SCIP symbol string: {symbol:?}")
            }
            Self::InvalidRange { path, range } => {
                write!(formatter, "invalid SCIP occurrence range {range:?} in {path:?}")
            }
            Self::Graph(error) => write!(formatter, "SCIP graph mapping failed: {error}"),
        }
    }
}

impl Error for ScipIngestionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Graph(error) => Some(error),
            Self::BlankScope
            | Self::BlankObservedAt
            | Self::InvalidArtifactDigest(_)
            | Self::BlankProducerName
            | Self::BlankProducerVersion
            | Self::BlankQualificationId
            | Self::TooManyDocuments { .. }
            | Self::TooManyOccurrences { .. }
            | Self::InvalidDocumentPath(_)
            | Self::DuplicateDocumentPath(_)
            | Self::BlankLanguage(_)
            | Self::InvalidSymbol(_)
            | Self::InvalidRange { .. } => None,
        }
    }
}

impl From<GraphContractError> for ScipIngestionError {
    fn from(error: GraphContractError) -> Self {
        Self::Graph(error)
    }
}

fn validate_scope_and_time(scope: &str, observed_at: &str) -> Result<(), ScipIngestionError> {
    if scope.trim().is_empty() {
        return Err(ScipIngestionError::BlankScope);
    }
    if observed_at.trim().is_empty() {
        return Err(ScipIngestionError::BlankObservedAt);
    }
    Ok(())
}

fn validate_request(request: &ScipIngestionRequest) -> Result<(), ScipIngestionError> {
    validate_scope_and_time(&request.scope, &request.observed_at)?;
    if !is_canonical_sha256_id(&request.artifact.artifact_digest) {
        return Err(ScipIngestionError::InvalidArtifactDigest(
            request.artifact.artifact_digest.clone(),
        ));
    }
    if request.artifact.producer_name.trim().is_empty() {
        return Err(ScipIngestionError::BlankProducerName);
    }
    if request
        .artifact
        .producer_version
        .as_deref()
        .is_some_and(|version| version.trim().is_empty())
    {
        return Err(ScipIngestionError::BlankProducerVersion);
    }
    if request.producer_qualification.qualification_id().trim().is_empty() {
        return Err(ScipIngestionError::BlankQualificationId);
    }
    if request.artifact.documents.len() > MAX_SCIP_DOCUMENTS {
        return Err(ScipIngestionError::TooManyDocuments {
            actual: request.artifact.documents.len(),
            maximum: MAX_SCIP_DOCUMENTS,
        });
    }

    let mut total_occurrences = 0usize;
    let mut seen_paths = BTreeSet::new();
    for document in &request.artifact.documents {
        validate_document_path(&document.relative_path)?;
        if !seen_paths.insert(document.relative_path.as_str()) {
            return Err(ScipIngestionError::DuplicateDocumentPath(
                document.relative_path.clone(),
            ));
        }
        if document.language.trim().is_empty() {
            return Err(ScipIngestionError::BlankLanguage(
                document.relative_path.clone(),
            ));
        }
        total_occurrences = total_occurrences
            .checked_add(document.occurrences.len())
            .ok_or(ScipIngestionError::TooManyOccurrences {
                actual: usize::MAX,
                maximum: MAX_SCIP_OCCURRENCES,
            })?;
        if total_occurrences > MAX_SCIP_OCCURRENCES {
            return Err(ScipIngestionError::TooManyOccurrences {
                actual: total_occurrences,
                maximum: MAX_SCIP_OCCURRENCES,
            });
        }

        for occurrence in &document.occurrences {
            validate_symbol(&occurrence.symbol)?;
            if occurrence.range.end < occurrence.range.start {
                return Err(ScipIngestionError::InvalidRange {
                    path: document.relative_path.clone(),
                    range: occurrence.range,
                });
            }
        }
    }

    Ok(())
}

fn validate_document_path(path: &str) -> Result<(), ScipIngestionError> {
    let invalid = path.is_empty()
        || path.len() > MAX_SCIP_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains('\0')
        || path.as_bytes().get(1) == Some(&b':')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..");
    if invalid {
        return Err(ScipIngestionError::InvalidDocumentPath(path.to_owned()));
    }
    Ok(())
}

fn validate_symbol(symbol: &str) -> Result<(), ScipIngestionError> {
    if symbol.trim().is_empty()
        || symbol.len() > MAX_SCIP_SYMBOL_BYTES
        || symbol.contains('\0')
        || symbol == "local"
    {
        return Err(ScipIngestionError::InvalidSymbol(symbol.to_owned()));
    }
    Ok(())
}

fn symbol_semantic_key(relative_path: &str, symbol: &str) -> String {
    if symbol.starts_with("local ") {
        format!("scip-local:{relative_path}:{symbol}")
    } else {
        format!("scip-symbol:{symbol}")
    }
}

fn reference_semantic_key(relative_path: &str, symbol: &str, range: ScipRange) -> String {
    format!(
        "scip-ref:{relative_path}:{}:{}-{}:{}:{symbol}",
        range.start.line, range.start.character, range.end.line, range.end.character
    )
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

    fn digest() -> String {
        format!("sha256:{}", "a".repeat(64))
    }

    fn compiler_qualification() -> ScipProducerQualification {
        ScipProducerQualification::CompilerBacked {
            qualification_id: "SCIPQ-fixture-compiler".to_owned(),
        }
    }

    fn heuristic_qualification() -> ScipProducerQualification {
        ScipProducerQualification::Heuristic {
            qualification_id: "SCIPQ-fixture-heuristic".to_owned(),
        }
    }

    fn occurrence(symbol: &str, role: ScipOccurrenceRole, line: u32) -> ScipOccurrence {
        ScipOccurrence {
            symbol: symbol.to_owned(),
            range: ScipRange {
                start: ScipPosition { line, character: 1 },
                end: ScipPosition { line, character: 5 },
            },
            role,
        }
    }

    fn request(qualification: ScipProducerQualification) -> ScipIngestionRequest {
        ScipIngestionRequest {
            artifact: ScipArtifact {
                artifact_digest: digest(),
                producer_name: "fixture-scip".to_owned(),
                producer_version: Some("1.2.3".to_owned()),
                documents: vec![ScipDocument {
                    relative_path: "src/lib.rs".to_owned(),
                    language: "rust".to_owned(),
                    occurrences: vec![
                        occurrence(
                            "rust cargo fixture 1.0.0 crate/source#",
                            ScipOccurrenceRole::Definition,
                            1,
                        ),
                        occurrence(
                            "rust cargo fixture 1.0.0 crate/source#",
                            ScipOccurrenceRole::Reference,
                            4,
                        ),
                    ],
                }],
            },
            producer_qualification: qualification,
            scope: ".".to_owned(),
            observed_at: "2026-08-28T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn compiler_backed_ingestion_requires_and_preserves_qualification_provenance() {
        let result = ingest_scip(request(compiler_qualification())).expect("SCIP ingestion");

        assert_eq!(result.coverage.state, CoverageState::Covered);
        assert_eq!(result.coverage.input_digests, vec![digest()]);
        assert_eq!(result.edges.len(), 1);
        assert_eq!(
            result.edges[0].confidence_source.basis,
            GraphConfidenceBasis::Extracted
        );
        assert_eq!(result.edges[0].relation, GraphRelation::Refs);
        assert!(result.edges[0]
            .provenance_ids
            .iter()
            .any(|id| id.as_str() == "source-qualification:SCIPQ-fixture-compiler"));
    }

    #[test]
    fn blank_qualification_cannot_mint_extracted_semantics() {
        let mut value = request(ScipProducerQualification::CompilerBacked {
            qualification_id: "   ".to_owned(),
        });
        value.artifact.producer_name = "self-described-compiler".to_owned();
        assert!(matches!(
            ingest_scip(value),
            Err(ScipIngestionError::BlankQualificationId)
        ));
    }

    #[test]
    fn heuristic_ingestion_never_claims_compiler_semantic_certainty() {
        let result = ingest_scip(request(heuristic_qualification())).expect("SCIP ingestion");

        assert_eq!(result.coverage.state, CoverageState::Partial);
        assert_eq!(
            result.coverage.reason_code.as_deref(),
            Some("SCIP_HEURISTIC_PRODUCER")
        );
        assert!(result
            .edges
            .iter()
            .all(|edge| edge.confidence_source.basis == GraphConfidenceBasis::Inferred));
    }

    #[test]
    fn local_symbol_identity_is_document_scoped() {
        let mut value = request(compiler_qualification());
        value.artifact.documents = vec![
            ScipDocument {
                relative_path: "src/a.rs".to_owned(),
                language: "rust".to_owned(),
                occurrences: vec![occurrence(
                    "local 0",
                    ScipOccurrenceRole::Definition,
                    1,
                )],
            },
            ScipDocument {
                relative_path: "src/b.rs".to_owned(),
                language: "rust".to_owned(),
                occurrences: vec![occurrence(
                    "local 0",
                    ScipOccurrenceRole::Definition,
                    1,
                )],
            },
        ];

        let result = ingest_scip(value).expect("SCIP ingestion");
        let local_symbols = result
            .nodes
            .iter()
            .filter(|node| node.node_kind == GraphNodeKind::Symbol)
            .collect::<Vec<_>>();
        assert_eq!(local_symbols.len(), 2);
        assert_ne!(local_symbols[0].node_id, local_symbols[1].node_id);
    }

    #[test]
    fn duplicate_occurrences_do_not_change_output() {
        let baseline = ingest_scip(request(compiler_qualification())).expect("baseline");
        let mut duplicated = request(compiler_qualification());
        let duplicate = duplicated.artifact.documents[0].occurrences[1].clone();
        duplicated.artifact.documents[0]
            .occurrences
            .push(duplicate);
        let repeated = ingest_scip(duplicated).expect("repeated");

        assert_eq!(baseline.nodes, repeated.nodes);
        assert_eq!(baseline.edges, repeated.edges);
        assert_eq!(baseline.coverage, repeated.coverage);
    }

    #[test]
    fn canonical_path_rules_fail_closed_without_filesystem_access() {
        for path in [
            "/etc/passwd",
            "../src/lib.rs",
            "src//lib.rs",
            "src/./lib.rs",
            "C:/repo/src/lib.rs",
            "src\\lib.rs",
        ] {
            let mut value = request(compiler_qualification());
            value.artifact.documents[0].relative_path = path.to_owned();
            assert!(matches!(
                ingest_scip(value),
                Err(ScipIngestionError::InvalidDocumentPath(_))
            ));
        }
    }

    #[test]
    fn invalid_digest_and_range_fail_closed() {
        let mut bad_digest = request(compiler_qualification());
        bad_digest.artifact.artifact_digest = "sha256:not-a-digest".to_owned();
        assert!(matches!(
            ingest_scip(bad_digest),
            Err(ScipIngestionError::InvalidArtifactDigest(_))
        ));

        let mut bad_range = request(compiler_qualification());
        bad_range.artifact.documents[0].occurrences[0].range = ScipRange {
            start: ScipPosition {
                line: 10,
                character: 0,
            },
            end: ScipPosition {
                line: 9,
                character: 99,
            },
        };
        assert!(matches!(
            ingest_scip(bad_range),
            Err(ScipIngestionError::InvalidRange { .. })
        ));
    }

    #[test]
    fn missing_optional_indexer_is_explicit_coverage_gap() {
        let coverage = scip_coverage_gap(
            ".",
            "2026-08-28T00:00:00Z",
            None,
            ScipCoverageGap::Unavailable,
        )
        .expect("coverage gap");
        assert_eq!(coverage.state, CoverageState::Unavailable);
        assert!(coverage.is_gap());
        assert_eq!(
            coverage.reason_code.as_deref(),
            Some("SCIP_ARTIFACT_UNAVAILABLE")
        );
    }

    #[test]
    fn empty_index_is_partial_not_clean_semantic_coverage() {
        let mut value = request(compiler_qualification());
        value.artifact.documents.clear();
        let result = ingest_scip(value).expect("empty SCIP artifact is representable");
        assert_eq!(result.coverage.state, CoverageState::Partial);
        assert_eq!(
            result.coverage.reason_code.as_deref(),
            Some("SCIP_EMPTY_INDEX")
        );
        assert!(result.nodes.is_empty());
        assert!(result.edges.is_empty());
    }
}