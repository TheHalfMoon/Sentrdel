//! Trusted R3-T016 bridge from canonical SCIP ingestion into the internal link IR.
//!
//! This module accepts only the opaque result returned by `sentrdel-graph::ingest_scip` for an
//! admitted semantic artifact. It never selects or qualifies a producer, executes an indexer,
//! reads target repository files, performs network access, creates Findings, or treats missing or
//! ambiguous semantic coverage as clean.

use std::{collections::BTreeMap, error::Error, fmt};

use sentrdel_graph::{
    GraphConfidenceBasis, GraphContractError, GraphRelation, SCIP_REFERENCE_CAPABILITY,
    ScipIngestionResult, validate_edge,
};
use sentrdel_review::business_logic::{
    link::MAX_INTER_FILE_LINKS,
    model::{
        BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, LinkBasis, ModelError,
        SourceLocation, StableSemanticId,
    },
};
use sentrdel_schema::coverage::CoverageState;

pub const MAX_SCIP_REFERENCES: usize = 8_192;
pub const SCIP_LINK_RELATION: &str = "semantic_reference";
pub const R3_SCIP_BRIDGE_EXECUTES_TARGET_CODE: bool = false;
pub const R3_SCIP_BRIDGE_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_SCIP_BRIDGE_QUALIFIES_PRODUCERS: bool = false;
pub const R3_SCIP_BRIDGE_CREATES_FINDINGS: bool = false;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScipSemanticInput {
    Unavailable,
    Ambiguous {
        provenance: Vec<SourceLocation>,
    },
    Admitted {
        ingestion: Box<ScipIngestionResult>,
        provenance: Vec<SourceLocation>,
        complete: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScipLinkingDiagnosticReason {
    ScipUnavailable,
    ScipAmbiguous,
    ScipIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipLinkingDiagnostic {
    reason: ScipLinkingDiagnosticReason,
    provenance: Vec<SourceLocation>,
}

impl ScipLinkingDiagnostic {
    #[must_use]
    pub const fn reason(&self) -> ScipLinkingDiagnosticReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipLinkingResult {
    links: Vec<CrossLayerLink>,
    semantic_state: CoverageState,
    diagnostics: Vec<ScipLinkingDiagnostic>,
}

impl ScipLinkingResult {
    #[must_use]
    pub fn links(&self) -> &[CrossLayerLink] {
        &self.links
    }

    #[must_use]
    pub fn semantic_state(&self) -> &CoverageState {
        &self.semantic_state
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[ScipLinkingDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Debug)]
pub enum ScipLinkingError {
    InvalidLimits,
    InvalidIngestion,
    MissingProvenance,
    TooManyProvenance { count: usize, max: usize },
    TooManyReferences { count: usize, max: usize },
    TooManyLinks { count: usize, max: usize },
    Graph(GraphContractError),
    Model(ModelError),
}

impl fmt::Display for ScipLinkingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("R3 SCIP linking limits must be non-zero"),
            Self::InvalidIngestion => formatter.write_str(
                "R3 SCIP linking requires canonical graph ingestion provenance and coverage",
            ),
            Self::MissingProvenance => {
                formatter.write_str("R3 SCIP linking requires explicit source provenance")
            }
            Self::TooManyProvenance { count, max } => {
                write!(
                    formatter,
                    "R3 SCIP provenance count {count} exceeds cap {max}"
                )
            }
            Self::TooManyReferences { count, max } => {
                write!(
                    formatter,
                    "R3 SCIP reference count {count} exceeds cap {max}"
                )
            }
            Self::TooManyLinks { count, max } => {
                write!(formatter, "R3 SCIP link count {count} exceeds cap {max}")
            }
            Self::Graph(source) => write!(formatter, "R3 SCIP graph validation failed: {source}"),
            Self::Model(source) => write!(formatter, "R3 SCIP model validation failed: {source}"),
        }
    }
}

impl Error for ScipLinkingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Graph(source) => Some(source),
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<GraphContractError> for ScipLinkingError {
    fn from(value: GraphContractError) -> Self {
        Self::Graph(value)
    }
}

impl From<ModelError> for ScipLinkingError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn link_scip_semantics(
    input: ScipSemanticInput,
    limits: BusinessLogicLimits,
) -> Result<ScipLinkingResult, ScipLinkingError> {
    let limits = limits.validate().map_err(|error| match error {
        ModelError::InvalidLimits => ScipLinkingError::InvalidLimits,
        other => ScipLinkingError::Model(other),
    })?;

    match input {
        ScipSemanticInput::Unavailable => Ok(ScipLinkingResult {
            links: Vec::new(),
            semantic_state: CoverageState::Unavailable,
            diagnostics: vec![ScipLinkingDiagnostic {
                reason: ScipLinkingDiagnosticReason::ScipUnavailable,
                provenance: Vec::new(),
            }],
        }),
        ScipSemanticInput::Ambiguous { mut provenance } => {
            normalize_optional_provenance(&mut provenance, limits)?;
            Ok(ScipLinkingResult {
                links: Vec::new(),
                semantic_state: CoverageState::Partial,
                diagnostics: vec![ScipLinkingDiagnostic {
                    reason: ScipLinkingDiagnosticReason::ScipAmbiguous,
                    provenance,
                }],
            })
        }
        ScipSemanticInput::Admitted {
            ingestion,
            mut provenance,
            complete,
        } => {
            if provenance.is_empty() {
                return Err(ScipLinkingError::MissingProvenance);
            }
            normalize_optional_provenance(&mut provenance, limits)?;

            let coverage = ingestion.coverage();
            if coverage.capability != SCIP_REFERENCE_CAPABILITY || coverage.input_digests.len() != 1
            {
                return Err(ScipLinkingError::InvalidIngestion);
            }
            let artifact_digest = &coverage.input_digests[0];
            if !is_canonical_sha256(artifact_digest) {
                return Err(ScipLinkingError::InvalidIngestion);
            }
            let scip_provenance_id = format!("scip:{artifact_digest}");
            let edges = ingestion.edges();
            let reference_cap = MAX_SCIP_REFERENCES.min(limits.max_path_candidates);
            if edges.len() > reference_cap {
                return Err(ScipLinkingError::TooManyReferences {
                    count: edges.len(),
                    max: reference_cap,
                });
            }

            let max_links = MAX_INTER_FILE_LINKS.min(limits.max_path_candidates);
            let mut links = BTreeMap::<String, CrossLayerLink>::new();
            let mut incomplete =
                !complete || edges.is_empty() || coverage.state != CoverageState::Covered;

            for edge in edges {
                validate_edge(edge)?;
                if edge.relation != GraphRelation::Refs
                    || !edge
                        .provenance_ids
                        .iter()
                        .any(|id| id.as_str() == scip_provenance_id)
                    || !edge.provenance_ids.iter().any(|id| {
                        id.as_str()
                            .strip_prefix("source-qualification:")
                            .is_some_and(valid_qualification_id)
                    })
                {
                    return Err(ScipLinkingError::InvalidIngestion);
                }

                let confidence_basis = match edge.confidence_source.basis {
                    GraphConfidenceBasis::Extracted => ConfidenceBasis::Extracted,
                    GraphConfidenceBasis::Inferred => {
                        incomplete = true;
                        ConfidenceBasis::Inferred
                    }
                    GraphConfidenceBasis::Ambiguous => {
                        incomplete = true;
                        ConfidenceBasis::Ambiguous
                    }
                };
                let source_id =
                    StableSemanticId::from_parts("r3-scip-node", &[edge.source.as_str()], limits)?;
                let target_id =
                    StableSemanticId::from_parts("r3-scip-node", &[edge.target.as_str()], limits)?;
                let link = CrossLayerLink::new(
                    StableSemanticId::from_parts(
                        "r3-scip-link",
                        &[
                            edge.edge_id.as_str(),
                            &coverage.coverage_id,
                            artifact_digest,
                        ],
                        limits,
                    )?,
                    source_id,
                    target_id,
                    SCIP_LINK_RELATION,
                    LinkBasis::ScipReference,
                    confidence_basis,
                    provenance.clone(),
                    limits,
                )?;
                let key = link.link_id().as_str().to_owned();
                if !links.contains_key(&key) && links.len() >= max_links {
                    return Err(ScipLinkingError::TooManyLinks {
                        count: links.len().saturating_add(1),
                        max: max_links,
                    });
                }
                links.insert(key, link);
            }

            let mut links = links.into_values().collect::<Vec<_>>();
            links.sort();
            let diagnostics = if incomplete {
                vec![ScipLinkingDiagnostic {
                    reason: ScipLinkingDiagnosticReason::ScipIncomplete,
                    provenance,
                }]
            } else {
                Vec::new()
            };

            Ok(ScipLinkingResult {
                links,
                semantic_state: if incomplete {
                    CoverageState::Partial
                } else {
                    CoverageState::Covered
                },
                diagnostics,
            })
        }
    }
}

fn normalize_optional_provenance(
    provenance: &mut Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<(), ScipLinkingError> {
    if provenance.len() > limits.max_provenance_per_record {
        return Err(ScipLinkingError::TooManyProvenance {
            count: provenance.len(),
            max: limits.max_provenance_per_record,
        });
    }
    provenance.sort();
    provenance.dedup();
    Ok(())
}

fn is_canonical_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_qualification_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= sentrdel_graph::MAX_SCIP_METADATA_BYTES
        && !value.chars().any(char::is_control)
}
