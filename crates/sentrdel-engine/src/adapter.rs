//! T028 strict adaptation of bounded external-engine output into canonical Evidence.
//!
//! External bytes never select producer identity, input provenance, capture time,
//! executable authority, Findings, or coverage. The trusted caller supplies an
//! `EvidenceAuthority`, trusted input digests, canonical capture time, and T027
//! `EngineLimits`. A streaming structural preflight rejects JSON amplification
//! before serde materializes untrusted collections.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs, io,
    path::{Component, Path},
};

use sentrdel_schema::{
    SCHEMA_V1,
    engine::{EngineManifest, TerminationReason},
    evidence::{
        ConfidenceBand, EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim,
        EvidenceLocation, EvidenceSubject, EvidenceValidationError, ProducerKind,
        ReproductionMetadata,
    },
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    EngineLimits, EngineProcessOutcome,
    bounded_json::{
        BoundedJsonDialect, BoundedJsonError, MAX_ATTRIBUTE_VALUE_BYTES, MAX_ATTRIBUTE_VALUE_DEPTH,
        MAX_ATTRIBUTE_VALUE_NODES, preflight_json,
    },
};

pub const SENTRDEL_JSON_V1_DIALECT: &str = "sentrdel-json-v1";
pub const SARIF_V2_1_0_DIALECT: &str = "sarif-v2.1.0";
pub const MAX_ENGINE_ADAPTER_JSON_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENGINE_ADAPTER_ITEMS: usize = 4_096;
pub const MAX_ENGINE_ADAPTER_RUNS: usize = 64;
pub const MAX_ENGINE_LOCATIONS_PER_ITEM: usize = 64;
pub const MAX_ENGINE_SUBJECTS_PER_ITEM: usize = 64;
pub const MAX_ENGINE_ATTRIBUTES_PER_ITEM: usize = 256;
pub const MAX_ENGINE_LOCATION_BYTES: usize = 4_096;
pub const MAX_ENGINE_IDENTIFIER_BYTES: usize = 4_096;
pub const MAX_ENGINE_RESULT_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineOutputDialect {
    SentrdelJsonV1,
    SarifV2_1_0,
}

impl EngineOutputDialect {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SentrdelJsonV1 => SENTRDEL_JSON_V1_DIALECT,
            Self::SarifV2_1_0 => SARIF_V2_1_0_DIALECT,
        }
    }
}

impl TryFrom<&str> for EngineOutputDialect {
    type Error = EngineAdapterError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            SENTRDEL_JSON_V1_DIALECT => Ok(Self::SentrdelJsonV1),
            SARIF_V2_1_0_DIALECT => Ok(Self::SarifV2_1_0),
            other => Err(EngineAdapterError::UnsupportedDialect(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoLocationError {
    Empty,
    TooLong { bytes: usize, max: usize },
    Padded,
    ControlCharacter,
    InvalidPercentEncoding,
    InvalidUtf8Encoding,
    UriQueryOrFragment,
    AbsoluteOrScheme,
    ParentTraversal,
    EmptyComponent,
    OutsideWorkspace,
    InvalidRange,
    InvalidSymbol,
    UnverifiedContentDigest,
    Filesystem(io::ErrorKind),
}

impl fmt::Display for RepoLocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("engine result location is empty"),
            Self::TooLong { bytes, max } => {
                write!(formatter, "engine result location length {bytes} exceeds cap {max}")
            }
            Self::Padded => formatter.write_str(
                "engine result location must be normalized without surrounding whitespace",
            ),
            Self::ControlCharacter => {
                formatter.write_str("engine result location contains a control character")
            }
            Self::InvalidPercentEncoding => {
                formatter.write_str("engine result location contains invalid percent encoding")
            }
            Self::InvalidUtf8Encoding => {
                formatter.write_str("engine result location percent-decodes to invalid UTF-8")
            }
            Self::UriQueryOrFragment => {
                formatter.write_str("engine result location may not contain a URI query or fragment")
            }
            Self::AbsoluteOrScheme => formatter.write_str(
                "engine result location must be repository-relative without a URI scheme or drive prefix",
            ),
            Self::ParentTraversal => {
                formatter.write_str("engine result location may not contain parent traversal")
            }
            Self::EmptyComponent => {
                formatter.write_str("engine result location may not contain empty path components")
            }
            Self::OutsideWorkspace => {
                formatter.write_str("engine result location resolves outside the approved workspace")
            }
            Self::InvalidRange => formatter.write_str(
                "engine result location contains an invalid one-based line/column range",
            ),
            Self::InvalidSymbol => formatter.write_str(
                "engine result location symbol must be bounded and free of unsupported controls",
            ),
            Self::UnverifiedContentDigest => formatter.write_str(
                "external engine location content digest is unverified and cannot enter canonical Evidence",
            ),
            Self::Filesystem(kind) => write!(
                formatter,
                "engine result location filesystem validation failed: {kind:?}"
            ),
        }
    }
}

impl Error for RepoLocationError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineAdapterError {
    UnsupportedDialect(String),
    UndeclaredDialect(String),
    DuplicateDialectDeclaration(String),
    ProcessNotCompleted(TerminationReason),
    RawOutputTooLarge { bytes: usize, max: usize },
    InvalidAuthority,
    AuthorityManifestMismatch,
    InvalidTrustedCaptureTime,
    MalformedJson,
    InvalidNativeEnvelope,
    UnsupportedNativeSchemaVersion(String),
    UnsupportedSarifVersion(String),
    TooManyRuns { count: usize, max: usize },
    TooManyItems { count: usize, max: usize },
    TooManyLocations { count: usize, max: usize },
    TooManySubjects { count: usize, max: usize },
    TooManyAttributes { count: usize, max: usize },
    JsonNestingTooDeep { depth: usize, max: usize },
    JsonStructureTooComplex { nodes: usize, max: usize },
    AttributeValueTooLarge { bytes: usize, max: usize },
    AttributeValueTooDeep { depth: usize, max: usize },
    AttributeValueTooComplex { nodes: usize, max: usize },
    InvalidIdentifier,
    InvalidResultText,
    ResultTextTooLarge { bytes: usize, max: usize },
    MissingSarifRuleId,
    MissingSarifMessage,
    UnsupportedSarifUriBase,
    UnsupportedSarifLocation,
    Location(RepoLocationError),
    Evidence(EvidenceValidationError),
}

impl fmt::Display for EngineAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDialect(dialect) => {
                write!(formatter, "unsupported engine output dialect: {dialect:?}")
            }
            Self::UndeclaredDialect(dialect) => write!(
                formatter,
                "engine output dialect was not declared by manifest: {dialect:?}"
            ),
            Self::DuplicateDialectDeclaration(dialect) => write!(
                formatter,
                "engine manifest declares output dialect more than once: {dialect:?}"
            ),
            Self::ProcessNotCompleted(reason) => write!(
                formatter,
                "engine output cannot be adapted from non-completed termination: {reason:?}"
            ),
            Self::RawOutputTooLarge { bytes, max } => {
                write!(formatter, "engine raw result size {bytes} exceeds adapter cap {max}")
            }
            Self::InvalidAuthority => formatter.write_str(
                "engine result adapter requires trusted EXTERNAL_ENGINE EvidenceAuthority",
            ),
            Self::AuthorityManifestMismatch => formatter.write_str(
                "trusted evidence authority id/version does not match engine manifest id/adapter version",
            ),
            Self::InvalidTrustedCaptureTime => formatter.write_str(
                "trusted capture time must be canonical UTC RFC3339 (YYYY-MM-DDTHH:MM:SS[.fraction]Z)",
            ),
            Self::MalformedJson => formatter.write_str("engine result is not valid bounded JSON"),
            Self::InvalidNativeEnvelope => formatter.write_str(
                "Sentrdel-native engine JSON does not match the strict v1 envelope",
            ),
            Self::UnsupportedNativeSchemaVersion(version) => write!(
                formatter,
                "unsupported Sentrdel-native engine result schema version: {version:?}"
            ),
            Self::UnsupportedSarifVersion(version) => {
                write!(formatter, "unsupported SARIF version: {version:?}")
            }
            Self::TooManyRuns { count, max } => {
                write!(formatter, "SARIF run count {count} exceeds cap {max}")
            }
            Self::TooManyItems { count, max } => {
                write!(formatter, "engine result item count {count} exceeds cap {max}")
            }
            Self::TooManyLocations { count, max } => write!(
                formatter,
                "engine result location count {count} exceeds per-item cap {max}"
            ),
            Self::TooManySubjects { count, max } => write!(
                formatter,
                "engine result subject count {count} exceeds per-item cap {max}"
            ),
            Self::TooManyAttributes { count, max } => write!(
                formatter,
                "engine result attribute count {count} exceeds per-item cap {max}"
            ),
            Self::JsonNestingTooDeep { depth, max } => {
                write!(formatter, "engine JSON nesting depth {depth} exceeds cap {max}")
            }
            Self::JsonStructureTooComplex { nodes, max } => {
                write!(formatter, "engine JSON node count {nodes} exceeds cap {max}")
            }
            Self::AttributeValueTooLarge { bytes, max } => write!(
                formatter,
                "engine attribute value size {bytes} exceeds per-value cap {max}"
            ),
            Self::AttributeValueTooDeep { depth, max } => write!(
                formatter,
                "engine attribute value nesting depth {depth} exceeds cap {max}"
            ),
            Self::AttributeValueTooComplex { nodes, max } => write!(
                formatter,
                "engine attribute value node count {nodes} exceeds cap {max}"
            ),
            Self::InvalidIdentifier => formatter.write_str(
                "engine result identifier must be non-empty, normalized, bounded, and control-free",
            ),
            Self::InvalidResultText => formatter.write_str(
                "engine result text must be non-blank and free of unsupported control characters",
            ),
            Self::ResultTextTooLarge { bytes, max } => {
                write!(formatter, "engine result text length {bytes} exceeds cap {max}")
            }
            Self::MissingSarifRuleId => {
                formatter.write_str("SARIF result is missing a non-empty ruleId")
            }
            Self::MissingSarifMessage => {
                formatter.write_str("SARIF result is missing non-empty message text")
            }
            Self::UnsupportedSarifUriBase => formatter.write_str(
                "SARIF uriBaseId resolution is not trusted by T028; artifact URI must be directly repository-relative",
            ),
            Self::UnsupportedSarifLocation => formatter.write_str(
                "SARIF result location is not a supported physical repository location",
            ),
            Self::Location(error) => write!(formatter, "{error}"),
            Self::Evidence(error) => write!(formatter, "engine evidence validation failed: {error}"),
        }
    }
}

impl Error for EngineAdapterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Location(error) => Some(error),
            Self::Evidence(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RepoLocationError> for EngineAdapterError {
    fn from(value: RepoLocationError) -> Self {
        Self::Location(value)
    }
}

impl From<EvidenceValidationError> for EngineAdapterError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

/// Adapt a successful bounded T027 process outcome into canonical Evidence.
///
/// Non-completed outcomes are rejected before parsing. This does not create a
/// CoverageRecord; T030 owns termination-to-coverage semantics.
pub fn adapt_engine_output(
    manifest: &EngineManifest,
    dialect: EngineOutputDialect,
    outcome: &EngineProcessOutcome,
    authority: &EvidenceAuthority,
    limits: &EngineLimits,
    input_digests: &[String],
    captured_at: &str,
) -> Result<Vec<Evidence>, EngineAdapterError> {
    if outcome.termination_reason() != &TerminationReason::Completed {
        return Err(EngineAdapterError::ProcessNotCompleted(
            outcome.termination_reason().clone(),
        ));
    }
    adapt_completed_output(
        manifest,
        dialect,
        outcome.stdout(),
        authority,
        limits,
        input_digests,
        captured_at,
    )
}

fn adapt_completed_output(
    manifest: &EngineManifest,
    dialect: EngineOutputDialect,
    raw: &[u8],
    authority: &EvidenceAuthority,
    limits: &EngineLimits,
    input_digests: &[String],
    captured_at: &str,
) -> Result<Vec<Evidence>, EngineAdapterError> {
    validate_adapter_context(manifest, dialect, raw, authority, limits, captured_at)?;
    preflight_output(raw, dialect)?;

    match dialect {
        EngineOutputDialect::SentrdelJsonV1 => adapt_native_json(
            raw,
            authority,
            limits.workspace_root(),
            input_digests,
            captured_at,
        ),
        EngineOutputDialect::SarifV2_1_0 => adapt_sarif(
            raw,
            authority,
            limits.workspace_root(),
            input_digests,
            captured_at,
        ),
    }
}

fn validate_adapter_context(
    manifest: &EngineManifest,
    dialect: EngineOutputDialect,
    raw: &[u8],
    authority: &EvidenceAuthority,
    limits: &EngineLimits,
    captured_at: &str,
) -> Result<(), EngineAdapterError> {
    let declaration_count = manifest
        .output_dialects
        .iter()
        .filter(|declared| declared.as_str() == dialect.as_str())
        .count();
    match declaration_count {
        0 => {
            return Err(EngineAdapterError::UndeclaredDialect(
                dialect.as_str().to_owned(),
            ));
        }
        1 => {}
        _ => {
            return Err(EngineAdapterError::DuplicateDialectDeclaration(
                dialect.as_str().to_owned(),
            ));
        }
    }

    let parser_cap = MAX_ENGINE_ADAPTER_JSON_BYTES
        .min(usize::try_from(limits.max_stdout_bytes()).unwrap_or(usize::MAX));
    if raw.len() > parser_cap {
        return Err(EngineAdapterError::RawOutputTooLarge {
            bytes: raw.len(),
            max: parser_cap,
        });
    }
    let producer = authority.producer();
    if producer.kind != ProducerKind::ExternalEngine {
        return Err(EngineAdapterError::InvalidAuthority);
    }
    if producer.id != manifest.engine_id || producer.version != manifest.adapter_version {
        return Err(EngineAdapterError::AuthorityManifestMismatch);
    }
    if !is_canonical_utc_rfc3339(captured_at) {
        return Err(EngineAdapterError::InvalidTrustedCaptureTime);
    }
    Ok(())
}

fn preflight_output(raw: &[u8], dialect: EngineOutputDialect) -> Result<(), EngineAdapterError> {
    let bounded_dialect = match dialect {
        EngineOutputDialect::SentrdelJsonV1 => BoundedJsonDialect::Native,
        EngineOutputDialect::SarifV2_1_0 => BoundedJsonDialect::Sarif,
    };
    preflight_json(
        raw,
        bounded_dialect,
        MAX_ENGINE_ADAPTER_ITEMS,
        MAX_ENGINE_ADAPTER_RUNS,
        MAX_ENGINE_LOCATIONS_PER_ITEM,
        MAX_ENGINE_SUBJECTS_PER_ITEM,
        MAX_ENGINE_ATTRIBUTES_PER_ITEM,
    )
    .map_err(map_preflight_error)
}

fn map_preflight_error(error: BoundedJsonError) -> EngineAdapterError {
    match error {
        BoundedJsonError::Malformed => EngineAdapterError::MalformedJson,
        BoundedJsonError::TooManyRuns { count, max } => {
            EngineAdapterError::TooManyRuns { count, max }
        }
        BoundedJsonError::TooManyItems { count, max } => {
            EngineAdapterError::TooManyItems { count, max }
        }
        BoundedJsonError::TooManyLocations { count, max } => {
            EngineAdapterError::TooManyLocations { count, max }
        }
        BoundedJsonError::TooManySubjects { count, max } => {
            EngineAdapterError::TooManySubjects { count, max }
        }
        BoundedJsonError::TooManyAttributes { count, max } => {
            EngineAdapterError::TooManyAttributes { count, max }
        }
        BoundedJsonError::StringTooLarge { bytes, max } => {
            EngineAdapterError::ResultTextTooLarge { bytes, max }
        }
        BoundedJsonError::NestingTooDeep { depth, max } => {
            EngineAdapterError::JsonNestingTooDeep { depth, max }
        }
        BoundedJsonError::StructureTooComplex { nodes, max } => {
            EngineAdapterError::JsonStructureTooComplex { nodes, max }
        }
        BoundedJsonError::AttributeValueTooLarge { bytes, max } => {
            EngineAdapterError::AttributeValueTooLarge { bytes, max }
        }
        BoundedJsonError::AttributeValueTooDeep { depth, .. } => {
            EngineAdapterError::AttributeValueTooDeep {
                depth,
                max: MAX_ATTRIBUTE_VALUE_DEPTH,
            }
        }
        BoundedJsonError::AttributeValueTooComplex { nodes, max } => {
            EngineAdapterError::AttributeValueTooComplex { nodes, max }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEnvelope {
    schema_version: String,
    evidence: Vec<NativeEvidenceClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEvidenceClaim {
    observation: String,
    security_interpretation: Option<String>,
    category: String,
    epistemic_class: EpistemicClass,
    confidence_band: Option<ConfidenceBand>,
    subjects: Vec<EvidenceSubject>,
    locations: Vec<EvidenceLocation>,
    attributes: BTreeMap<String, Value>,
    reproduction: Option<ReproductionMetadata>,
}

fn adapt_native_json(
    raw: &[u8],
    authority: &EvidenceAuthority,
    workspace_root: &Path,
    input_digests: &[String],
    captured_at: &str,
) -> Result<Vec<Evidence>, EngineAdapterError> {
    let envelope: NativeEnvelope = serde_json::from_slice(raw).map_err(|error| {
        if error.is_syntax() || error.is_eof() {
            EngineAdapterError::MalformedJson
        } else {
            EngineAdapterError::InvalidNativeEnvelope
        }
    })?;
    if envelope.schema_version != SCHEMA_V1 {
        return Err(EngineAdapterError::UnsupportedNativeSchemaVersion(
            envelope.schema_version,
        ));
    }
    if envelope.evidence.len() > MAX_ENGINE_ADAPTER_ITEMS {
        return Err(EngineAdapterError::TooManyItems {
            count: envelope.evidence.len(),
            max: MAX_ENGINE_ADAPTER_ITEMS,
        });
    }

    envelope
        .evidence
        .into_iter()
        .map(|wire| {
            validate_result_text(&wire.observation)?;
            validate_identifier(&wire.category)?;
            if let Some(interpretation) = &wire.security_interpretation {
                validate_result_text(interpretation)?;
            }
            validate_subjects(&wire.subjects)?;
            validate_attributes(&wire.attributes)?;
            validate_reproduction(wire.reproduction.as_ref())?;
            let locations = normalize_locations(workspace_root, wire.locations)?;
            authority
                .seal(EvidenceClaim {
                    schema_version: SCHEMA_V1.to_owned(),
                    input_digests: input_digests.to_vec(),
                    observation: wire.observation,
                    security_interpretation: wire.security_interpretation,
                    category: wire.category,
                    epistemic_class: wire.epistemic_class,
                    confidence_band: wire.confidence_band,
                    subjects: wire.subjects,
                    locations,
                    attributes: wire.attributes,
                    reproduction: wire.reproduction,
                    captured_at: captured_at.to_owned(),
                })
                .map_err(EngineAdapterError::from)
        })
        .collect()
}

#[derive(Deserialize)]
struct SarifLog {
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Deserialize)]
struct SarifRun {
    tool: SarifTool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Deserialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: String,
    version: Option<String>,
    semantic_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: Option<String>,
    message: SarifMessage,
    #[serde(default)]
    locations: Vec<SarifLocation>,
    level: Option<String>,
}

#[derive(Deserialize)]
struct SarifMessage {
    text: Option<String>,
    markdown: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: Option<SarifPhysicalLocation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: Option<SarifRegion>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifArtifactLocation {
    uri: String,
    uri_base_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: Option<u64>,
    start_column: Option<u64>,
    end_line: Option<u64>,
    end_column: Option<u64>,
}

fn adapt_sarif(
    raw: &[u8],
    authority: &EvidenceAuthority,
    workspace_root: &Path,
    input_digests: &[String],
    captured_at: &str,
) -> Result<Vec<Evidence>, EngineAdapterError> {
    let log: SarifLog =
        serde_json::from_slice(raw).map_err(|_| EngineAdapterError::MalformedJson)?;
    if log.version != "2.1.0" {
        return Err(EngineAdapterError::UnsupportedSarifVersion(log.version));
    }
    if log.runs.len() > MAX_ENGINE_ADAPTER_RUNS {
        return Err(EngineAdapterError::TooManyRuns {
            count: log.runs.len(),
            max: MAX_ENGINE_ADAPTER_RUNS,
        });
    }
    let item_count = log
        .runs
        .iter()
        .try_fold(0usize, |count, run| count.checked_add(run.results.len()))
        .ok_or(EngineAdapterError::TooManyItems {
            count: usize::MAX,
            max: MAX_ENGINE_ADAPTER_ITEMS,
        })?;
    if item_count > MAX_ENGINE_ADAPTER_ITEMS {
        return Err(EngineAdapterError::TooManyItems {
            count: item_count,
            max: MAX_ENGINE_ADAPTER_ITEMS,
        });
    }

    let mut evidence = Vec::with_capacity(item_count);
    for run in log.runs {
        validate_identifier(&run.tool.driver.name)?;
        let tool_version = run
            .tool
            .driver
            .semantic_version
            .filter(|version| !version.trim().is_empty())
            .or_else(|| {
                run.tool
                    .driver
                    .version
                    .filter(|version| !version.trim().is_empty())
            });
        if let Some(version) = &tool_version {
            validate_identifier(version)?;
        }

        for result in run.results {
            let rule_id = result
                .rule_id
                .filter(|value| !value.trim().is_empty())
                .ok_or(EngineAdapterError::MissingSarifRuleId)?;
            validate_identifier(&rule_id)?;
            let SarifMessage { text, markdown } = result.message;
            let message = text
                .filter(|value| !value.trim().is_empty())
                .or_else(|| markdown.filter(|value| !value.trim().is_empty()))
                .ok_or(EngineAdapterError::MissingSarifMessage)?;
            validate_result_text(&message)?;
            if result.locations.len() > MAX_ENGINE_LOCATIONS_PER_ITEM {
                return Err(EngineAdapterError::TooManyLocations {
                    count: result.locations.len(),
                    max: MAX_ENGINE_LOCATIONS_PER_ITEM,
                });
            }

            let mut locations = Vec::with_capacity(result.locations.len());
            for location in result.locations {
                let physical = location
                    .physical_location
                    .ok_or(EngineAdapterError::UnsupportedSarifLocation)?;
                if physical.artifact_location.uri_base_id.is_some() {
                    return Err(EngineAdapterError::UnsupportedSarifUriBase);
                }
                let repo_relative_path =
                    normalize_repo_relative_path(workspace_root, &physical.artifact_location.uri)?;
                let region = physical.region;
                let evidence_location = EvidenceLocation {
                    repo_relative_path,
                    start_line: region.as_ref().and_then(|value| value.start_line),
                    start_column: region.as_ref().and_then(|value| value.start_column),
                    end_line: region.as_ref().and_then(|value| value.end_line),
                    end_column: region.as_ref().and_then(|value| value.end_column),
                    symbol: None,
                    content_digest: None,
                };
                validate_location_metadata(&evidence_location)?;
                locations.push(evidence_location);
            }

            let mut attributes = BTreeMap::new();
            attributes.insert("sarif_rule_id".to_owned(), Value::String(rule_id.clone()));
            attributes.insert(
                "sarif_tool_name".to_owned(),
                Value::String(run.tool.driver.name.clone()),
            );
            if let Some(version) = &tool_version {
                attributes.insert(
                    "sarif_tool_version".to_owned(),
                    Value::String(version.clone()),
                );
            }
            if let Some(level) = result.level.filter(|value| !value.trim().is_empty()) {
                validate_identifier(&level)?;
                attributes.insert("sarif_level".to_owned(), Value::String(level));
            }

            let observation = format!("external engine reported SARIF rule {rule_id}");
            evidence.push(authority.seal(EvidenceClaim {
                schema_version: SCHEMA_V1.to_owned(),
                input_digests: input_digests.to_vec(),
                observation,
                security_interpretation: Some(message),
                category: format!("sarif:{rule_id}"),
                epistemic_class: EpistemicClass::Inference,
                confidence_band: None,
                subjects: Vec::new(),
                locations,
                attributes,
                reproduction: None,
                captured_at: captured_at.to_owned(),
            })?);
        }
    }
    Ok(evidence)
}

fn validate_subjects(subjects: &[EvidenceSubject]) -> Result<(), EngineAdapterError> {
    if subjects.len() > MAX_ENGINE_SUBJECTS_PER_ITEM {
        return Err(EngineAdapterError::TooManySubjects {
            count: subjects.len(),
            max: MAX_ENGINE_SUBJECTS_PER_ITEM,
        });
    }
    for subject in subjects {
        validate_identifier(&subject.kind)?;
        validate_identifier(&subject.id)?;
    }
    Ok(())
}

fn validate_attributes(attributes: &BTreeMap<String, Value>) -> Result<(), EngineAdapterError> {
    if attributes.len() > MAX_ENGINE_ATTRIBUTES_PER_ITEM {
        return Err(EngineAdapterError::TooManyAttributes {
            count: attributes.len(),
            max: MAX_ENGINE_ATTRIBUTES_PER_ITEM,
        });
    }
    for (key, value) in attributes {
        validate_identifier(key)?;
        validate_attribute_value(value)?;
    }
    Ok(())
}

fn validate_attribute_value(value: &Value) -> Result<(), EngineAdapterError> {
    let mut nodes = 0usize;
    let mut bytes = 0usize;
    validate_attribute_value_inner(value, 0, &mut nodes, &mut bytes)
}

fn validate_attribute_value_inner(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
) -> Result<(), EngineAdapterError> {
    if depth > MAX_ATTRIBUTE_VALUE_DEPTH {
        return Err(EngineAdapterError::AttributeValueTooDeep {
            depth,
            max: MAX_ATTRIBUTE_VALUE_DEPTH,
        });
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_ATTRIBUTE_VALUE_NODES {
        return Err(EngineAdapterError::AttributeValueTooComplex {
            nodes: *nodes,
            max: MAX_ATTRIBUTE_VALUE_NODES,
        });
    }

    match value {
        Value::Null => add_attribute_bytes(bytes, 4)?,
        Value::Bool(true) => add_attribute_bytes(bytes, 4)?,
        Value::Bool(false) => add_attribute_bytes(bytes, 5)?,
        Value::Number(number) => add_attribute_bytes(bytes, number.to_string().len())?,
        Value::String(string) => add_attribute_bytes(bytes, string.len())?,
        Value::Array(values) => {
            add_attribute_bytes(bytes, 2)?;
            for child in values {
                validate_attribute_value_inner(child, depth + 1, nodes, bytes)?;
            }
        }
        Value::Object(values) => {
            add_attribute_bytes(bytes, 2)?;
            for (key, child) in values {
                if key.len() > MAX_ENGINE_IDENTIFIER_BYTES || key.chars().any(char::is_control) {
                    return Err(EngineAdapterError::InvalidIdentifier);
                }
                add_attribute_bytes(bytes, key.len())?;
                validate_attribute_value_inner(child, depth + 1, nodes, bytes)?;
            }
        }
    }
    Ok(())
}

fn add_attribute_bytes(total: &mut usize, additional: usize) -> Result<(), EngineAdapterError> {
    *total = total.saturating_add(additional);
    if *total > MAX_ATTRIBUTE_VALUE_BYTES {
        return Err(EngineAdapterError::AttributeValueTooLarge {
            bytes: *total,
            max: MAX_ATTRIBUTE_VALUE_BYTES,
        });
    }
    Ok(())
}

fn validate_reproduction(
    reproduction: Option<&ReproductionMetadata>,
) -> Result<(), EngineAdapterError> {
    let Some(reproduction) = reproduction else {
        return Ok(());
    };
    validate_identifier(&reproduction.method)?;
    if let Some(input_digest) = &reproduction.input_digest {
        validate_identifier(input_digest)?;
    }
    if let Some(notes) = &reproduction.notes {
        validate_result_text(notes)?;
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), EngineAdapterError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.len() > MAX_ENGINE_IDENTIFIER_BYTES
    {
        return Err(EngineAdapterError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_result_text(value: &str) -> Result<(), EngineAdapterError> {
    let bytes = value.len();
    if bytes > MAX_ENGINE_RESULT_TEXT_BYTES {
        return Err(EngineAdapterError::ResultTextTooLarge {
            bytes,
            max: MAX_ENGINE_RESULT_TEXT_BYTES,
        });
    }
    if value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(EngineAdapterError::InvalidResultText);
    }
    Ok(())
}

fn normalize_locations(
    workspace_root: &Path,
    locations: Vec<EvidenceLocation>,
) -> Result<Vec<EvidenceLocation>, EngineAdapterError> {
    if locations.len() > MAX_ENGINE_LOCATIONS_PER_ITEM {
        return Err(EngineAdapterError::TooManyLocations {
            count: locations.len(),
            max: MAX_ENGINE_LOCATIONS_PER_ITEM,
        });
    }
    locations
        .into_iter()
        .map(|mut location| {
            location.repo_relative_path =
                normalize_repo_relative_path(workspace_root, &location.repo_relative_path)?;
            validate_location_metadata(&location)?;
            Ok(location)
        })
        .collect()
}

fn validate_location_metadata(location: &EvidenceLocation) -> Result<(), RepoLocationError> {
    if location.content_digest.is_some() {
        return Err(RepoLocationError::UnverifiedContentDigest);
    }
    if let Some(symbol) = &location.symbol
        && (symbol.is_empty()
            || symbol.len() > MAX_ENGINE_RESULT_TEXT_BYTES
            || symbol
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\t')))
    {
        return Err(RepoLocationError::InvalidSymbol);
    }

    let values = [
        location.start_line,
        location.start_column,
        location.end_line,
        location.end_column,
    ];
    if values.into_iter().flatten().any(|value| value == 0) {
        return Err(RepoLocationError::InvalidRange);
    }
    if location.start_line.is_none()
        && (location.start_column.is_some()
            || location.end_line.is_some()
            || location.end_column.is_some())
    {
        return Err(RepoLocationError::InvalidRange);
    }
    if location.end_column.is_some() && location.start_column.is_none() {
        return Err(RepoLocationError::InvalidRange);
    }
    if let (Some(start_line), Some(end_line)) = (location.start_line, location.end_line) {
        if end_line < start_line {
            return Err(RepoLocationError::InvalidRange);
        }
        if end_line == start_line
            && let (Some(start_column), Some(end_column)) =
                (location.start_column, location.end_column)
            && end_column < start_column
        {
            return Err(RepoLocationError::InvalidRange);
        }
    } else if location.end_line.is_none()
        && let (Some(start_column), Some(end_column)) = (location.start_column, location.end_column)
        && end_column < start_column
    {
        return Err(RepoLocationError::InvalidRange);
    }
    Ok(())
}

fn is_canonical_utc_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len()) {
        return false;
    }
    for index in [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    if bytes.len() == 20 {
        if bytes[19] != b'Z' {
            return false;
        }
    } else {
        if bytes[19] != b'.' || bytes[bytes.len() - 1] != b'Z' {
            return false;
        }
        let fraction = &bytes[20..bytes.len() - 1];
        if fraction.is_empty()
            || fraction.len() > 9
            || fraction.iter().any(|byte| !byte.is_ascii_digit())
            || fraction.last() == Some(&b'0')
        {
            return false;
        }
    }

    let year = parse_ascii_u32(&bytes[0..4]);
    let month = parse_ascii_u32(&bytes[5..7]);
    let day = parse_ascii_u32(&bytes[8..10]);
    let hour = parse_ascii_u32(&bytes[11..13]);
    let minute = parse_ascii_u32(&bytes[14..16]);
    let second = parse_ascii_u32(&bytes[17..19]);
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (year, month, day, hour, minute, second)
    else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 59 || !(1..=12).contains(&month) {
        return false;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day)
}

fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Normalize an untrusted engine/SARIF source location to one canonical,
/// forward-slash, repository-relative path and reject lexical or symlink escape.
pub fn normalize_repo_relative_path(
    workspace_root: &Path,
    raw: &str,
) -> Result<String, RepoLocationError> {
    if raw.is_empty() {
        return Err(RepoLocationError::Empty);
    }
    if raw.len() > MAX_ENGINE_LOCATION_BYTES {
        return Err(RepoLocationError::TooLong {
            bytes: raw.len(),
            max: MAX_ENGINE_LOCATION_BYTES,
        });
    }
    if raw.trim() != raw {
        return Err(RepoLocationError::Padded);
    }
    if raw.chars().any(char::is_control) {
        return Err(RepoLocationError::ControlCharacter);
    }

    let decoded = percent_decode_utf8(raw)?;
    if decoded.chars().any(char::is_control) {
        return Err(RepoLocationError::ControlCharacter);
    }
    if decoded.contains('?') || decoded.contains('#') {
        return Err(RepoLocationError::UriQueryOrFragment);
    }
    let portable = decoded.replace('\\', "/");
    if portable.starts_with('/') || has_uri_scheme_or_drive(&portable) {
        return Err(RepoLocationError::AbsoluteOrScheme);
    }

    let mut normalized = Vec::new();
    for component in portable.split('/') {
        match component {
            "" => return Err(RepoLocationError::EmptyComponent),
            "." => {}
            ".." => return Err(RepoLocationError::ParentTraversal),
            value => normalized.push(value),
        }
    }
    if normalized.is_empty() {
        return Err(RepoLocationError::Empty);
    }

    let normalized_path = normalized.join("/");
    validate_existing_prefixes(workspace_root, &normalized_path)?;
    Ok(normalized_path)
}

fn has_uri_scheme_or_drive(value: &str) -> bool {
    let Some(colon) = value.find(':') else {
        return false;
    };
    let slash = value.find('/').unwrap_or(usize::MAX);
    if colon > slash {
        return false;
    }
    let scheme = &value[..colon];
    !scheme.is_empty()
        && scheme.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic()
            } else {
                character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
            }
        })
}

fn percent_decode_utf8(value: &str) -> Result<String, RepoLocationError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(RepoLocationError::InvalidPercentEncoding);
        }
        let high = hex_value(bytes[index + 1]).ok_or(RepoLocationError::InvalidPercentEncoding)?;
        let low = hex_value(bytes[index + 2]).ok_or(RepoLocationError::InvalidPercentEncoding)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| RepoLocationError::InvalidUtf8Encoding)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn validate_existing_prefixes(
    workspace_root: &Path,
    normalized_path: &str,
) -> Result<(), RepoLocationError> {
    let canonical_root = fs::canonicalize(workspace_root)
        .map_err(|error| RepoLocationError::Filesystem(error.kind()))?;
    if !canonical_root.is_dir() {
        return Err(RepoLocationError::OutsideWorkspace);
    }

    let mut prefix = canonical_root.clone();
    for component in Path::new(normalized_path).components() {
        let Component::Normal(component) = component else {
            return Err(RepoLocationError::ParentTraversal);
        };
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(_) => {
                let canonical = fs::canonicalize(&prefix)
                    .map_err(|error| RepoLocationError::Filesystem(error.kind()))?;
                if !canonical.starts_with(&canonical_root) {
                    return Err(RepoLocationError::OutsideWorkspace);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(RepoLocationError::Filesystem(error.kind())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::engine::NetworkRequirement;
    use std::{
        env,
        path::PathBuf,
        process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn workspace(label: &str) -> (PathBuf, PathBuf) {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("sentrdel-t028-{label}-{}-{id}", process::id()));
        let cwd = root.join("cwd");
        fs::create_dir_all(&cwd).expect("create T028 workspace");
        (root, cwd)
    }

    fn manifest(dialect: &str) -> EngineManifest {
        EngineManifest {
            schema_version: SCHEMA_V1.to_owned(),
            engine_id: "fixture-engine".to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-fixture".to_owned(),
            executable_digest: None,
            expected_version_constraint: None,
            input_dialects: vec!["fixture".to_owned()],
            output_dialects: vec![dialect.to_owned()],
            capabilities: vec!["fixture".to_owned()],
            timeout_ms: 1_000,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 64 * 1024,
            allowed_environment_names: Vec::new(),
            network_requirement: NetworkRequirement::None,
        }
    }

    fn limits(manifest: &EngineManifest, label: &str) -> EngineLimits {
        let (root, cwd) = workspace(label);
        EngineLimits::from_manifest(manifest, root, cwd, crate::NetworkAccessPolicy::Deny)
            .expect("valid T028 limits")
    }

    fn authority() -> EvidenceAuthority {
        EvidenceAuthority::from_runtime("fixture-engine", "1", ProducerKind::ExternalEngine)
            .expect("external engine authority")
    }

    #[test]
    fn native_json_injects_trusted_provenance_and_normalizes_location() {
        let manifest = manifest(SENTRDEL_JSON_V1_DIALECT);
        let limits = limits(&manifest, "native");
        let raw = serde_json::json!({
            "schema_version": "1",
            "evidence": [{
                "observation": "manifest field is present",
                "security_interpretation": null,
                "category": "fixture",
                "epistemic_class": "FACT",
                "confidence_band": "HIGH",
                "subjects": [],
                "locations": [{
                    "repo_relative_path": "src/./lib.rs",
                    "start_line": 2,
                    "start_column": 1,
                    "end_line": 2,
                    "end_column": 4,
                    "symbol": null,
                    "content_digest": null
                }],
                "attributes": {},
                "reproduction": null
            }]
        });
        let evidence = adapt_completed_output(
            &manifest,
            EngineOutputDialect::SentrdelJsonV1,
            &serde_json::to_vec(&raw).expect("serialize fixture"),
            &authority(),
            &limits,
            &["sha256:trusted-input".to_owned()],
            "2026-08-26T00:00:00Z",
        )
        .expect("adapt native result");

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].producer().kind, ProducerKind::ExternalEngine);
        assert_eq!(
            evidence[0].claim().locations[0].repo_relative_path,
            "src/lib.rs"
        );
    }

    #[test]
    fn native_json_rejects_forged_authority_verified_and_unverified_digest() {
        let manifest = manifest(SENTRDEL_JSON_V1_DIALECT);
        let limits = limits(&manifest, "native-authority");
        let forged = serde_json::json!({
            "schema_version": "1",
            "evidence": [{
                "producer": {"id": "forged", "version": "9", "kind": "SYSTEM"},
                "observation": "x",
                "security_interpretation": null,
                "category": "fixture",
                "epistemic_class": "FACT",
                "confidence_band": null,
                "subjects": [],
                "locations": [],
                "attributes": {},
                "reproduction": null
            }]
        });
        assert_eq!(
            adapt_completed_output(
                &manifest,
                EngineOutputDialect::SentrdelJsonV1,
                &serde_json::to_vec(&forged).expect("serialize fixture"),
                &authority(),
                &limits,
                &[],
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineAdapterError::InvalidNativeEnvelope)
        );

        let verified = serde_json::json!({
            "schema_version": "1",
            "evidence": [{
                "observation": "x",
                "security_interpretation": null,
                "category": "fixture",
                "epistemic_class": "VERIFIED",
                "confidence_band": null,
                "subjects": [],
                "locations": [],
                "attributes": {},
                "reproduction": null
            }]
        });
        assert!(matches!(
            adapt_completed_output(
                &manifest,
                EngineOutputDialect::SentrdelJsonV1,
                &serde_json::to_vec(&verified).expect("serialize fixture"),
                &authority(),
                &limits,
                &[],
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineAdapterError::Evidence(
                EvidenceValidationError::VerifiedNotAuthorizedInR1
            ))
        ));

        let digest = serde_json::json!({
            "schema_version": "1",
            "evidence": [{
                "observation": "x",
                "security_interpretation": null,
                "category": "fixture",
                "epistemic_class": "FACT",
                "confidence_band": null,
                "subjects": [],
                "locations": [{
                    "repo_relative_path": "src/lib.rs",
                    "start_line": 1,
                    "start_column": null,
                    "end_line": null,
                    "end_column": null,
                    "symbol": null,
                    "content_digest": "sha256:forged"
                }],
                "attributes": {},
                "reproduction": null
            }]
        });
        assert!(matches!(
            adapt_completed_output(
                &manifest,
                EngineOutputDialect::SentrdelJsonV1,
                &serde_json::to_vec(&digest).expect("serialize fixture"),
                &authority(),
                &limits,
                &[],
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineAdapterError::Location(
                RepoLocationError::UnverifiedContentDigest
            ))
        ));
    }

    #[test]
    fn invalid_capture_time_is_rejected_before_parsing() {
        let manifest = manifest(SENTRDEL_JSON_V1_DIALECT);
        let limits = limits(&manifest, "time");
        for invalid in [
            "not-a-timestamp",
            "2026-02-30T00:00:00Z",
            "2026-08-26T00:00:00+00:00",
            "2026-08-26T00:00:00.100Z",
        ] {
            assert_eq!(
                adapt_completed_output(
                    &manifest,
                    EngineOutputDialect::SentrdelJsonV1,
                    br#"{"schema_version":"1","evidence":[]}"#,
                    &authority(),
                    &limits,
                    &[],
                    invalid,
                ),
                Err(EngineAdapterError::InvalidTrustedCaptureTime)
            );
        }
        assert!(is_canonical_utc_rfc3339("2026-08-26T00:00:00.1Z"));
    }

    #[test]
    fn sarif_blank_text_falls_back_to_markdown() {
        let manifest = manifest(SARIF_V2_1_0_DIALECT);
        let limits = limits(&manifest, "sarif-markdown");
        let raw = serde_json::json!({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "FixtureScan"}},
                "results": [{
                    "ruleId": "fixture.rule",
                    "message": {"text": "   ", "markdown": "valid message"},
                    "locations": []
                }]
            }]
        });
        let evidence = adapt_completed_output(
            &manifest,
            EngineOutputDialect::SarifV2_1_0,
            &serde_json::to_vec(&raw).expect("serialize fixture"),
            &authority(),
            &limits,
            &[],
            "2026-08-26T00:00:00Z",
        )
        .expect("adapt markdown fallback");
        assert_eq!(
            evidence[0].claim().security_interpretation.as_deref(),
            Some("valid message")
        );
    }

    #[test]
    fn attribute_subtree_depth_fails_before_serde_materialization() {
        let manifest = manifest(SENTRDEL_JSON_V1_DIALECT);
        let limits = limits(&manifest, "attribute-depth");
        let mut nested = String::new();
        for _ in 0..=MAX_ATTRIBUTE_VALUE_DEPTH {
            nested.push('[');
        }
        nested.push('0');
        for _ in 0..=MAX_ATTRIBUTE_VALUE_DEPTH {
            nested.push(']');
        }
        let raw = format!(
            r#"{{"schema_version":"1","evidence":[{{"observation":"x","security_interpretation":null,"category":"fixture","epistemic_class":"FACT","confidence_band":null,"subjects":[],"locations":[],"attributes":{{"x":{nested}}},"reproduction":null}}]}}"#
        );
        assert!(matches!(
            adapt_completed_output(
                &manifest,
                EngineOutputDialect::SentrdelJsonV1,
                raw.as_bytes(),
                &authority(),
                &limits,
                &[],
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineAdapterError::AttributeValueTooDeep { .. })
        ));
    }

    #[test]
    fn sarif_maps_results_to_inference_and_normalized_locations() {
        let manifest = manifest(SARIF_V2_1_0_DIALECT);
        let limits = limits(&manifest, "sarif");
        let raw = serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "FixtureScan", "semanticVersion": "1.2.3"}},
                "results": [{
                    "ruleId": "fixture.rule",
                    "level": "warning",
                    "message": {"text": "possible security issue"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/%6cib.rs"},
                            "region": {"startLine": 7, "startColumn": 3}
                        }
                    }]
                }]
            }]
        });
        let evidence = adapt_completed_output(
            &manifest,
            EngineOutputDialect::SarifV2_1_0,
            &serde_json::to_vec(&raw).expect("serialize fixture"),
            &authority(),
            &limits,
            &["sha256:trusted-input".to_owned()],
            "2026-08-26T00:00:00Z",
        )
        .expect("adapt SARIF");

        let claim = evidence[0].claim();
        assert_eq!(claim.epistemic_class, EpistemicClass::Inference);
        assert_eq!(
            claim.observation,
            "external engine reported SARIF rule fixture.rule"
        );
        assert_eq!(claim.locations[0].repo_relative_path, "src/lib.rs");
    }

    #[test]
    fn dialect_location_and_range_fail_closed() {
        let manifest = manifest(SENTRDEL_JSON_V1_DIALECT);
        let limits = limits(&manifest, "paths");
        assert_eq!(
            EngineOutputDialect::try_from("json"),
            Err(EngineAdapterError::UnsupportedDialect("json".to_owned()))
        );

        for path in [
            "../secret",
            "%2e%2e/secret",
            "/etc/passwd",
            "C:\\secret",
            "file:///tmp/x",
        ] {
            assert!(normalize_repo_relative_path(limits.workspace_root(), path).is_err());
        }

        let invalid_range = EvidenceLocation {
            repo_relative_path: "src/lib.rs".to_owned(),
            start_line: Some(0),
            start_column: None,
            end_line: None,
            end_column: None,
            symbol: None,
            content_digest: None,
        };
        assert_eq!(
            validate_location_metadata(&invalid_range),
            Err(RepoLocationError::InvalidRange)
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let manifest = manifest(SENTRDEL_JSON_V1_DIALECT);
        let limits = limits(&manifest, "symlink");
        let outside = env::temp_dir().join(format!(
            "sentrdel-t028-outside-{}-{}",
            process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&outside).expect("create outside fixture");
        symlink(&outside, limits.workspace_root().join("escape")).expect("create fixture symlink");

        assert_eq!(
            normalize_repo_relative_path(limits.workspace_root(), "escape/file.rs"),
            Err(RepoLocationError::OutsideWorkspace)
        );
    }
}
