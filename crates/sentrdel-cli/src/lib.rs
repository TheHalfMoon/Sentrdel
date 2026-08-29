#![forbid(unsafe_code)]
//! Stable R1 CLI process and JSON-output contracts.
//!
//! This crate layer owns only the cross-command envelope and exit semantics.
//! Command parsing, repository discovery, dependency injection, review/init/
//! guard behavior, and feature-specific output population remain later tasks.

pub mod explain;
pub mod guard_mcp;
pub mod init;
pub mod review;

use std::{error::Error, fmt, process::ExitCode};

use sentrdel_schema::{SCHEMA_V1, coverage::CoverageRecord, policy::Verdict};
use serde::Serialize;

const MAX_CLI_ID_BYTES: usize = 4_096;
const MAX_CLI_MESSAGE_BYTES: usize = 64 * 1024;

/// Frozen R1 process exit codes from the binding CLI contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CliExitCode {
    Success = 0,
    Blocking = 1,
    Usage = 2,
    Incomplete = 3,
    Internal = 4,
}

impl CliExitCode {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<CliExitCode> for ExitCode {
    fn from(value: CliExitCode) -> Self {
        Self::from(value.as_u8())
    }
}

/// Machine-readable decision/outcome carried in the stable JSON envelope.
///
/// The four security/policy decisions deliberately preserve the canonical R1
/// `Verdict` vocabulary, including `ASK`. Usage and internal failures are also
/// represented so `--json` callers can receive a structurally stable response
/// when a command cannot complete normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CliDecision {
    Allow,
    Ask,
    Deny,
    Undecidable,
    UsageError,
    InternalFailure,
}

impl CliDecision {
    pub const fn exit_code(self) -> CliExitCode {
        match self {
            Self::Allow => CliExitCode::Success,
            Self::Deny => CliExitCode::Blocking,
            Self::UsageError => CliExitCode::Usage,
            Self::Ask | Self::Undecidable => CliExitCode::Incomplete,
            Self::InternalFailure => CliExitCode::Internal,
        }
    }
}

impl From<Verdict> for CliDecision {
    fn from(value: Verdict) -> Self {
        match value {
            Verdict::Allow => Self::Allow,
            Verdict::Ask => Self::Ask,
            Verdict::Deny => Self::Deny,
            Verdict::Undecidable => Self::Undecidable,
        }
    }
}

/// Frozen command identifiers for the R1 top-level JSON `command` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CliCommand {
    #[serde(rename = "init")]
    Init,
    #[serde(rename = "review")]
    Review,
    #[serde(rename = "explain")]
    Explain,
    #[serde(rename = "guard mcp")]
    GuardMcp,
    #[serde(rename = "guard install-git-hooks")]
    GuardInstallGitHooks,
}

/// Stable repository identity emitted by machine-readable commands.
///
/// `root` is a portable repository-relative display root (`.` or a canonical
/// relative subtree), never an absolute workstation path. Command-specific
/// human output may separately render a user-approved local path when needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CliRepository {
    pub identity: String,
    pub root: String,
}

impl CliRepository {
    pub fn new(
        identity: impl Into<String>,
        root: impl Into<String>,
    ) -> Result<Self, CliContractError> {
        let value = Self {
            identity: identity.into(),
            root: root.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), CliContractError> {
        validate_identifier("repository identity", &self.identity)?;
        if self.root != "." && !is_canonical_relative_path(&self.root) {
            return Err(CliContractError::InvalidRepositoryRoot(self.root.clone()));
        }
        Ok(())
    }
}

/// Canonical references needed by CI consumers without duplicating Finding
/// authority or lifecycle state inside the CLI layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CliFindingRef {
    pub finding_id: String,
    pub evidence_ids: Vec<String>,
}

impl CliFindingRef {
    pub fn new(
        finding_id: impl Into<String>,
        evidence_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, CliContractError> {
        let mut value = Self {
            finding_id: finding_id.into(),
            evidence_ids: evidence_ids.into_iter().collect(),
        };
        value.normalize()?;
        Ok(value)
    }

    fn normalize(&mut self) -> Result<(), CliContractError> {
        validate_identifier("finding id", &self.finding_id)?;
        for evidence_id in &self.evidence_ids {
            validate_identifier("evidence id", evidence_id)?;
        }
        self.evidence_ids.sort();
        self.evidence_ids.dedup();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CliDiagnosticLevel {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CliDiagnostic {
    pub code: String,
    pub level: CliDiagnosticLevel,
    pub message: String,
}

impl CliDiagnostic {
    pub fn new(
        code: impl Into<String>,
        level: CliDiagnosticLevel,
        message: impl Into<String>,
    ) -> Result<Self, CliContractError> {
        let value = Self {
            code: code.into(),
            level,
            message: message.into(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), CliContractError> {
        validate_identifier("diagnostic code", &self.code)?;
        if self.message.trim().is_empty()
            || self.message.len() > MAX_CLI_MESSAGE_BYTES
            || self.message.chars().any(char::is_control)
        {
            return Err(CliContractError::InvalidDiagnosticMessage);
        }
        Ok(())
    }
}

/// Runtime-only metadata explicitly allowed to vary across otherwise identical
/// deterministic command results.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CliTiming {
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

impl CliTiming {
    pub fn validate(&self) -> Result<(), CliContractError> {
        if self.observed_at.as_deref().is_some_and(|value| {
            value.trim().is_empty()
                || value.len() > MAX_CLI_ID_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(CliContractError::InvalidObservedAt);
        }
        Ok(())
    }
}

/// Stable R1 JSON envelope shared by all public commands.
///
/// Input collections are revalidated and normalized into deterministic order at
/// construction, even if a caller created public record fields directly. The
/// envelope is output-only; it deliberately does not implement Deserialize and
/// therefore cannot manufacture canonical Finding, Evidence, or policy
/// authority from untrusted JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CliEnvelope {
    pub schema_version: String,
    pub command: CliCommand,
    pub repository: CliRepository,
    pub decision: CliDecision,
    pub findings: Vec<CliFindingRef>,
    pub coverage: Vec<CoverageRecord>,
    pub diagnostics: Vec<CliDiagnostic>,
    pub timing: CliTiming,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_refs: Option<Vec<String>>,
}

impl CliEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: CliCommand,
        repository: CliRepository,
        decision: CliDecision,
        mut findings: Vec<CliFindingRef>,
        mut coverage: Vec<CoverageRecord>,
        mut diagnostics: Vec<CliDiagnostic>,
        timing: CliTiming,
        store_refs: Option<Vec<String>>,
    ) -> Result<Self, CliContractError> {
        repository.validate()?;
        timing.validate()?;
        for finding in &mut findings {
            finding.normalize()?;
        }
        findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        coverage.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
        diagnostics.sort();
        let store_refs = normalize_store_refs(store_refs)?;
        Ok(Self {
            schema_version: SCHEMA_V1.to_owned(),
            command,
            repository,
            decision,
            findings,
            coverage,
            diagnostics,
            timing,
            store_refs,
        })
    }

    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CliContractError {
    InvalidIdentifier(&'static str),
    InvalidRepositoryRoot(String),
    InvalidDiagnosticMessage,
    InvalidObservedAt,
    InvalidStoreRef,
}

impl fmt::Display for CliContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(kind) => write!(formatter, "invalid {kind}"),
            Self::InvalidRepositoryRoot(root) => {
                write!(formatter, "invalid repository root {root:?}")
            }
            Self::InvalidDiagnosticMessage => formatter.write_str("invalid diagnostic message"),
            Self::InvalidObservedAt => formatter.write_str("invalid observed_at value"),
            Self::InvalidStoreRef => formatter.write_str("invalid store reference"),
        }
    }
}

impl Error for CliContractError {}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), CliContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_CLI_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CliContractError::InvalidIdentifier(kind));
    }
    Ok(())
}

fn is_canonical_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains("//")
        && !value.contains("\\")
        && !value.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        && !value.chars().any(char::is_control)
}

fn normalize_store_refs(
    refs: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, CliContractError> {
    let Some(mut refs) = refs else {
        return Ok(None);
    };
    for value in &refs {
        validate_identifier("store reference", value).map_err(|_| CliContractError::InvalidStoreRef)?;
    }
    refs.sort();
    refs.dedup();
    Ok(Some(refs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::coverage::CoverageState;

    fn repository() -> CliRepository {
        CliRepository::new("repo:fixture", ".").expect("repository")
    }

    #[test]
    fn frozen_exit_codes_are_stable() {
        assert_eq!(CliExitCode::Success.as_u8(), 0);
        assert_eq!(CliExitCode::Blocking.as_u8(), 1);
        assert_eq!(CliExitCode::Usage.as_u8(), 2);
        assert_eq!(CliExitCode::Incomplete.as_u8(), 3);
        assert_eq!(CliExitCode::Internal.as_u8(), 4);
    }

    #[test]
    fn verdict_mapping_preserves_ask_and_undecidable() {
        assert_eq!(CliDecision::from(Verdict::Allow), CliDecision::Allow);
        assert_eq!(CliDecision::from(Verdict::Ask), CliDecision::Ask);
        assert_eq!(CliDecision::from(Verdict::Deny), CliDecision::Deny);
        assert_eq!(CliDecision::from(Verdict::Undecidable), CliDecision::Undecidable);
    }

    #[test]
    fn envelope_normalizes_findings_coverage_and_store_refs() {
        let coverage = CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: "coverage:z".to_owned(),
            capability: "fixture".to_owned(),
            scope: ".".to_owned(),
            producer: None,
            provider_dimension: None,
            state: CoverageState::Covered,
            reason_code: None,
            details: None,
            input_digests: Vec::new(),
            observed_at: "2026-08-24T00:00:00Z".to_owned(),
        };
        let envelope = CliEnvelope::new(
            CliCommand::Review,
            repository(),
            CliDecision::Allow,
            vec![
                CliFindingRef::new("finding:z", vec!["evidence:z".to_owned()]).expect("finding"),
                CliFindingRef::new("finding:a", vec!["evidence:b".to_owned(), "evidence:a".to_owned()])
                    .expect("finding"),
            ],
            vec![coverage],
            Vec::new(),
            CliTiming::default(),
            Some(vec!["store:z".to_owned(), "store:a".to_owned(), "store:z".to_owned()]),
        )
        .expect("envelope");
        assert_eq!(envelope.findings[0].finding_id, "finding:a");
        assert_eq!(envelope.findings[0].evidence_ids, vec!["evidence:a", "evidence:b"]);
        assert_eq!(envelope.store_refs, Some(vec!["store:a".to_owned(), "store:z".to_owned()]));
    }

    #[test]
    fn envelope_rejects_absolute_or_traversing_repository_root() {
        assert!(CliRepository::new("repo:fixture", "/tmp/repo").is_err());
        assert!(CliRepository::new("repo:fixture", "../repo").is_err());
    }

    #[test]
    fn json_envelope_has_frozen_top_level_fields() {
        let envelope = CliEnvelope::new(
            CliCommand::Init,
            repository(),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .expect("envelope");
        let value = serde_json::to_value(envelope).expect("json");
        for field in [
            "schema_version",
            "command",
            "repository",
            "decision",
            "findings",
            "coverage",
            "diagnostics",
            "timing",
        ] {
            assert!(value.get(field).is_some(), "missing {field}");
        }
    }
}
