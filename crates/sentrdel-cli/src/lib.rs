#![forbid(unsafe_code)]
//! Stable R1 CLI process and JSON-output contracts.
//!
//! This crate layer owns only the cross-command envelope and exit semantics.
//! Command parsing, repository discovery, dependency injection, review/init/
//! guard behavior, and feature-specific output population remain later tasks.

pub mod guard_mcp;
pub mod init;
pub mod provider_registration;
pub mod reasoning;
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
            // ASK means the action is not resolved until explicit approval;
            // returning success/block would misrepresent the pending decision.
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
        reject_duplicate_finding_ids(&findings)?;

        for record in &coverage {
            validate_identifier("coverage id", &record.coverage_id)?;
        }
        coverage.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
        reject_duplicate_coverage_ids(&coverage)?;

        for diagnostic in &diagnostics {
            diagnostic.validate()?;
        }
        diagnostics.sort();
        diagnostics.dedup();

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

    pub const fn exit_code(&self) -> CliExitCode {
        self.decision.exit_code()
    }

    /// Serialize one deterministic machine-readable JSON line suitable for CI
    /// stdout. A trailing newline is always present.
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        let mut output = serde_json::to_string(self)?;
        output.push('\n');
        Ok(output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliContractError {
    InvalidIdentifier(&'static str),
    InvalidRepositoryRoot(String),
    InvalidDiagnosticMessage,
    InvalidObservedAt,
    DuplicateFindingId(String),
    DuplicateCoverageId(String),
}

impl fmt::Display for CliContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(field) => write!(
                formatter,
                "CLI {field} must be bounded, non-blank text without controls"
            ),
            Self::InvalidRepositoryRoot(root) => write!(
                formatter,
                "CLI repository root must be '.' or a canonical repository-relative path: {root:?}"
            ),
            Self::InvalidDiagnosticMessage => formatter.write_str(
                "CLI diagnostic message must be bounded, non-blank text without controls",
            ),
            Self::InvalidObservedAt => formatter.write_str(
                "CLI observed_at must be bounded, non-blank text without control characters when present",
            ),
            Self::DuplicateFindingId(id) => {
                write!(formatter, "CLI envelope contains duplicate finding id {id:?}")
            }
            Self::DuplicateCoverageId(id) => {
                write!(formatter, "CLI envelope contains duplicate coverage id {id:?}")
            }
        }
    }
}

impl Error for CliContractError {}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), CliContractError> {
    if value.trim().is_empty()
        || value.len() > MAX_CLI_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CliContractError::InvalidIdentifier(field));
    }
    Ok(())
}

fn is_canonical_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.chars().any(char::is_control)
        })
        && !value
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':' && value.as_bytes()[0].is_ascii_alphabetic())
}

fn reject_duplicate_finding_ids(findings: &[CliFindingRef]) -> Result<(), CliContractError> {
    for pair in findings.windows(2) {
        if pair[0].finding_id == pair[1].finding_id {
            return Err(CliContractError::DuplicateFindingId(
                pair[0].finding_id.clone(),
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_coverage_ids(coverage: &[CoverageRecord]) -> Result<(), CliContractError> {
    for pair in coverage.windows(2) {
        if pair[0].coverage_id == pair[1].coverage_id {
            return Err(CliContractError::DuplicateCoverageId(
                pair[0].coverage_id.clone(),
            ));
        }
    }
    Ok(())
}

fn normalize_store_refs(store_refs: Option<Vec<String>>) -> Result<Option<Vec<String>>, CliContractError> {
    let Some(mut refs) = store_refs else {
        return Ok(None);
    };
    for value in &refs {
        validate_identifier("store ref", value)?;
    }
    refs.sort();
    refs.dedup();
    if refs.is_empty() {
        Ok(None)
    } else {
        Ok(Some(refs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage(id: &str) -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: id.to_owned(),
            capability: "fixture".to_owned(),
            scope: ".".to_owned(),
            producer: None,
            provider_dimension: None,
            state: sentrdel_schema::coverage::CoverageState::Covered,
            reason_code: None,
            details: None,
            input_digests: Vec::new(),
            observed_at: "2026-08-28T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn exit_codes_are_frozen() {
        assert_eq!(CliExitCode::Success.as_u8(), 0);
        assert_eq!(CliExitCode::Blocking.as_u8(), 1);
        assert_eq!(CliExitCode::Usage.as_u8(), 2);
        assert_eq!(CliExitCode::Incomplete.as_u8(), 3);
        assert_eq!(CliExitCode::Internal.as_u8(), 4);
        assert_eq!(CliDecision::Allow.exit_code(), CliExitCode::Success);
        assert_eq!(CliDecision::Deny.exit_code(), CliExitCode::Blocking);
        assert_eq!(CliDecision::Ask.exit_code(), CliExitCode::Incomplete);
        assert_eq!(
            CliDecision::Undecidable.exit_code(),
            CliExitCode::Incomplete
        );
        assert_eq!(CliDecision::UsageError.exit_code(), CliExitCode::Usage);
        assert_eq!(
            CliDecision::InternalFailure.exit_code(),
            CliExitCode::Internal
        );
    }

    #[test]
    fn json_envelope_is_deterministic_and_one_line() {
        let envelope = CliEnvelope::new(
            CliCommand::Review,
            CliRepository::new("repo:fixture", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            vec![coverage("coverage:b"), coverage("coverage:a")],
            vec![
                CliDiagnostic::new("Z_LAST", CliDiagnosticLevel::Info, "last").unwrap(),
                CliDiagnostic::new("A_FIRST", CliDiagnosticLevel::Warning, "first").unwrap(),
            ],
            CliTiming {
                duration_ms: 12,
                observed_at: None,
            },
            Some(vec!["store:z".to_owned(), "store:a".to_owned()]),
        )
        .unwrap();

        let serialized = envelope.to_json_line().unwrap();
        assert_eq!(serialized.matches('\n').count(), 1);
        let value: serde_json::Value = serde_json::from_str(serialized.trim_end()).unwrap();
        assert_eq!(value["coverage"][0]["coverage_id"], "coverage:a");
        assert_eq!(value["diagnostics"][0]["code"], "A_FIRST");
        assert_eq!(value["store_refs"][0], "store:a");
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let error = CliEnvelope::new(
            CliCommand::Review,
            CliRepository::new("repo:fixture", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            vec![coverage("coverage:a"), coverage("coverage:a")],
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap_err();
        assert!(matches!(error, CliContractError::DuplicateCoverageId(_)));
    }

    #[test]
    fn repository_root_rejects_escape_and_windows_absolute_paths() {
        for invalid in ["../repo", "repo/../escape", "C:/repo", "/repo", "repo\\path"] {
            assert!(CliRepository::new("repo:fixture", invalid).is_err());
        }
        assert!(CliRepository::new("repo:fixture", "apps/web").is_ok());
    }
}
