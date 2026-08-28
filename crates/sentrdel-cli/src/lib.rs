#![forbid(unsafe_code)]
//! Stable R1 CLI process and JSON-output contracts.
//!
//! This crate layer owns only the cross-command envelope and exit semantics.
//! Command parsing, repository discovery, dependency injection, review/init/
//! guard behavior, and feature-specific output population remain later tasks.

use std::{error::Error, fmt, process::ExitCode};

use sentrdel_schema::{SCHEMA_V1, coverage::CoverageRecord};
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
/// Usage and internal failures are included so `--json` callers can receive a
/// structurally stable response even when a command cannot complete normally.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CliDecision {
    Clear,
    Blocking,
    Undecidable,
    UsageError,
    InternalFailure,
}

impl CliDecision {
    pub const fn exit_code(self) -> CliExitCode {
        match self {
            Self::Clear => CliExitCode::Success,
            Self::Blocking => CliExitCode::Blocking,
            Self::UsageError => CliExitCode::Usage,
            Self::Undecidable => CliExitCode::Incomplete,
            Self::InternalFailure => CliExitCode::Internal,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct CliFindingRef {
    pub finding_id: String,
    pub evidence_ids: Vec<String>,
}

impl CliFindingRef {
    pub fn new(
        finding_id: impl Into<String>,
        evidence_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self, CliContractError> {
        let finding_id = finding_id.into();
        validate_identifier("finding id", &finding_id)?;
        let mut evidence_ids = evidence_ids.into_iter().collect::<Vec<_>>();
        for evidence_id in &evidence_ids {
            validate_identifier("evidence id", evidence_id)?;
        }
        evidence_ids.sort();
        evidence_ids.dedup();
        Ok(Self {
            finding_id,
            evidence_ids,
        })
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
#[serde(deny_unknown_fields)]
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
        validate_identifier("diagnostic code", &value.code)?;
        if value.message.trim().is_empty()
            || value.message.len() > MAX_CLI_MESSAGE_BYTES
            || value.message.chars().any(char::is_control)
        {
            return Err(CliContractError::InvalidDiagnosticMessage);
        }
        Ok(value)
    }
}

/// Runtime-only metadata explicitly allowed to vary across otherwise identical
/// deterministic command results.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CliTiming {
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

impl CliTiming {
    pub fn validate(&self) -> Result<(), CliContractError> {
        if self
            .observed_at
            .as_deref()
            .is_some_and(|value| value.trim().is_empty() || value.chars().any(char::is_control))
        {
            return Err(CliContractError::InvalidObservedAt);
        }
        Ok(())
    }
}

/// Stable R1 JSON envelope shared by all public commands.
///
/// Input collections are normalized into deterministic order at construction.
/// The envelope is output-only; it deliberately does not implement Deserialize
/// and therefore cannot manufacture canonical Finding, Evidence, or policy
/// authority from untrusted JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
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

        findings.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
        reject_duplicate_finding_ids(&findings)?;

        coverage.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
        reject_duplicate_coverage_ids(&coverage)?;

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
            Self::InvalidIdentifier(field) => {
                write!(formatter, "CLI {field} must be bounded, non-blank text without controls")
            }
            Self::InvalidRepositoryRoot(root) => write!(
                formatter,
                "CLI repository root must be '.' or a canonical repository-relative path: {root:?}"
            ),
            Self::InvalidDiagnosticMessage => formatter.write_str(
                "CLI diagnostic message must be bounded, non-blank text without controls",
            ),
            Self::InvalidObservedAt => formatter.write_str(
                "CLI observed_at must be non-blank text without control characters when present",
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

fn is_canonical_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_CLI_ID_BYTES
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && path.as_bytes().get(1) != Some(&b':')
        && !path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
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

fn normalize_store_refs(
    store_refs: Option<Vec<String>>,
) -> Result<Option<Vec<String>>, CliContractError> {
    let Some(mut values) = store_refs else {
        return Ok(None);
    };
    for value in &values {
        validate_identifier("store reference", value)?;
    }
    values.sort();
    values.dedup();
    if values.is_empty() {
        Ok(None)
    } else {
        Ok(Some(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::coverage::CoverageState;
    use serde_json::Value;

    fn coverage(id: &str) -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: id.to_owned(),
            capability: "fixture".to_owned(),
            scope: ".".to_owned(),
            producer: None,
            provider_dimension: None,
            state: CoverageState::Covered,
            reason_code: None,
            details: None,
            input_digests: Vec::new(),
            observed_at: "2026-08-28T00:00:00Z".to_owned(),
        }
    }

    fn envelope(
        findings: Vec<CliFindingRef>,
        coverage: Vec<CoverageRecord>,
        diagnostics: Vec<CliDiagnostic>,
        store_refs: Option<Vec<String>>,
    ) -> CliEnvelope {
        CliEnvelope::new(
            CliCommand::Review,
            CliRepository::new("sha256:repo", ".").expect("repo"),
            CliDecision::Clear,
            findings,
            coverage,
            diagnostics,
            CliTiming {
                duration_ms: 12,
                observed_at: Some("2026-08-28T00:00:00Z".to_owned()),
            },
            store_refs,
        )
        .expect("envelope")
    }

    #[test]
    fn r1_exit_codes_are_numerically_frozen() {
        assert_eq!(CliExitCode::Success.as_u8(), 0);
        assert_eq!(CliExitCode::Blocking.as_u8(), 1);
        assert_eq!(CliExitCode::Usage.as_u8(), 2);
        assert_eq!(CliExitCode::Incomplete.as_u8(), 3);
        assert_eq!(CliExitCode::Internal.as_u8(), 4);
    }

    #[test]
    fn every_machine_decision_maps_to_the_binding_exit_semantics() {
        assert_eq!(CliDecision::Clear.exit_code(), CliExitCode::Success);
        assert_eq!(CliDecision::Blocking.exit_code(), CliExitCode::Blocking);
        assert_eq!(CliDecision::UsageError.exit_code(), CliExitCode::Usage);
        assert_eq!(CliDecision::Undecidable.exit_code(), CliExitCode::Incomplete);
        assert_eq!(
            CliDecision::InternalFailure.exit_code(),
            CliExitCode::Internal
        );
    }

    #[test]
    fn command_identifiers_are_stable() {
        let cases = [
            (CliCommand::Init, "\"init\""),
            (CliCommand::Review, "\"review\""),
            (CliCommand::Explain, "\"explain\""),
            (CliCommand::GuardMcp, "\"guard mcp\""),
            (
                CliCommand::GuardInstallGitHooks,
                "\"guard install-git-hooks\"",
            ),
        ];
        for (command, expected) in cases {
            assert_eq!(serde_json::to_string(&command).expect("serialize"), expected);
        }
    }

    #[test]
    fn json_envelope_has_binding_top_level_shape_and_optional_store_refs() {
        let value: Value = serde_json::from_str(
            envelope(Vec::new(), Vec::new(), Vec::new(), None)
                .to_json_line()
                .expect("json")
                .trim_end(),
        )
        .expect("parse");
        let object = value.as_object().expect("object");
        assert_eq!(
            object.keys().cloned().collect::<Vec<_>>(),
            vec![
                "command",
                "coverage",
                "decision",
                "diagnostics",
                "findings",
                "repository",
                "schema_version",
                "timing",
            ]
        );
        assert!(!object.contains_key("store_refs"));
        assert_eq!(object["schema_version"], SCHEMA_V1);
        assert_eq!(object["decision"], "CLEAR");
    }

    #[test]
    fn input_order_does_not_change_machine_json() {
        let finding_a = CliFindingRef::new(
            "finding:a",
            vec!["evidence:2".to_owned(), "evidence:1".to_owned()],
        )
        .expect("finding");
        let finding_b = CliFindingRef::new("finding:b", vec!["evidence:3".to_owned()])
            .expect("finding");
        let diagnostic_a = CliDiagnostic::new(
            "A",
            CliDiagnosticLevel::Warning,
            "first diagnostic",
        )
        .expect("diagnostic");
        let diagnostic_b = CliDiagnostic::new(
            "B",
            CliDiagnosticLevel::Info,
            "second diagnostic",
        )
        .expect("diagnostic");

        let forward = envelope(
            vec![finding_b.clone(), finding_a.clone()],
            vec![coverage("coverage:b"), coverage("coverage:a")],
            vec![diagnostic_b.clone(), diagnostic_a.clone()],
            Some(vec!["store:b".to_owned(), "store:a".to_owned()]),
        );
        let reverse = envelope(
            vec![finding_a, finding_b],
            vec![coverage("coverage:a"), coverage("coverage:b")],
            vec![diagnostic_a, diagnostic_b],
            Some(vec!["store:a".to_owned(), "store:b".to_owned()]),
        );

        assert_eq!(
            forward.to_json_line().expect("forward"),
            reverse.to_json_line().expect("reverse")
        );
    }

    #[test]
    fn envelope_rejects_duplicate_canonical_references() {
        let finding = CliFindingRef::new("finding:a", Vec::<String>::new()).expect("finding");
        assert!(matches!(
            CliEnvelope::new(
                CliCommand::Review,
                CliRepository::new("sha256:repo", ".").expect("repo"),
                CliDecision::Clear,
                vec![finding.clone(), finding],
                Vec::new(),
                Vec::new(),
                CliTiming::default(),
                None,
            ),
            Err(CliContractError::DuplicateFindingId(_))
        ));

        assert!(matches!(
            envelope(
                Vec::new(),
                vec![coverage("coverage:a"), coverage("coverage:a")],
                Vec::new(),
                None,
            ),
            _
        ));
    }

    #[test]
    fn absolute_or_noncanonical_repository_roots_are_rejected() {
        for root in [
            "/home/user/repo",
            "C:/repo",
            "../repo",
            "repo/../other",
            "repo\\src",
        ] {
            assert!(matches!(
                CliRepository::new("sha256:repo", root),
                Err(CliContractError::InvalidRepositoryRoot(_))
            ));
        }
        assert!(CliRepository::new("sha256:repo", ".").is_ok());
        assert!(CliRepository::new("sha256:repo", "packages/api").is_ok());
    }

    #[test]
    fn untrusted_identifiers_and_diagnostics_are_bounded() {
        assert!(CliFindingRef::new("   ", Vec::<String>::new()).is_err());
        assert!(CliFindingRef::new("finding:a", vec!["bad\nid".to_owned()]).is_err());
        assert!(CliDiagnostic::new(
            "D001",
            CliDiagnosticLevel::Error,
            "bad\nmessage"
        )
        .is_err());
    }
}
