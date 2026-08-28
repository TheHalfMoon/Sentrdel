//! Bounded static GitHub Actions observations for changed workflow files.
//!
//! Workflow bytes are untrusted data. This producer never executes YAML, actions,
//! shells, expressions, target repository code, package managers, or network calls.

use crate::view::NormalizedRepoPath;
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_WORKFLOW_BYTES: usize = 512 * 1024;
const PRODUCER_ID: &str = "sentrdel.github-actions";
const PRODUCER_VERSION: &str = "1";

const WRITE_PERMISSIONS: &[&str] = &[
    "actions",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "issues",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
];

#[derive(Debug)]
pub enum ActionsScanError {
    NotWorkflowPath,
    DocumentTooLarge { bytes: usize, max: usize },
    NonUtf8Source,
    EmptyCapturedAt,
    Evidence(EvidenceValidationError),
}

impl fmt::Display for ActionsScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWorkflowPath => formatter.write_str("path is not a GitHub Actions workflow"),
            Self::DocumentTooLarge { bytes, max } => {
                write!(formatter, "workflow size {bytes} exceeds scan cap {max}")
            }
            Self::NonUtf8Source => formatter.write_str("workflow source must be valid UTF-8"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::Evidence(error) => {
                write!(formatter, "cannot seal GitHub Actions evidence: {error}")
            }
        }
    }
}

impl std::error::Error for ActionsScanError {}

impl From<EvidenceValidationError> for ActionsScanError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Observation {
    line: u64,
    rule_id: &'static str,
    observation: &'static str,
}

pub fn scan_changed_workflow(
    path: &NormalizedRepoPath,
    before: Option<&[u8]>,
    after: &[u8],
    captured_at: &str,
) -> Result<Vec<Evidence>, ActionsScanError> {
    validate_workflow_path(path)?;
    let after = bounded_utf8(after)?;
    let before = before.map(bounded_utf8).transpose()?;
    if captured_at.trim().is_empty() {
        return Err(ActionsScanError::EmptyCapturedAt);
    }

    let before_features = before.map(scan_features).unwrap_or_default();
    let after_features = scan_features(after);
    let mut observations = BTreeSet::new();

    for permission in after_features
        .write_permissions
        .difference(&before_features.write_permissions)
    {
        observations.insert(Observation {
            line: after_features
                .write_permission_lines
                .get(permission)
                .copied()
                .unwrap_or(1),
            rule_id: "gha.permission-widening",
            observation: "Changed workflow introduces a GitHub Actions write permission",
        });
    }
    if after_features.write_all && !before_features.write_all {
        observations.insert(Observation {
            line: after_features.write_all_line.unwrap_or(1),
            rule_id: "gha.permission-widening",
            observation: "Changed workflow introduces permissions: write-all",
        });
    }
    if after_features.id_token_write && !before_features.id_token_write {
        observations.insert(Observation {
            line: after_features.id_token_line.unwrap_or(1),
            rule_id: "gha.oidc-id-token-write",
            observation: "Changed workflow introduces id-token: write OIDC authority",
        });
    }
    if after_features.pull_request_target && !before_features.pull_request_target {
        observations.insert(Observation {
            line: after_features.pull_request_target_line.unwrap_or(1),
            rule_id: "gha.pull-request-target",
            observation: "Changed workflow introduces pull_request_target execution context",
        });
    }
    if after_features.pull_request && after_features.secret_expression {
        observations.insert(Observation {
            line: after_features.secret_expression_line.unwrap_or(1),
            rule_id: "gha.secret-in-untrusted-pr-path",
            observation: "Pull-request workflow references GitHub secrets",
        });
    }
    for line in &after_features.untrusted_shell_lines {
        observations.insert(Observation {
            line: *line,
            rule_id: "gha.untrusted-expression-shell",
            observation: "Workflow shell command directly interpolates pull-request controlled expression data",
        });
    }
    for line in &after_features.mutable_action_lines {
        observations.insert(Observation {
            line: *line,
            rule_id: "gha.mutable-action-ref",
            observation: "Workflow uses a non-SHA mutable external action reference",
        });
    }
    if after_features.self_hosted && !before_features.self_hosted {
        observations.insert(Observation {
            line: after_features.self_hosted_line.unwrap_or(1),
            rule_id: "gha.self-hosted-runner-change",
            observation: "Changed workflow introduces a self-hosted runner",
        });
    }
    if (after_features.pull_request_target || after_features.workflow_run)
        && !after_features.trust_handoff_lines.is_empty()
    {
        for line in &after_features.trust_handoff_lines {
            observations.insert(Observation {
                line: *line,
                rule_id: "gha.trust-sensitive-artifact-cache-handoff",
                observation: "Privileged workflow context consumes artifact or cache state across a trust boundary",
            });
        }
    }

    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    observations
        .into_iter()
        .map(|item| {
            let mut attributes = BTreeMap::new();
            attributes.insert("rule_id".to_owned(), Value::String(item.rule_id.to_owned()));
            attributes.insert(
                "workflow_path".to_owned(),
                Value::String(path.as_str().to_owned()),
            );
            authority
                .seal(EvidenceClaim {
                    schema_version: SCHEMA_V1.to_owned(),
                    input_digests: Vec::new(),
                    observation: item.observation.to_owned(),
                    security_interpretation: None,
                    category: "github_actions".to_owned(),
                    epistemic_class: EpistemicClass::Fact,
                    confidence_band: None,
                    subjects: vec![EvidenceSubject {
                        kind: "repository_path".to_owned(),
                        id: path.as_str().to_owned(),
                    }],
                    locations: vec![EvidenceLocation {
                        repo_relative_path: path.as_str().to_owned(),
                        start_line: Some(item.line),
                        start_column: None,
                        end_line: Some(item.line),
                        end_column: None,
                        symbol: None,
                        content_digest: None,
                    }],
                    attributes,
                    reproduction: None,
                    captured_at: captured_at.to_owned(),
                })
                .map_err(ActionsScanError::Evidence)
        })
        .collect()
}

fn validate_workflow_path(path: &NormalizedRepoPath) -> Result<(), ActionsScanError> {
    let value = path.as_str();
    let extension_ok = value.ends_with(".yml") || value.ends_with(".yaml");
    if !extension_ok || !value.starts_with(".github/workflows/") {
        return Err(ActionsScanError::NotWorkflowPath);
    }
    Ok(())
}

fn bounded_utf8(bytes: &[u8]) -> Result<&str, ActionsScanError> {
    if bytes.len() > MAX_WORKFLOW_BYTES {
        return Err(ActionsScanError::DocumentTooLarge {
            bytes: bytes.len(),
            max: MAX_WORKFLOW_BYTES,
        });
    }
    std::str::from_utf8(bytes).map_err(|_| ActionsScanError::NonUtf8Source)
}

#[derive(Default)]
struct Features {
    pull_request: bool,
    pull_request_target: bool,
    pull_request_target_line: Option<u64>,
    workflow_run: bool,
    write_all: bool,
    write_all_line: Option<u64>,
    write_permissions: BTreeSet<String>,
    write_permission_lines: BTreeMap<String, u64>,
    id_token_write: bool,
    id_token_line: Option<u64>,
    secret_expression: bool,
    secret_expression_line: Option<u64>,
    self_hosted: bool,
    self_hosted_line: Option<u64>,
    untrusted_shell_lines: BTreeSet<u64>,
    mutable_action_lines: BTreeSet<u64>,
    trust_handoff_lines: BTreeSet<u64>,
}

fn scan_features(source: &str) -> Features {
    let mut out = Features::default();
    let mut in_run_block: Option<usize> = None;

    for (index, raw) in source.lines().enumerate() {
        let line_number = u64::try_from(index + 1).unwrap_or(u64::MAX);
        let trimmed = raw.trim();
        let step_mapping = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        let indent = raw.len().saturating_sub(raw.trim_start().len());
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with("pull_request_target:") || trimmed == "pull_request_target" {
            out.pull_request_target = true;
            out.pull_request_target_line.get_or_insert(line_number);
        } else if trimmed.starts_with("pull_request:") || trimmed == "pull_request" {
            out.pull_request = true;
        } else if trimmed.starts_with("workflow_run:") || trimmed == "workflow_run" {
            out.workflow_run = true;
        }

        if trimmed == "permissions: write-all"
            || trimmed == "permissions: 'write-all'"
            || trimmed == "permissions: \"write-all\""
        {
            out.write_all = true;
            out.write_all_line.get_or_insert(line_number);
        }

        if let Some((name, value)) = split_mapping(trimmed) {
            if value == "write" || value == "'write'" || value == "\"write\"" {
                if name == "id-token" {
                    out.id_token_write = true;
                    out.id_token_line.get_or_insert(line_number);
                } else if WRITE_PERMISSIONS.contains(&name) {
                    out.write_permissions.insert(name.to_owned());
                    out.write_permission_lines
                        .entry(name.to_owned())
                        .or_insert(line_number);
                }
            }
        }

        if trimmed.contains("${{ secrets.") {
            out.secret_expression = true;
            out.secret_expression_line.get_or_insert(line_number);
        }

        if trimmed.starts_with("runs-on:") && contains_token(trimmed, "self-hosted") {
            out.self_hosted = true;
            out.self_hosted_line.get_or_insert(line_number);
        }

        if let Some(value) = step_mapping.strip_prefix("uses:").map(str::trim) {
            if is_external_action(value) && !is_full_sha_pinned(value) {
                out.mutable_action_lines.insert(line_number);
            }
            let normalized = value.to_ascii_lowercase();
            if normalized.starts_with("actions/download-artifact@")
                || normalized.starts_with("actions/cache@")
                || normalized.starts_with("actions/cache/restore@")
            {
                out.trust_handoff_lines.insert(line_number);
            }
        }

        if let Some(value) = step_mapping.strip_prefix("run:").map(str::trim) {
            if value == "|" || value == ">" || value == "|-" || value == ">-" {
                in_run_block = Some(indent);
            } else {
                in_run_block = None;
                if contains_untrusted_expression(value) {
                    out.untrusted_shell_lines.insert(line_number);
                }
            }
        } else if let Some(run_indent) = in_run_block {
            if indent > run_indent {
                if contains_untrusted_expression(trimmed) {
                    out.untrusted_shell_lines.insert(line_number);
                }
            } else {
                in_run_block = None;
            }
        }
    }
    out
}

fn split_mapping(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim(), value.trim()))
}

fn contains_token(line: &str, token: &str) -> bool {
    line.split(|ch: char| ch.is_ascii_whitespace() || matches!(ch, '[' | ']' | ',' | '\'' | '"'))
        .any(|part| part == token)
}

fn contains_untrusted_expression(value: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "${{ github.event.pull_request.",
        "${{ github.event.issue.",
        "${{ github.event.comment.",
        "${{ github.head_ref",
    ];
    PREFIXES.iter().any(|prefix| value.contains(prefix))
}

fn is_external_action(value: &str) -> bool {
    if value.starts_with("./") || value.starts_with("docker://") {
        return false;
    }
    let Some((repository, _reference)) = value.split_once('@') else {
        return false;
    };
    repository.split('/').count() >= 2
}

fn is_full_sha_pinned(value: &str) -> bool {
    let Some((_repository, reference)) = value.split_once('@') else {
        return false;
    };
    reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit())
}
