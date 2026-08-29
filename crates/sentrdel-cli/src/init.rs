//! `sentrdel init` output assembly.
//!
//! The init command reports bounded project inventory and explicit coverage. It
//! does not turn detection into security posture, execute target tooling, open
//! provider connections, access credentials, or perform network activity.

use std::fmt::{self, Write as _};

use sentrdel_review::pack_registry::PackCoverageDimension;
use sentrdel_review::profile::{
    ProjectCoverageEntry, ProjectCoverageSubjectKind, ProjectProfileSnapshot,
};
use sentrdel_schema::coverage::{CoverageRecord, ProviderCoverageDimension};

use crate::{
    CliCommand, CliContractError, CliDecision, CliDiagnostic, CliDiagnosticLevel, CliEnvelope,
    CliRepository, CliTiming,
};

#[derive(Debug)]
pub enum InitOutputError {
    Contract(CliContractError),
    Json(serde_json::Error),
    Format(fmt::Error),
}

impl fmt::Display for InitOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "init CLI contract failed: {error}"),
            Self::Json(error) => write!(formatter, "init JSON serialization failed: {error}"),
            Self::Format(error) => {
                write!(formatter, "init human output formatting failed: {error}")
            }
        }
    }
}

impl std::error::Error for InitOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Format(error) => Some(error),
        }
    }
}

impl From<CliContractError> for InitOutputError {
    fn from(value: CliContractError) -> Self {
        Self::Contract(value)
    }
}

impl From<serde_json::Error> for InitOutputError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<fmt::Error> for InitOutputError {
    fn from(value: fmt::Error) -> Self {
        Self::Format(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitOutput {
    pub envelope: CliEnvelope,
    pub human: String,
}

impl InitOutput {
    pub fn json_line(&self) -> Result<String, serde_json::Error> {
        self.envelope.to_json_line()
    }
}

pub fn build_init_output(
    snapshot: &ProjectProfileSnapshot,
    repository_root: &str,
    duration_ms: u64,
) -> Result<InitOutput, InitOutputError> {
    let profile = &snapshot.profile;
    let repository = CliRepository::new(&profile.repository_id, repository_root)?;
    let coverage = snapshot
        .coverage
        .entries
        .iter()
        .map(|entry| {
            coverage_record(
                entry,
                &profile.repository_root_digest,
                &profile.refreshed_at,
            )
        })
        .collect();
    let diagnostics = inventory_diagnostics(snapshot)?;
    let envelope = CliEnvelope::new(
        CliCommand::Init,
        repository,
        CliDecision::Allow,
        Vec::new(),
        coverage,
        diagnostics,
        CliTiming {
            duration_ms,
            observed_at: Some(profile.refreshed_at.clone()),
        },
        None,
    )?;
    let human = render_human(snapshot, repository_root)?;
    Ok(InitOutput { envelope, human })
}

fn coverage_record(
    entry: &ProjectCoverageEntry,
    repository_root_digest: &str,
    observed_at: &str,
) -> CoverageRecord {
    let kind = subject_kind(entry.key.subject_kind);
    let dimension = dimension_name(entry.key.dimension);
    CoverageRecord {
        schema_version: sentrdel_schema::SCHEMA_V1.to_owned(),
        coverage_id: format!(
            "coverage:init:{kind}:{}:{}",
            entry.key.subject_id,
            dimension.to_ascii_lowercase()
        ),
        capability: format!("{kind}.{}.{}", entry.key.subject_id, dimension),
        scope: ".".to_owned(),
        producer: None,
        provider_dimension: provider_dimension(entry.key.dimension),
        state: entry.state.clone(),
        reason_code: entry.reason_code.clone(),
        details: None,
        input_digests: vec![repository_root_digest.to_owned()],
        observed_at: observed_at.to_owned(),
    }
}

fn inventory_diagnostics(
    snapshot: &ProjectProfileSnapshot,
) -> Result<Vec<CliDiagnostic>, CliContractError> {
    let profile = &snapshot.profile;
    let mut diagnostics = Vec::new();
    push_inventory(
        &mut diagnostics,
        "INIT_LANGUAGES",
        "Detected languages",
        &profile.languages,
    )?;
    push_inventory(
        &mut diagnostics,
        "INIT_ECOSYSTEMS",
        "Detected package ecosystems",
        &profile.package_ecosystems,
    )?;
    push_inventory(
        &mut diagnostics,
        "INIT_CI",
        "Detected CI systems",
        &profile.ci_systems,
    )?;
    push_inventory(
        &mut diagnostics,
        "INIT_MCP",
        "Detected MCP configurations",
        &profile.mcp_configurations,
    )?;
    push_inventory(
        &mut diagnostics,
        "INIT_PROVIDERS",
        "Detected providers",
        &profile
            .detected_providers
            .iter()
            .map(|provider| provider.provider_id.clone())
            .collect::<Vec<_>>(),
    )?;
    push_inventory(
        &mut diagnostics,
        "INIT_FRAMEWORKS",
        "Detected frameworks",
        &profile
            .detected_frameworks
            .iter()
            .map(|framework| framework.framework_id.clone())
            .collect::<Vec<_>>(),
    )?;
    push_inventory(
        &mut diagnostics,
        "INIT_SECURITY_PACKS",
        "Available security packs",
        &profile.security_packs,
    )?;

    for entry in snapshot
        .coverage
        .entries
        .iter()
        .filter(|entry| entry.is_gap())
    {
        diagnostics.push(CliDiagnostic::new(
            format!(
                "INIT_COVERAGE_{}_{}",
                subject_kind(entry.key.subject_kind).to_ascii_uppercase(),
                dimension_name(entry.key.dimension)
            ),
            CliDiagnosticLevel::Warning,
            format!(
                "{} {} coverage is {:?}: {}",
                subject_kind(entry.key.subject_kind),
                entry.key.subject_id,
                entry.state,
                entry.reason_code.as_deref().unwrap_or("NO_REASON_CODE")
            ),
        )?);
    }
    Ok(diagnostics)
}

fn push_inventory(
    diagnostics: &mut Vec<CliDiagnostic>,
    code: &str,
    label: &str,
    values: &[String],
) -> Result<(), CliContractError> {
    let rendered = if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    };
    diagnostics.push(CliDiagnostic::new(
        code,
        CliDiagnosticLevel::Info,
        format!("{label}: {rendered}"),
    )?);
    Ok(())
}

fn render_human(
    snapshot: &ProjectProfileSnapshot,
    repository_root: &str,
) -> Result<String, fmt::Error> {
    let profile = &snapshot.profile;
    let mut output = String::new();
    writeln!(output, "Sentrdel init")?;
    writeln!(
        output,
        "Repository: {} ({repository_root})",
        profile.repository_id
    )?;
    writeln!(output, "Languages: {}", human_list(&profile.languages))?;
    writeln!(
        output,
        "Package ecosystems: {}",
        human_list(&profile.package_ecosystems)
    )?;
    writeln!(output, "CI: {}", human_list(&profile.ci_systems))?;
    writeln!(
        output,
        "MCP configurations: {}",
        human_list(&profile.mcp_configurations)
    )?;
    writeln!(
        output,
        "Providers: {}",
        human_list(
            &profile
                .detected_providers
                .iter()
                .map(|provider| provider.provider_id.clone())
                .collect::<Vec<_>>()
        )
    )?;
    writeln!(
        output,
        "Frameworks: {}",
        human_list(
            &profile
                .detected_frameworks
                .iter()
                .map(|framework| framework.framework_id.clone())
                .collect::<Vec<_>>()
        )
    )?;
    writeln!(
        output,
        "Security packs: {}",
        human_list(&profile.security_packs)
    )?;
    writeln!(output, "Coverage:")?;
    for entry in &snapshot.coverage.entries {
        writeln!(
            output,
            "- {} {} / {}: {:?}{}",
            subject_kind(entry.key.subject_kind),
            entry.key.subject_id,
            dimension_name(entry.key.dimension),
            entry.state,
            entry
                .reason_code
                .as_ref()
                .map(|reason| format!(" ({reason})"))
                .unwrap_or_default()
        )?;
    }
    if snapshot.coverage.gap_count > 0 {
        writeln!(
            output,
            "Warning: {} coverage dimension(s) are partial, unavailable, or unsupported.",
            snapshot.coverage.gap_count
        )?;
    }
    Ok(output)
}

fn human_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

const fn subject_kind(kind: ProjectCoverageSubjectKind) -> &'static str {
    match kind {
        ProjectCoverageSubjectKind::Provider => "provider",
        ProjectCoverageSubjectKind::Framework => "framework",
    }
}

const fn dimension_name(dimension: PackCoverageDimension) -> &'static str {
    dimension.as_str()
}

const fn provider_dimension(dimension: PackCoverageDimension) -> Option<ProviderCoverageDimension> {
    match dimension {
        PackCoverageDimension::Detection => Some(ProviderCoverageDimension::Detection),
        PackCoverageDimension::StaticPosture => Some(ProviderCoverageDimension::StaticPosture),
        PackCoverageDimension::LivePosture => {
            Some(ProviderCoverageDimension::CredentialedLivePosture)
        }
        PackCoverageDimension::BusinessLogic => {
            Some(ProviderCoverageDimension::CrossLayerBusinessLogic)
        }
        PackCoverageDimension::Runtime => None,
    }
}
