//! Deterministic ProjectProfile assembly and honest project coverage matrix.
//!
//! This layer combines already-bounded inventory signals. It does not execute
//! target code, open provider connections, read credentials, or turn detection
//! into a security verdict. A registered pack is capability metadata only; a
//! dimension remains unavailable until an analysis producer actually runs.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;
use sentrdel_schema::project::{DetectedFramework, DetectedProvider, PackStatus, ProjectProfile};
use sentrdel_schema::SCHEMA_V1;

use crate::config_detection::CiMcpConfigDetection;
use crate::pack_registry::{PackCoverageDimension, SecurityPackRegistry};
use crate::project_detection::LanguageEcosystemDetection;
use crate::stack_detection::{DetectedStack, StackDetectionResult};
use crate::supabase_detection::SupabaseDetection;

const PATH_SIGNAL_CONFIDENCE: &str = "PATH_SIGNAL";
const PACK_REGISTERED_NOT_RUN: &str = "PACK_REGISTERED_NOT_RUN";
const R1_POSTURE_NOT_IMPLEMENTED: &str = "R1_POSTURE_NOT_IMPLEMENTED";
const SUPABASE_STATIC_POSTURE_NOT_IMPLEMENTED: &str = "SUPABASE_STATIC_POSTURE_NOT_IMPLEMENTED";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProjectCoverageSubjectKind {
    Provider,
    Framework,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProjectCoverageKey {
    pub subject_kind: ProjectCoverageSubjectKind,
    pub subject_id: String,
    pub dimension: PackCoverageDimension,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCoverageEntry {
    pub key: ProjectCoverageKey,
    pub state: CoverageState,
    pub reason_code: Option<String>,
}

impl ProjectCoverageEntry {
    #[must_use]
    pub fn is_gap(&self) -> bool {
        self.state != CoverageState::Covered
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectCoverageMatrix {
    pub entries: Vec<ProjectCoverageEntry>,
    pub gap_count: usize,
}

impl ProjectCoverageMatrix {
    #[must_use]
    pub fn get(
        &self,
        subject_kind: ProjectCoverageSubjectKind,
        subject_id: &str,
        dimension: PackCoverageDimension,
    ) -> Option<&ProjectCoverageEntry> {
        self.entries.iter().find(|entry| {
            entry.key.subject_kind == subject_kind
                && entry.key.subject_id == subject_id
                && entry.key.dimension == dimension
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectProfileSnapshot {
    pub profile: ProjectProfile,
    pub coverage: ProjectCoverageMatrix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectProfileError {
    EmptyRepositoryId,
    EmptyRepositoryRootDigest,
    EmptyTimestamp(&'static str),
}

impl fmt::Display for ProjectProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRepositoryId => formatter.write_str("project profile repository id must not be empty"),
            Self::EmptyRepositoryRootDigest => {
                formatter.write_str("project profile repository root digest must not be empty")
            }
            Self::EmptyTimestamp(field) => write!(formatter, "project profile {field} must not be empty"),
        }
    }
}

impl Error for ProjectProfileError {}

#[allow(clippy::too_many_arguments)]
pub fn build_project_profile_snapshot(
    repository_id: &str,
    repository_root_digest: &str,
    language_ecosystems: &LanguageEcosystemDetection,
    ci_mcp: &CiMcpConfigDetection,
    stacks: &StackDetectionResult,
    supabase: &SupabaseDetection,
    packs: &SecurityPackRegistry,
    created_at: &str,
    refreshed_at: &str,
) -> Result<ProjectProfileSnapshot, ProjectProfileError> {
    if repository_id.trim().is_empty() {
        return Err(ProjectProfileError::EmptyRepositoryId);
    }
    if repository_root_digest.trim().is_empty() {
        return Err(ProjectProfileError::EmptyRepositoryRootDigest);
    }
    if created_at.trim().is_empty() {
        return Err(ProjectProfileError::EmptyTimestamp("created_at"));
    }
    if refreshed_at.trim().is_empty() {
        return Err(ProjectProfileError::EmptyTimestamp("refreshed_at"));
    }

    let mut providers: BTreeMap<String, DetectedProvider> = stacks
        .providers
        .iter()
        .map(|stack| {
            (
                stack.id.clone(),
                DetectedProvider {
                    provider_id: stack.id.clone(),
                    evidence_ids: Vec::new(),
                    detection_confidence: PATH_SIGNAL_CONFIDENCE.to_owned(),
                    pack_status: PackStatus::NotInstalled,
                },
            )
        })
        .collect();

    if supabase.detected {
        providers
            .entry("supabase".to_owned())
            .and_modify(|provider| provider.pack_status = PackStatus::NotImplemented)
            .or_insert_with(|| DetectedProvider {
                provider_id: "supabase".to_owned(),
                evidence_ids: Vec::new(),
                detection_confidence: PATH_SIGNAL_CONFIDENCE.to_owned(),
                pack_status: PackStatus::NotImplemented,
            });
    }

    let frameworks: Vec<DetectedFramework> = stacks
        .frameworks
        .iter()
        .map(|stack| DetectedFramework {
            framework_id: stack.id.clone(),
            evidence_ids: Vec::new(),
            detection_confidence: PATH_SIGNAL_CONFIDENCE.to_owned(),
        })
        .collect();

    let provider_ids: BTreeSet<&str> = providers.keys().map(String::as_str).collect();
    let framework_ids: BTreeSet<&str> = frameworks
        .iter()
        .map(|framework| framework.framework_id.as_str())
        .collect();
    let security_packs: Vec<String> = packs
        .iter()
        .filter_map(|(pack_id, pack)| {
            let subject = pack.manifest().provider_or_framework.as_str();
            (provider_ids.contains(subject) || framework_ids.contains(subject))
                .then(|| pack_id.to_owned())
        })
        .collect();

    let profile = ProjectProfile {
        schema_version: SCHEMA_V1.to_owned(),
        repository_id: repository_id.to_owned(),
        repository_root_digest: repository_root_digest.to_owned(),
        languages: language_ecosystems.languages.clone(),
        package_ecosystems: language_ecosystems.package_ecosystems.clone(),
        ci_systems: ci_mcp.ci_systems.clone(),
        mcp_configurations: ci_mcp.mcp_configurations.clone(),
        detected_providers: providers.into_values().collect(),
        detected_frameworks: frameworks,
        security_packs,
        created_at: created_at.to_owned(),
        refreshed_at: refreshed_at.to_owned(),
    };

    let coverage = build_project_coverage_matrix(&profile, stacks, supabase, packs);
    Ok(ProjectProfileSnapshot { profile, coverage })
}

fn build_project_coverage_matrix(
    profile: &ProjectProfile,
    stacks: &StackDetectionResult,
    supabase: &SupabaseDetection,
    packs: &SecurityPackRegistry,
) -> ProjectCoverageMatrix {
    let pack_dimensions: BTreeMap<&str, BTreeSet<PackCoverageDimension>> = packs
        .iter()
        .fold(BTreeMap::new(), |mut by_subject, (_, pack)| {
            by_subject
                .entry(pack.manifest().provider_or_framework.as_str())
                .or_default()
                .extend(pack.coverage_dimensions().iter().copied());
            by_subject
        });

    let mut entries = Vec::new();
    for provider in &profile.detected_providers {
        push_subject_dimensions(
            &mut entries,
            ProjectCoverageSubjectKind::Provider,
            &provider.provider_id,
            pack_dimensions.get(provider.provider_id.as_str()),
            supabase.detected && provider.provider_id == "supabase",
        );
    }
    for framework in &profile.detected_frameworks {
        push_subject_dimensions(
            &mut entries,
            ProjectCoverageSubjectKind::Framework,
            &framework.framework_id,
            pack_dimensions.get(framework.framework_id.as_str()),
            false,
        );
    }

    // Preserve the T063 detection result as the bounded source of generic stack
    // presence. This assertion keeps profile assembly from silently inventing a
    // generic provider/framework that was not detected.
    debug_assert!(profile.detected_providers.iter().all(|provider| {
        provider.provider_id == "supabase"
            || stack_present(&stacks.providers, &provider.provider_id)
    }));
    debug_assert!(profile
        .detected_frameworks
        .iter()
        .all(|framework| stack_present(&stacks.frameworks, &framework.framework_id)));

    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let gap_count = entries.iter().filter(|entry| entry.is_gap()).count();
    ProjectCoverageMatrix { entries, gap_count }
}

fn stack_present(stacks: &[DetectedStack], id: &str) -> bool {
    stacks.iter().any(|stack| stack.id == id)
}

fn push_subject_dimensions(
    entries: &mut Vec<ProjectCoverageEntry>,
    subject_kind: ProjectCoverageSubjectKind,
    subject_id: &str,
    declared_dimensions: Option<&BTreeSet<PackCoverageDimension>>,
    is_supabase: bool,
) {
    for dimension in [
        PackCoverageDimension::Detection,
        PackCoverageDimension::StaticPosture,
        PackCoverageDimension::LivePosture,
        PackCoverageDimension::BusinessLogic,
        PackCoverageDimension::Runtime,
    ] {
        let (state, reason_code) = match dimension {
            PackCoverageDimension::Detection => (CoverageState::Covered, None),
            PackCoverageDimension::StaticPosture if is_supabase => (
                CoverageState::Partial,
                Some(SUPABASE_STATIC_POSTURE_NOT_IMPLEMENTED.to_owned()),
            ),
            _ if declared_dimensions.is_some_and(|declared| declared.contains(&dimension)) => (
                CoverageState::Unavailable,
                Some(PACK_REGISTERED_NOT_RUN.to_owned()),
            ),
            _ => (
                CoverageState::Unsupported,
                Some(R1_POSTURE_NOT_IMPLEMENTED.to_owned()),
            ),
        };
        entries.push(ProjectCoverageEntry {
            key: ProjectCoverageKey {
                subject_kind,
                subject_id: subject_id.to_owned(),
                dimension,
            },
            state,
            reason_code,
        });
    }
}
