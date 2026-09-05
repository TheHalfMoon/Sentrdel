//! Bounded correlation between canonical Supabase R2 provider output and R3 IR.
//!
//! This module consumes only already-validated `SupabaseR2ProviderOutput`.
//! R2 Evidence and Coverage remain the source of truth: their identities,
//! subjects, locations, input digests, and coverage records are copied without
//! reinterpretation. The result is supporting context only; it cannot create
//! Findings, prove hosted/live state, execute target code, or access Supabase.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageRecord;
use sentrdel_schema::evidence::{EvidenceLocation, EvidenceSubject};

use crate::business_logic::model::{ProviderAuthorityClass, ProviderClientAuthority, ResourceRef};
use crate::supabase_integration::SupabaseR2ProviderOutput;

pub const R2_SUPPORT_CREATES_FINDINGS: bool = false;
pub const R2_SUPPORT_PROVES_LIVE_POSTURE: bool = false;
pub const R2_SUPPORT_PROVIDER_NETWORK_ALLOWED: bool = false;
pub const R2_SUPPORT_TARGET_EXECUTION_ALLOWED: bool = false;
pub const R2_SUPPORT_CONFIDENCE_GRANTS_AUTHORITY: bool = false;

pub const DEFAULT_MAX_R2_SUPPORT_EVIDENCE: usize = 4_096;
pub const DEFAULT_MAX_R2_SUPPORT_COVERAGE: usize = 1_024;
pub const DEFAULT_MAX_R2_SUPPORT_RESOURCES: usize = 4_096;
pub const DEFAULT_MAX_R2_SUPPORT_CLIENTS: usize = 4_096;
pub const DEFAULT_MAX_R2_SUPPORT_MATCHES: usize = 8_192;
pub const DEFAULT_MAX_R2_SUPPORT_DIAGNOSTICS: usize = 1_024;

const RLS_POSTURE: &str = "supabase_rls_posture";
const POLICY_POSTURE: &str = "supabase_policy_posture";
const STORAGE_POLICY_POSTURE: &str = "supabase_storage_policy_posture";
const API_ROLE_GRANT: &str = "supabase_api_role_grant";
const ELEVATED_KEY_CLIENT_BOUNDARY: &str = "supabase_elevated_key_client_boundary";
const FUNCTION_SECURITY_MODE: &str = "supabase_function_security_mode";
const FUNCTION_SEARCH_PATH: &str = "supabase_function_search_path";
const EDGE_FUNCTION_AUTH_POSTURE: &str = "supabase_edge_function_auth_posture";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct R2SupportLimits {
    pub max_evidence: usize,
    pub max_coverage: usize,
    pub max_resources: usize,
    pub max_clients: usize,
    pub max_matches: usize,
    pub max_diagnostics: usize,
}

impl Default for R2SupportLimits {
    fn default() -> Self {
        Self {
            max_evidence: DEFAULT_MAX_R2_SUPPORT_EVIDENCE,
            max_coverage: DEFAULT_MAX_R2_SUPPORT_COVERAGE,
            max_resources: DEFAULT_MAX_R2_SUPPORT_RESOURCES,
            max_clients: DEFAULT_MAX_R2_SUPPORT_CLIENTS,
            max_matches: DEFAULT_MAX_R2_SUPPORT_MATCHES,
            max_diagnostics: DEFAULT_MAX_R2_SUPPORT_DIAGNOSTICS,
        }
    }
}

impl R2SupportLimits {
    fn validate(self) -> Result<Self, R2SupportError> {
        if self.max_evidence == 0
            || self.max_coverage == 0
            || self.max_resources == 0
            || self.max_clients == 0
            || self.max_matches == 0
            || self.max_diagnostics == 0
        {
            return Err(R2SupportError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum R2SupportKind {
    RlsPosture,
    PolicyPosture,
    ApiRoleGrant,
    KeyClientBoundary,
    StaticContext,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum R2SupportTargetKind {
    ResourceSubject,
    ProviderClient,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2SupportMatch {
    target_kind: R2SupportTargetKind,
    target_id: String,
    support_kind: R2SupportKind,
    evidence_id: String,
    producer_id: String,
    category: String,
    subjects: Vec<EvidenceSubject>,
    locations: Vec<EvidenceLocation>,
    input_digests: Vec<String>,
}

impl R2SupportMatch {
    #[must_use]
    pub const fn target_kind(&self) -> R2SupportTargetKind {
        self.target_kind
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub const fn support_kind(&self) -> R2SupportKind {
        self.support_kind
    }

    #[must_use]
    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    #[must_use]
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    #[must_use]
    pub fn category(&self) -> &str {
        &self.category
    }

    #[must_use]
    pub fn subjects(&self) -> &[EvidenceSubject] {
        &self.subjects
    }

    #[must_use]
    pub fn locations(&self) -> &[EvidenceLocation] {
        &self.locations
    }

    #[must_use]
    pub fn input_digests(&self) -> &[String] {
        &self.input_digests
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum R2SupportDiagnosticReason {
    UnmatchedResourceSubject,
    UnmatchedClientEvidence,
    UnsupportedClientEvidenceCategory,
    ElevatedAuthorityBypassesOrdinaryRls,
    StaticEvidenceDoesNotProveLivePosture,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R2SupportDiagnostic {
    reason: R2SupportDiagnosticReason,
    subject: Option<String>,
}

impl R2SupportDiagnostic {
    #[must_use]
    pub const fn reason(&self) -> R2SupportDiagnosticReason {
        self.reason
    }

    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct R2SupportCorrelation {
    matches: Vec<R2SupportMatch>,
    coverage: Vec<CoverageRecord>,
    diagnostics: Vec<R2SupportDiagnostic>,
}

impl R2SupportCorrelation {
    #[must_use]
    pub fn matches(&self) -> &[R2SupportMatch] {
        &self.matches
    }

    /// Exact canonical R2 Coverage records, deterministically ordered by ID.
    /// No aggregate state is computed here; R3-T019 owns aggregation.
    #[must_use]
    pub fn coverage(&self) -> &[CoverageRecord] {
        &self.coverage
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[R2SupportDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum R2SupportError {
    InvalidLimits,
    TooManyEvidence { count: usize, max: usize },
    TooManyCoverage { count: usize, max: usize },
    TooManyResources { count: usize, max: usize },
    TooManyClients { count: usize, max: usize },
    TooManyMatches { count: usize, max: usize },
    TooManyDiagnostics { count: usize, max: usize },
}

impl fmt::Display for R2SupportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("R2 support limits must be non-zero"),
            Self::TooManyEvidence { count, max } => {
                write!(formatter, "R2 Evidence count {count} exceeds cap {max}")
            }
            Self::TooManyCoverage { count, max } => {
                write!(formatter, "R2 Coverage count {count} exceeds cap {max}")
            }
            Self::TooManyResources { count, max } => {
                write!(formatter, "R3 resource count {count} exceeds R2 support cap {max}")
            }
            Self::TooManyClients { count, max } => {
                write!(formatter, "R3 provider-client count {count} exceeds R2 support cap {max}")
            }
            Self::TooManyMatches { count, max } => {
                write!(formatter, "R2 support match count {count} exceeds cap {max}")
            }
            Self::TooManyDiagnostics { count, max } => {
                write!(formatter, "R2 support diagnostic count {count} exceeds cap {max}")
            }
        }
    }
}

impl Error for R2SupportError {}

/// Correlate canonical R2 provider output to R3 resources and provider clients.
///
/// Resource correlation requires an exact `ResourceRef::r2_subject` to match an
/// exact canonical R2 Evidence subject ID. Provider-client correlation requires
/// an exact `source_evidence_ids` reference to an Evidence ID. No lexical name,
/// file proximity, resource-name equality, confidence score, or inferred key
/// value is accepted as identity equivalence.
pub fn correlate_supabase_r2_support(
    provider: &SupabaseR2ProviderOutput,
    resources: &[ResourceRef],
    clients: &[ProviderClientAuthority],
    limits: R2SupportLimits,
) -> Result<R2SupportCorrelation, R2SupportError> {
    let limits = limits.validate()?;
    enforce_count(provider.evidence().len(), limits.max_evidence, CountKind::Evidence)?;
    enforce_count(provider.coverage().len(), limits.max_coverage, CountKind::Coverage)?;
    enforce_count(resources.len(), limits.max_resources, CountKind::Resources)?;
    enforce_count(clients.len(), limits.max_clients, CountKind::Clients)?;

    let mut relevant_by_id = BTreeMap::new();
    let mut relevant_by_subject: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    let mut all_evidence_ids = BTreeSet::new();

    for evidence in provider.evidence() {
        all_evidence_ids.insert(evidence.evidence_id());
        let Some(kind) = classify_category(&evidence.claim().category) else {
            continue;
        };
        relevant_by_id.insert(evidence.evidence_id(), (kind, evidence));
        for subject in &evidence.claim().subjects {
            relevant_by_subject
                .entry(subject.id.as_str())
                .or_default()
                .push((kind, evidence));
        }
    }

    let mut matches = BTreeMap::new();
    let mut diagnostics = Vec::new();

    for resource in resources {
        let Some(r2_subject) = resource.r2_subject() else {
            continue;
        };
        match relevant_by_subject.get(r2_subject) {
            Some(items) => {
                for (kind, evidence) in items {
                    insert_match(
                        &mut matches,
                        R2SupportTargetKind::ResourceSubject,
                        r2_subject,
                        *kind,
                        evidence,
                        limits,
                    )?;
                }
            }
            None => push_diagnostic(
                &mut diagnostics,
                R2SupportDiagnosticReason::UnmatchedResourceSubject,
                Some(r2_subject.to_owned()),
                limits,
            )?,
        }
    }

    for client in clients {
        for evidence_id in client.source_evidence_ids() {
            if let Some((kind, evidence)) = relevant_by_id.get(evidence_id.as_str()) {
                insert_match(
                    &mut matches,
                    R2SupportTargetKind::ProviderClient,
                    client.client_id().as_str(),
                    *kind,
                    evidence,
                    limits,
                )?;
            } else if all_evidence_ids.contains(evidence_id.as_str()) {
                push_diagnostic(
                    &mut diagnostics,
                    R2SupportDiagnosticReason::UnsupportedClientEvidenceCategory,
                    Some(evidence_id.clone()),
                    limits,
                )?;
            } else {
                push_diagnostic(
                    &mut diagnostics,
                    R2SupportDiagnosticReason::UnmatchedClientEvidence,
                    Some(evidence_id.clone()),
                    limits,
                )?;
            }
        }

        if client.authority_class() == ProviderAuthorityClass::ElevatedSecretOrServiceRole {
            push_diagnostic(
                &mut diagnostics,
                R2SupportDiagnosticReason::ElevatedAuthorityBypassesOrdinaryRls,
                Some(client.client_id().as_str().to_owned()),
                limits,
            )?;
        }
    }

    if !matches.is_empty() {
        push_diagnostic(
            &mut diagnostics,
            R2SupportDiagnosticReason::StaticEvidenceDoesNotProveLivePosture,
            None,
            limits,
        )?;
    }

    let mut coverage = provider.coverage().to_vec();
    coverage.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));

    diagnostics.sort_by(|left, right| {
        (left.reason, left.subject.as_deref()).cmp(&(right.reason, right.subject.as_deref()))
    });
    diagnostics.dedup();

    Ok(R2SupportCorrelation {
        matches: matches.into_values().collect(),
        coverage,
        diagnostics,
    })
}

#[derive(Clone, Copy)]
enum CountKind {
    Evidence,
    Coverage,
    Resources,
    Clients,
}

fn enforce_count(count: usize, max: usize, kind: CountKind) -> Result<(), R2SupportError> {
    if count <= max {
        return Ok(());
    }
    Err(match kind {
        CountKind::Evidence => R2SupportError::TooManyEvidence { count, max },
        CountKind::Coverage => R2SupportError::TooManyCoverage { count, max },
        CountKind::Resources => R2SupportError::TooManyResources { count, max },
        CountKind::Clients => R2SupportError::TooManyClients { count, max },
    })
}

fn classify_category(category: &str) -> Option<R2SupportKind> {
    match category {
        RLS_POSTURE => Some(R2SupportKind::RlsPosture),
        POLICY_POSTURE | STORAGE_POLICY_POSTURE => Some(R2SupportKind::PolicyPosture),
        API_ROLE_GRANT => Some(R2SupportKind::ApiRoleGrant),
        ELEVATED_KEY_CLIENT_BOUNDARY => Some(R2SupportKind::KeyClientBoundary),
        FUNCTION_SECURITY_MODE | FUNCTION_SEARCH_PATH | EDGE_FUNCTION_AUTH_POSTURE => {
            Some(R2SupportKind::StaticContext)
        }
        _ => None,
    }
}

fn insert_match(
    matches: &mut BTreeMap<(R2SupportTargetKind, String, String), R2SupportMatch>,
    target_kind: R2SupportTargetKind,
    target_id: &str,
    support_kind: R2SupportKind,
    evidence: &sentrdel_schema::evidence::Evidence,
    limits: R2SupportLimits,
) -> Result<(), R2SupportError> {
    let key = (
        target_kind,
        target_id.to_owned(),
        evidence.evidence_id().to_owned(),
    );
    if matches.contains_key(&key) {
        return Ok(());
    }
    let next_count = matches.len().saturating_add(1);
    if next_count > limits.max_matches {
        return Err(R2SupportError::TooManyMatches {
            count: next_count,
            max: limits.max_matches,
        });
    }
    matches.insert(
        key,
        R2SupportMatch {
            target_kind,
            target_id: target_id.to_owned(),
            support_kind,
            evidence_id: evidence.evidence_id().to_owned(),
            producer_id: evidence.producer().id.clone(),
            category: evidence.claim().category.clone(),
            subjects: evidence.claim().subjects.clone(),
            locations: evidence.claim().locations.clone(),
            input_digests: evidence.claim().input_digests.clone(),
        },
    );
    Ok(())
}

fn push_diagnostic(
    diagnostics: &mut Vec<R2SupportDiagnostic>,
    reason: R2SupportDiagnosticReason,
    subject: Option<String>,
    limits: R2SupportLimits,
) -> Result<(), R2SupportError> {
    if diagnostics.iter().any(|item| item.reason == reason && item.subject == subject) {
        return Ok(());
    }
    let next_count = diagnostics.len().saturating_add(1);
    if next_count > limits.max_diagnostics {
        return Err(R2SupportError::TooManyDiagnostics {
            count: next_count,
            max: limits.max_diagnostics,
        });
    }
    diagnostics.push(R2SupportDiagnostic { reason, subject });
    Ok(())
}
