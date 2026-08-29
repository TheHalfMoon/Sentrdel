//! Output-only finding presentation primitives for the explain flow.
//!
//! This module does not reconcile, reclassify, suppress, transition, or otherwise
//! mutate canonical Finding state. It only renders already-authoritative fields.

use std::{error::Error, fmt};

use sentrdel_cli::{
    CliCommand, CliContractError, CliDecision, CliEnvelope, CliFindingRef, CliRepository, CliTiming,
};
use sentrdel_schema::{
    coverage::CoverageRecord,
    finding::{
        EpistemicState, Finding, ReconcilerAuthority, Severity, WorkflowAuthorization,
        WorkflowState,
    },
};
use sentrdel_store::{StateStoreError, Store};
use serde::Serialize;

const MAX_PRESENTATION_FIELD_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImpactComponents {
    pub actor: String,
    pub capability: String,
    pub object: String,
}

impl ImpactComponents {
    pub fn new(
        actor: impl Into<String>,
        capability: impl Into<String>,
        object: impl Into<String>,
    ) -> Result<Self, PresentationError> {
        let value = Self {
            actor: normalize_field(actor.into())?,
            capability: normalize_field(capability.into())?,
            object: normalize_field(object.into())?,
        };
        Ok(value)
    }

    #[must_use]
    pub fn sentence(&self) -> String {
        format!("{} can {} on {}.", self.actor, self.capability, self.object)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PresentationTier {
    pub heading: &'static str,
    pub text: String,
}

/// Three-tier, output-only presentation of one canonical Finding.
///
/// Tier 1 answers "what could happen?" in actor/capability/object form. Tier 2
/// exposes the canonical impact statement and epistemic basis. Tier 3 exposes
/// bounded technical identity/location/workflow detail without changing it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FindingPresentation {
    pub finding_id: String,
    pub impact: PresentationTier,
    pub evidence: PresentationTier,
    pub technical: PresentationTier,
}

impl FindingPresentation {
    pub fn from_finding(
        finding: &Finding,
        components: ImpactComponents,
    ) -> Result<Self, PresentationError> {
        let draft = finding.draft();
        let impact_statement = normalize_field(draft.impact_statement.clone())?;
        let title = normalize_field(draft.title.clone())?;
        let category = normalize_field(draft.category.clone())?;

        let evidence_text = if draft.contradiction_ids.is_empty() {
            format!(
                "{} Evidence state: {}; supporting evidence: {}.",
                impact_statement,
                epistemic_name(&draft.epistemic_state),
                draft.evidence_ids.len()
            )
        } else {
            format!(
                "{} Evidence state: {}; supporting evidence: {}; contradictions: {}.",
                impact_statement,
                epistemic_name(&draft.epistemic_state),
                draft.evidence_ids.len(),
                draft.contradiction_ids.len()
            )
        };

        let location = draft.primary_location.as_deref().unwrap_or("not available");
        let technical_text = format!(
            "{} [{}]; category={}; finding={}; workflow={}; location={}.",
            title,
            severity_name(&draft.severity),
            category,
            finding.finding_id(),
            workflow_name(finding.workflow_state()),
            location
        );

        validate_rendered(&evidence_text)?;
        validate_rendered(&technical_text)?;

        Ok(Self {
            finding_id: finding.finding_id().to_owned(),
            impact: PresentationTier {
                heading: "Impact",
                text: components.sentence(),
            },
            evidence: PresentationTier {
                heading: "Evidence",
                text: evidence_text,
            },
            technical: PresentationTier {
                heading: "Technical detail",
                text: technical_text,
            },
        })
    }
}

/// Read-only `sentrdel explain <finding-id>` output.
pub struct ExplainOutput {
    revision: i64,
    finding: Finding,
    presentation: FindingPresentation,
    envelope: CliEnvelope,
}

impl ExplainOutput {
    #[allow(clippy::too_many_arguments)]
    pub fn load(
        store: &Store,
        finding_id: &str,
        reconciler: &ReconcilerAuthority,
        authorization: Option<&WorkflowAuthorization>,
        now_unix_seconds: i64,
        repository: CliRepository,
        components: ImpactComponents,
        coverage: Vec<CoverageRecord>,
        timing: CliTiming,
        store_refs: Option<Vec<String>>,
    ) -> Result<Option<Self>, ExplainCommandError> {
        let Some((revision, finding)) =
            store.get_finding(finding_id, reconciler, authorization, now_unix_seconds)?
        else {
            return Ok(None);
        };
        Self::new(
            revision, finding, repository, components, coverage, timing, store_refs,
        )
        .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: i64,
        finding: Finding,
        repository: CliRepository,
        components: ImpactComponents,
        coverage: Vec<CoverageRecord>,
        timing: CliTiming,
        store_refs: Option<Vec<String>>,
    ) -> Result<Self, ExplainCommandError> {
        if revision <= 0 {
            return Err(ExplainCommandError::InvalidRevision(revision));
        }
        let presentation = FindingPresentation::from_finding(&finding, components)?;
        let finding_ref =
            CliFindingRef::new(finding.finding_id(), finding.draft().evidence_ids.clone())?;
        let envelope = CliEnvelope::new(
            CliCommand::Explain,
            repository,
            CliDecision::Allow,
            vec![finding_ref],
            coverage,
            Vec::new(),
            timing,
            store_refs,
        )?;
        Ok(Self {
            revision,
            finding,
            presentation,
            envelope,
        })
    }

    #[must_use]
    pub const fn revision(&self) -> i64 {
        self.revision
    }

    #[must_use]
    pub fn finding(&self) -> &Finding {
        &self.finding
    }

    #[must_use]
    pub fn envelope(&self) -> &CliEnvelope {
        &self.envelope
    }

    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        self.envelope.to_json_line()
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let draft = self.finding.draft();
        let mut out = String::new();
        out.push_str("Impact:\n");
        out.push_str(&self.presentation.impact.text);
        out.push_str("\n\nSecurity narrative:\n");
        out.push_str(&self.presentation.evidence.text);
        out.push_str("\nRemediation: ");
        out.push_str(draft.remediation.as_deref().unwrap_or(
            "Review the cited evidence and remove the observed risky capability with the smallest safe change.",
        ));

        out.push_str("\n\nEvidence / provenance / coverage references:\n");
        for evidence_id in &draft.evidence_ids {
            out.push_str("- evidence: ");
            out.push_str(evidence_id);
            out.push('\n');
        }
        for contradiction_id in &draft.contradiction_ids {
            out.push_str("- contradiction: ");
            out.push_str(contradiction_id);
            out.push('\n');
        }
        for coverage in &self.envelope.coverage {
            out.push_str("- coverage: ");
            out.push_str(&coverage.coverage_id);
            out.push_str(" — ");
            out.push_str(&coverage.capability);
            out.push_str(" / ");
            out.push_str(&coverage.scope);
            out.push('\n');
        }
        if let Some(store_refs) = &self.envelope.store_refs {
            for store_ref in store_refs {
                out.push_str("- store: ");
                out.push_str(store_ref);
                out.push('\n');
            }
        }
        if draft.evidence_ids.is_empty()
            && draft.contradiction_ids.is_empty()
            && self.envelope.coverage.is_empty()
            && self.envelope.store_refs.as_ref().is_none_or(Vec::is_empty)
        {
            out.push_str("- none recorded\n");
        }

        out.push_str("\nTechnical detail:\n");
        out.push_str(&self.presentation.technical.text);
        out.push_str(" revision=");
        out.push_str(&self.revision.to_string());
        out.push('\n');
        out
    }
}

#[derive(Debug)]
pub enum ExplainCommandError {
    InvalidRevision(i64),
    Presentation(PresentationError),
    Contract(CliContractError),
    Store(StateStoreError),
}

impl fmt::Display for ExplainCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRevision(revision) => {
                write!(
                    formatter,
                    "finding revision must be positive, got {revision}"
                )
            }
            Self::Presentation(error) => write!(formatter, "cannot render finding: {error}"),
            Self::Contract(error) => write!(formatter, "invalid explain output: {error}"),
            Self::Store(error) => {
                write!(formatter, "cannot load finding from local store: {error}")
            }
        }
    }
}

impl Error for ExplainCommandError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRevision(_) => None,
            Self::Presentation(error) => Some(error),
            Self::Contract(error) => Some(error),
            Self::Store(error) => Some(error),
        }
    }
}

impl From<PresentationError> for ExplainCommandError {
    fn from(error: PresentationError) -> Self {
        Self::Presentation(error)
    }
}

impl From<CliContractError> for ExplainCommandError {
    fn from(error: CliContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<StateStoreError> for ExplainCommandError {
    fn from(error: StateStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresentationError {
    InvalidField,
    RenderedOutputTooLarge,
}

impl fmt::Display for PresentationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField => formatter.write_str(
                "presentation fields must be bounded, non-blank text without control characters",
            ),
            Self::RenderedOutputTooLarge => {
                formatter.write_str("rendered presentation text exceeds the bounded output limit")
            }
        }
    }
}

impl Error for PresentationError {}

fn normalize_field(value: String) -> Result<String, PresentationError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > MAX_PRESENTATION_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(PresentationError::InvalidField);
    }
    Ok(value.to_owned())
}

fn validate_rendered(value: &str) -> Result<(), PresentationError> {
    if value.len() > MAX_PRESENTATION_FIELD_BYTES * 4 {
        return Err(PresentationError::RenderedOutputTooLarge);
    }
    Ok(())
}

const fn severity_name(value: &Severity) -> &'static str {
    match value {
        Severity::Block => "BLOCK",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

const fn epistemic_name(value: &EpistemicState) -> &'static str {
    match value {
        EpistemicState::Detected => "DETECTED",
        EpistemicState::Corroborated => "CORROBORATED",
        EpistemicState::Contested => "CONTESTED",
        EpistemicState::Proven => "PROVEN",
        EpistemicState::Unproven => "UNPROVEN",
        EpistemicState::Unverifiable => "UNVERIFIABLE",
    }
}

const fn workflow_name(value: &WorkflowState) -> &'static str {
    match value {
        WorkflowState::New => "NEW",
        WorkflowState::TriagedFixNow => "TRIAGED_FIX_NOW",
        WorkflowState::TriagedDefer => "TRIAGED_DEFER",
        WorkflowState::Accepted => "ACCEPTED",
        WorkflowState::Suppressed => "SUPPRESSED",
        WorkflowState::FixProposed => "FIX_PROPOSED",
        WorkflowState::FixVerified => "FIX_VERIFIED",
        WorkflowState::FixRegressed => "FIX_REGRESSED",
        WorkflowState::Closed => "CLOSED",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use sentrdel_schema::{
        SCHEMA_V1,
        finding::{ReconciledFindingDraft, ReconcilerAuthority},
    };

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    fn finding() -> Finding {
        let reconciler =
            ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t067-config")
                .expect("reconciler authority");
        finding_for(&reconciler, None)
    }

    fn finding_for(reconciler: &ReconcilerAuthority, remediation: Option<String>) -> Finding {
        Finding::new_reconciled(
            ReconciledFindingDraft {
                schema_version: SCHEMA_V1.to_owned(),
                fingerprint: "t067:fingerprint".to_owned(),
                title: "Privileged workflow path".to_owned(),
                impact_statement: "A changed workflow grants a privileged capability.".to_owned(),
                category: "ci.workflow".to_owned(),
                severity: Severity::High,
                epistemic_state: EpistemicState::Corroborated,
                evidence_ids: vec!["evidence:a".to_owned(), "evidence:b".to_owned()],
                contradiction_ids: Vec::new(),
                primary_location: Some(".github/workflows/ci.yml:12".to_owned()),
                affected_subjects: vec!["workflow:ci".to_owned()],
                first_seen_commit: None,
                last_seen_commit: None,
                remediation,
                updated_at: "2026-08-29T00:00:00Z".to_owned(),
            },
            reconciler,
        )
        .expect("finding")
    }

    fn components() -> ImpactComponents {
        ImpactComponents::new(
            "an untrusted pull request actor",
            "obtain write-capable CI authority",
            "the repository",
        )
        .expect("impact components")
    }

    fn repository() -> CliRepository {
        CliRepository::new("sha256:repo", ".").expect("repository")
    }

    fn temp_db() -> PathBuf {
        let sequence = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sentrdel-t069-{}-{sequence}.sqlite3",
            std::process::id()
        ))
    }

    fn cleanup_db(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
            let _ = fs::remove_file(candidate);
        }
    }

    #[test]
    fn presentation_has_three_ordered_authority_safe_tiers() {
        let finding = finding();
        let presentation =
            FindingPresentation::from_finding(&finding, components()).expect("presentation");

        assert_eq!(presentation.impact.heading, "Impact");
        assert_eq!(
            presentation.impact.text,
            "an untrusted pull request actor can obtain write-capable CI authority on the repository."
        );
        assert_eq!(presentation.evidence.heading, "Evidence");
        assert!(presentation.evidence.text.contains("CORROBORATED"));
        assert!(
            presentation
                .evidence
                .text
                .contains("supporting evidence: 2")
        );
        assert_eq!(presentation.technical.heading, "Technical detail");
        assert!(presentation.technical.text.contains("workflow=NEW"));
        assert!(presentation.technical.text.contains("category=ci.workflow"));
    }

    #[test]
    fn presentation_does_not_mutate_canonical_finding_state() {
        let finding = finding();
        let before = finding.to_record();
        let _ = FindingPresentation::from_finding(
            &finding,
            ImpactComponents::new("actor", "change capability", "object")
                .expect("impact components"),
        )
        .expect("presentation");
        assert_eq!(finding.to_record(), before);
    }

    #[test]
    fn presentation_components_fail_closed_on_controls_blank_or_oversized_input() {
        assert!(ImpactComponents::new(" ", "read", "repo").is_err());
        assert!(ImpactComponents::new("actor", "read\nwrite", "repo").is_err());
        assert!(
            ImpactComponents::new(
                "actor",
                "read",
                "x".repeat(MAX_PRESENTATION_FIELD_BYTES + 1)
            )
            .is_err()
        );
    }

    #[test]
    fn explain_loads_existing_finding_from_local_store() {
        let reconciler =
            ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t069-config")
                .expect("reconciler authority");
        let canonical = finding_for(
            &reconciler,
            Some("Reduce workflow permissions to the minimum required scope.".to_owned()),
        );
        let path = temp_db();
        cleanup_db(&path);
        {
            let mut store = Store::open(&path).expect("store");
            assert!(store.put_finding(&canonical).expect("put finding"));

            let output = ExplainOutput::load(
                &store,
                canonical.finding_id(),
                &reconciler,
                None,
                0,
                repository(),
                components(),
                Vec::new(),
                CliTiming::default(),
                Some(vec!["graph:provenance-root".to_owned()]),
            )
            .expect("load")
            .expect("finding exists");

            assert_eq!(output.revision(), 1);
            assert_eq!(output.finding().finding_id(), canonical.finding_id());
            assert_eq!(output.envelope().command, CliCommand::Explain);
        }
        cleanup_db(&path);
    }

    #[test]
    fn human_and_json_modes_preserve_frozen_machine_envelope() {
        let reconciler =
            ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t069-config")
                .expect("reconciler authority");
        let output = ExplainOutput::new(
            1,
            finding_for(
                &reconciler,
                Some("Reduce workflow permissions to the minimum required scope.".to_owned()),
            ),
            repository(),
            components(),
            Vec::new(),
            CliTiming::default(),
            Some(vec!["graph:provenance-root".to_owned()]),
        )
        .expect("output");

        let human = output.render_human();
        assert!(human.contains("Impact:"));
        assert!(human.contains("Security narrative:"));
        assert!(human.contains("Remediation:"));
        assert!(human.contains("Evidence / provenance / coverage references:"));
        assert!(human.contains("Technical detail:"));

        let json = output.render_json().expect("json");
        assert!(json.ends_with('\n'));
        let value: serde_json::Value = serde_json::from_str(json.trim_end()).expect("parse json");
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
                "store_refs",
                "timing",
            ]
        );
        assert_eq!(value["command"], "explain");
        assert_eq!(value["decision"], "ALLOW");
        assert_eq!(
            value["findings"][0]["evidence_ids"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
    }

    #[test]
    fn unknown_finding_returns_none_without_manufacturing_state() {
        let reconciler =
            ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t069-config")
                .expect("reconciler authority");
        let path = temp_db();
        cleanup_db(&path);
        {
            let store = Store::open(&path).expect("store");
            let output = ExplainOutput::load(
                &store,
                "finding:missing",
                &reconciler,
                None,
                0,
                repository(),
                components(),
                Vec::new(),
                CliTiming::default(),
                None,
            )
            .expect("load");
            assert!(output.is_none());
        }
        cleanup_db(&path);
    }
}
