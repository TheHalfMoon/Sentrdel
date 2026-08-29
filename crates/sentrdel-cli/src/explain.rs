//! Output-only finding presentation primitives for the explain flow.
//!
//! This module does not reconcile, reclassify, suppress, transition, or otherwise
//! mutate canonical Finding state. It only renders already-authoritative fields.

use std::{error::Error, fmt};

use sentrdel_schema::finding::{EpistemicState, Finding, Severity, WorkflowState};
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
        format!(
            "{} can {} on {}.",
            self.actor, self.capability, self.object
        )
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
    use super::*;
    use sentrdel_schema::{
        SCHEMA_V1,
        finding::{ReconciledFindingDraft, ReconcilerAuthority},
    };

    fn finding() -> Finding {
        let reconciler = ReconcilerAuthority::from_runtime(
            "sentrdel-reconciler",
            "sha256:t067-config",
        )
        .expect("reconciler authority");
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
                remediation: None,
                updated_at: "2026-08-29T00:00:00Z".to_owned(),
            },
            &reconciler,
        )
        .expect("finding")
    }

    #[test]
    fn presentation_has_three_ordered_authority_safe_tiers() {
        let finding = finding();
        let presentation = FindingPresentation::from_finding(
            &finding,
            ImpactComponents::new(
                "an untrusted pull request actor",
                "obtain write-capable CI authority",
                "the repository",
            )
            .expect("impact components"),
        )
        .expect("presentation");

        assert_eq!(presentation.impact.heading, "Impact");
        assert_eq!(
            presentation.impact.text,
            "an untrusted pull request actor can obtain write-capable CI authority on the repository."
        );
        assert_eq!(presentation.evidence.heading, "Evidence");
        assert!(presentation.evidence.text.contains("CORROBORATED"));
        assert!(presentation.evidence.text.contains("supporting evidence: 2"));
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
            ImpactComponents::new("actor", "read", "x".repeat(MAX_PRESENTATION_FIELD_BYTES + 1))
                .is_err()
        );
    }
}
