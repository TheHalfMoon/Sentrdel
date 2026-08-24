//! Reconciled Finding state. Producers never construct Findings directly.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Block,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicState {
    Detected,
    Corroborated,
    Contested,
    Proven,
    Unproven,
    Unverifiable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowState {
    New,
    TriagedFixNow,
    TriagedDefer,
    Accepted,
    Suppressed,
    FixProposed,
    FixVerified,
    FixRegressed,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRisk {
    pub owner: String,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
    pub signature_ref: Option<String>,
    pub evidence_basis: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub schema_version: String,
    pub finding_id: String,
    pub fingerprint: String,
    pub title: String,
    pub impact_statement: String,
    pub category: String,
    pub severity: Severity,
    pub epistemic_state: EpistemicState,
    pub workflow_state: WorkflowState,
    pub evidence_ids: Vec<String>,
    pub contradiction_ids: Vec<String>,
    pub primary_location: Option<String>,
    pub affected_subjects: Vec<String>,
    pub first_seen_commit: Option<String>,
    pub last_seen_commit: Option<String>,
    pub remediation: Option<String>,
    pub accepted_risk: Option<AcceptedRisk>,
    pub updated_at: String,
}

impl Finding {
    /// Validate a workflow transition without changing epistemic state.
    pub fn can_transition_workflow(&self, next: &WorkflowState) -> bool {
        use WorkflowState::*;
        matches!(
            (&self.workflow_state, next),
            (New, TriagedFixNow | TriagedDefer | Accepted | Suppressed | FixProposed | Closed)
                | (TriagedFixNow, Accepted | TriagedDefer | FixProposed | Closed)
                | (TriagedDefer, TriagedFixNow | Accepted | FixProposed | Closed)
                | (Accepted, TriagedFixNow | TriagedDefer | Closed)
                | (Suppressed, New | Closed)
                | (FixProposed, FixVerified | FixRegressed | TriagedFixNow | Closed)
                | (FixVerified, FixRegressed | Closed)
                | (FixRegressed, TriagedFixNow | FixProposed | Closed)
        ) || self.workflow_state == *next
    }

    pub fn validate_risk_acceptance(&self) -> bool {
        match (&self.workflow_state, &self.accepted_risk) {
            (WorkflowState::Accepted, Some(risk)) => {
                !risk.owner.trim().is_empty()
                    && !risk.reason.trim().is_empty()
                    && !risk.expires_at.trim().is_empty()
            }
            (WorkflowState::Accepted, None) => false,
            (_, Some(_)) => false,
            (_, None) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(state: WorkflowState) -> Finding {
        Finding {
            schema_version: "1".to_owned(),
            finding_id: "finding:1".to_owned(),
            fingerprint: "fp".to_owned(),
            title: "fixture".to_owned(),
            impact_statement: "fixture impact".to_owned(),
            category: "fixture".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Detected,
            workflow_state: state,
            evidence_ids: vec!["sha256:evidence".to_owned()],
            contradiction_ids: Vec::new(),
            primary_location: None,
            affected_subjects: Vec::new(),
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: None,
            accepted_risk: None,
            updated_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn closed_cannot_silently_reopen() {
        let value = finding(WorkflowState::Closed);
        assert!(!value.can_transition_workflow(&WorkflowState::New));
    }

    #[test]
    fn accepted_requires_expiring_owner_record() {
        let value = finding(WorkflowState::Accepted);
        assert!(!value.validate_risk_acceptance());
    }
}
