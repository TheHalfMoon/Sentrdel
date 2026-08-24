//! Reconciled Finding state with sealed reconciler and workflow authority.

use crate::{
    canonical::{CanonicalError, content_id},
    version::SCHEMA_V1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

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

/// Persisted risk-acceptance record. Epoch seconds avoid accepting arbitrary
/// unparsed timestamp strings at the authority boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AcceptedRiskRecord {
    pub owner: String,
    pub reason: String,
    pub created_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
    pub authorization_ref: String,
    pub evidence_basis: Vec<String>,
}

/// Runtime capability owned by the trusted reconciler implementation. It is
/// neither serializable nor deserializable, so untrusted bytes cannot mint it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcilerAuthority {
    authority_id: String,
    configuration_digest: String,
}

impl ReconcilerAuthority {
    pub fn from_runtime(
        authority_id: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let authority_id = authority_id.into();
        let configuration_digest = configuration_digest.into();
        if authority_id.trim().is_empty() || configuration_digest.trim().is_empty() {
            return Err(FindingError::MissingReconcilerAuthority);
        }
        Ok(Self {
            authority_id,
            configuration_digest,
        })
    }
}

/// Runtime-issued workflow authorization. It deliberately implements neither
/// Serialize nor Deserialize, so repository/model/engine JSON cannot fabricate
/// an authority token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowAuthorization {
    authority_id: String,
    authorization_ref: String,
}

impl WorkflowAuthorization {
    pub fn from_runtime(
        authority_id: impl Into<String>,
        authorization_ref: impl Into<String>,
    ) -> Result<Self, FindingError> {
        let authority_id = authority_id.into();
        let authorization_ref = authorization_ref.into();
        if authority_id.trim().is_empty() || authorization_ref.trim().is_empty() {
            return Err(FindingError::MissingAuthorization);
        }
        Ok(Self {
            authority_id,
            authorization_ref,
        })
    }

    pub fn authorization_ref(&self) -> &str {
        &self.authorization_ref
    }
}

/// Input supplied by reconciliation logic. Workflow state is intentionally
/// absent; canonical findings always begin at NEW.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconciledFindingDraft {
    pub schema_version: String,
    pub fingerprint: String,
    pub title: String,
    pub impact_statement: String,
    pub category: String,
    pub severity: Severity,
    pub epistemic_state: EpistemicState,
    pub evidence_ids: Vec<String>,
    pub contradiction_ids: Vec<String>,
    pub primary_location: Option<String>,
    pub affected_subjects: Vec<String>,
    pub first_seen_commit: Option<String>,
    pub last_seen_commit: Option<String>,
    pub remediation: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    finding_id: String,
    reconciler_authority_id: String,
    reconciler_configuration_digest: String,
    #[serde(flatten)]
    draft: ReconciledFindingDraft,
    workflow_state: WorkflowState,
    accepted_risk: Option<AcceptedRiskRecord>,
    workflow_authority_id: Option<String>,
    workflow_authorization_ref: Option<String>,
}

/// Untrusted persistence/wire record. Acceptance requires validation against a
/// runtime reconciler authority; states beyond NEW additionally require a
/// runtime workflow authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingRecord {
    pub finding_id: String,
    pub reconciler_authority_id: String,
    pub reconciler_configuration_digest: String,
    #[serde(flatten)]
    pub draft: ReconciledFindingDraft,
    pub workflow_state: WorkflowState,
    pub accepted_risk: Option<AcceptedRiskRecord>,
    pub workflow_authority_id: Option<String>,
    pub workflow_authorization_ref: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FindingError {
    UnsupportedSchemaVersion(String),
    EmptyFingerprint,
    EmptyEvidenceBasis,
    MissingReconcilerAuthority,
    ReconcilerAuthorityMismatch,
    ForgedFindingId,
    InvalidTransition,
    MissingAuthorization,
    AuthorizationMismatch,
    UnexpectedAuthorizationMetadata,
    AcceptedRiskRequired,
    AcceptedRiskUnexpected,
    AcceptedRiskMalformed,
    AcceptedRiskExpired,
    FixVerifiedNotAuthorizedInR1,
    Canonical(String),
}

impl fmt::Display for FindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported finding schema version: {version}")
            }
            Self::EmptyFingerprint => write!(f, "finding fingerprint must not be empty"),
            Self::EmptyEvidenceBasis => write!(f, "finding must reference supporting evidence"),
            Self::MissingReconcilerAuthority => {
                write!(f, "trusted reconciler authority is required")
            }
            Self::ReconcilerAuthorityMismatch => {
                write!(f, "finding reconciler authority binding mismatch")
            }
            Self::ForgedFindingId => write!(f, "finding id does not match canonical identity"),
            Self::InvalidTransition => write!(f, "invalid finding workflow transition"),
            Self::MissingAuthorization => write!(f, "trusted workflow authorization is required"),
            Self::AuthorizationMismatch => write!(f, "workflow authorization binding mismatch"),
            Self::UnexpectedAuthorizationMetadata => {
                write!(
                    f,
                    "NEW finding must not contain workflow authorization metadata"
                )
            }
            Self::AcceptedRiskRequired => write!(f, "ACCEPTED state requires a valid risk record"),
            Self::AcceptedRiskUnexpected => {
                write!(f, "risk record is only valid in ACCEPTED state")
            }
            Self::AcceptedRiskMalformed => write!(
                f,
                "risk record is missing required authority/evidence fields"
            ),
            Self::AcceptedRiskExpired => write!(f, "risk acceptance is already expired"),
            Self::FixVerifiedNotAuthorizedInR1 => write!(
                f,
                "FIX_VERIFIED cannot be set before the verification spec is implemented"
            ),
            Self::Canonical(message) => write!(f, "finding canonicalization failed: {message}"),
        }
    }
}

impl Error for FindingError {}

impl From<CanonicalError> for FindingError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value.to_string())
    }
}

impl Finding {
    pub fn new_reconciled(
        draft: ReconciledFindingDraft,
        reconciler: &ReconcilerAuthority,
    ) -> Result<Self, FindingError> {
        validate_draft(&draft)?;
        let finding_id = finding_id(&draft)?;
        Ok(Self {
            finding_id,
            reconciler_authority_id: reconciler.authority_id.clone(),
            reconciler_configuration_digest: reconciler.configuration_digest.clone(),
            draft,
            workflow_state: WorkflowState::New,
            accepted_risk: None,
            workflow_authority_id: None,
            workflow_authorization_ref: None,
        })
    }

    pub fn try_from_record(
        record: FindingRecord,
        reconciler: &ReconcilerAuthority,
        authorization: Option<&WorkflowAuthorization>,
        now_unix_seconds: i64,
    ) -> Result<Self, FindingError> {
        validate_draft(&record.draft)?;
        if record.reconciler_authority_id != reconciler.authority_id
            || record.reconciler_configuration_digest != reconciler.configuration_digest
        {
            return Err(FindingError::ReconcilerAuthorityMismatch);
        }
        if finding_id(&record.draft)? != record.finding_id {
            return Err(FindingError::ForgedFindingId);
        }
        validate_workflow_state(
            &record.workflow_state,
            record.accepted_risk.as_ref(),
            authorization,
            record.workflow_authority_id.as_deref(),
            record.workflow_authorization_ref.as_deref(),
            now_unix_seconds,
        )?;
        Ok(Self {
            finding_id: record.finding_id,
            reconciler_authority_id: record.reconciler_authority_id,
            reconciler_configuration_digest: record.reconciler_configuration_digest,
            draft: record.draft,
            workflow_state: record.workflow_state,
            accepted_risk: record.accepted_risk,
            workflow_authority_id: record.workflow_authority_id,
            workflow_authorization_ref: record.workflow_authorization_ref,
        })
    }

    pub fn transition(
        &mut self,
        next: WorkflowState,
        authorization: &WorkflowAuthorization,
        accepted_risk: Option<AcceptedRiskRecord>,
        now_unix_seconds: i64,
    ) -> Result<(), FindingError> {
        if next == WorkflowState::FixVerified {
            return Err(FindingError::FixVerifiedNotAuthorizedInR1);
        }
        if !self.can_transition_workflow(&next) {
            return Err(FindingError::InvalidTransition);
        }
        validate_workflow_state(
            &next,
            accepted_risk.as_ref(),
            Some(authorization),
            Some(&authorization.authority_id),
            Some(&authorization.authorization_ref),
            now_unix_seconds,
        )?;
        self.workflow_state = next;
        self.accepted_risk = accepted_risk;
        self.workflow_authority_id = Some(authorization.authority_id.clone());
        self.workflow_authorization_ref = Some(authorization.authorization_ref.clone());
        Ok(())
    }

    pub fn to_record(&self) -> FindingRecord {
        FindingRecord {
            finding_id: self.finding_id.clone(),
            reconciler_authority_id: self.reconciler_authority_id.clone(),
            reconciler_configuration_digest: self.reconciler_configuration_digest.clone(),
            draft: self.draft.clone(),
            workflow_state: self.workflow_state.clone(),
            accepted_risk: self.accepted_risk.clone(),
            workflow_authority_id: self.workflow_authority_id.clone(),
            workflow_authorization_ref: self.workflow_authorization_ref.clone(),
        }
    }

    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }

    pub fn workflow_state(&self) -> &WorkflowState {
        &self.workflow_state
    }

    pub fn draft(&self) -> &ReconciledFindingDraft {
        &self.draft
    }

    fn can_transition_workflow(&self, next: &WorkflowState) -> bool {
        use WorkflowState::*;
        matches!(
            (&self.workflow_state, next),
            (
                New,
                TriagedFixNow | TriagedDefer | Accepted | Suppressed | FixProposed | Closed
            ) | (
                TriagedFixNow,
                Accepted | TriagedDefer | FixProposed | Closed
            ) | (
                TriagedDefer,
                TriagedFixNow | Accepted | FixProposed | Closed
            ) | (Accepted, TriagedFixNow | TriagedDefer | Closed)
                | (Suppressed, New | Closed)
                | (FixProposed, FixRegressed | TriagedFixNow | Closed)
                | (FixRegressed, TriagedFixNow | FixProposed | Closed)
        ) || &self.workflow_state == next
    }
}

fn validate_draft(draft: &ReconciledFindingDraft) -> Result<(), FindingError> {
    if draft.schema_version != SCHEMA_V1 {
        return Err(FindingError::UnsupportedSchemaVersion(
            draft.schema_version.clone(),
        ));
    }
    if draft.fingerprint.trim().is_empty() {
        return Err(FindingError::EmptyFingerprint);
    }
    if draft.evidence_ids.is_empty() {
        return Err(FindingError::EmptyEvidenceBasis);
    }
    Ok(())
}

fn finding_id(draft: &ReconciledFindingDraft) -> Result<String, FindingError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        fingerprint: &'a str,
        category: &'a str,
    }
    Ok(content_id(
        "finding",
        &Identity {
            fingerprint: &draft.fingerprint,
            category: &draft.category,
        },
    )?)
}

fn validate_workflow_state(
    state: &WorkflowState,
    risk: Option<&AcceptedRiskRecord>,
    authorization: Option<&WorkflowAuthorization>,
    stored_authority_id: Option<&str>,
    stored_authorization_ref: Option<&str>,
    now_unix_seconds: i64,
) -> Result<(), FindingError> {
    if state == &WorkflowState::New {
        if risk.is_some() {
            return Err(FindingError::AcceptedRiskUnexpected);
        }
        if stored_authority_id.is_some() || stored_authorization_ref.is_some() {
            return Err(FindingError::UnexpectedAuthorizationMetadata);
        }
        return Ok(());
    }
    if state == &WorkflowState::FixVerified {
        return Err(FindingError::FixVerifiedNotAuthorizedInR1);
    }
    let authorization = authorization.ok_or(FindingError::MissingAuthorization)?;
    if stored_authority_id != Some(authorization.authority_id.as_str())
        || stored_authorization_ref != Some(authorization.authorization_ref.as_str())
    {
        return Err(FindingError::AuthorizationMismatch);
    }
    match (state, risk) {
        (WorkflowState::Accepted, Some(risk)) => {
            validate_accepted_risk(risk, authorization, now_unix_seconds)
        }
        (WorkflowState::Accepted, None) => Err(FindingError::AcceptedRiskRequired),
        (_, Some(_)) => Err(FindingError::AcceptedRiskUnexpected),
        (_, None) => Ok(()),
    }
}

fn validate_accepted_risk(
    risk: &AcceptedRiskRecord,
    authorization: &WorkflowAuthorization,
    now_unix_seconds: i64,
) -> Result<(), FindingError> {
    if risk.owner.trim().is_empty()
        || risk.reason.trim().is_empty()
        || risk.authorization_ref.trim().is_empty()
        || risk.evidence_basis.is_empty()
        || risk.created_at_unix_seconds > risk.expires_at_unix_seconds
    {
        return Err(FindingError::AcceptedRiskMalformed);
    }
    if risk.authorization_ref != authorization.authorization_ref {
        return Err(FindingError::AuthorizationMismatch);
    }
    if risk.expires_at_unix_seconds <= now_unix_seconds {
        return Err(FindingError::AcceptedRiskExpired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reconciler() -> ReconcilerAuthority {
        ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:config")
            .expect("reconciler")
    }

    fn draft() -> ReconciledFindingDraft {
        ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint: "fp".to_owned(),
            title: "fixture".to_owned(),
            impact_statement: "fixture impact".to_owned(),
            category: "fixture".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Detected,
            evidence_ids: vec!["sha256:evidence".to_owned()],
            contradiction_ids: Vec::new(),
            primary_location: None,
            affected_subjects: Vec::new(),
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: None,
            updated_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn reconciled_finding_always_starts_new() {
        let value = Finding::new_reconciled(draft(), &reconciler()).expect("finding");
        assert_eq!(value.workflow_state(), &WorkflowState::New);
    }

    #[test]
    fn record_is_bound_to_reconciler_authority() {
        let authority = reconciler();
        let value = Finding::new_reconciled(draft(), &authority).expect("finding");
        let record = value.to_record();
        let other = ReconcilerAuthority::from_runtime("other", "sha256:other").expect("other");
        assert!(matches!(
            Finding::try_from_record(record, &other, None, 100),
            Err(FindingError::ReconcilerAuthorityMismatch)
        ));
    }

    #[test]
    fn new_record_rejects_hidden_workflow_authority() {
        let authority = reconciler();
        let value = Finding::new_reconciled(draft(), &authority).expect("finding");
        let mut record = value.to_record();
        record.workflow_authority_id = Some("fake".to_owned());
        record.workflow_authorization_ref = Some("fake".to_owned());
        assert!(matches!(
            Finding::try_from_record(record, &authority, None, 100),
            Err(FindingError::UnexpectedAuthorizationMetadata)
        ));
    }

    #[test]
    fn forged_closed_record_needs_authority() {
        let authority = reconciler();
        let value = Finding::new_reconciled(draft(), &authority).expect("finding");
        let mut record = value.to_record();
        record.workflow_state = WorkflowState::Closed;
        record.workflow_authority_id = Some("fake".to_owned());
        record.workflow_authorization_ref = Some("fake".to_owned());
        assert!(matches!(
            Finding::try_from_record(record, &authority, None, 100),
            Err(FindingError::MissingAuthorization)
        ));
    }

    #[test]
    fn expired_or_empty_basis_risk_is_rejected() {
        let authority = reconciler();
        let mut value = Finding::new_reconciled(draft(), &authority).expect("finding");
        let auth = WorkflowAuthorization::from_runtime("user-policy", "approval:1").expect("auth");
        let risk = AcceptedRiskRecord {
            owner: "owner".to_owned(),
            reason: "temporary".to_owned(),
            created_at_unix_seconds: 10,
            expires_at_unix_seconds: 20,
            authorization_ref: "approval:1".to_owned(),
            evidence_basis: Vec::new(),
        };
        assert!(matches!(
            value.transition(WorkflowState::Accepted, &auth, Some(risk), 15),
            Err(FindingError::AcceptedRiskMalformed)
        ));
    }

    #[test]
    fn fix_verified_is_impossible_in_r1() {
        let authority = reconciler();
        let mut value = Finding::new_reconciled(draft(), &authority).expect("finding");
        let auth = WorkflowAuthorization::from_runtime("kernel", "approval:2").expect("auth");
        assert!(matches!(
            value.transition(WorkflowState::FixVerified, &auth, None, 0),
            Err(FindingError::FixVerifiedNotAuthorizedInR1)
        ));
    }
}
