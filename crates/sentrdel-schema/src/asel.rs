//! Agent Security Event Log (ASEL) canonical envelopes and session verification.

use crate::{
    canonical::{CanonicalError, content_id},
    policy::{PolicyDecision, PolicyDecisionError, PolicyDecisionRecord, TrustedPolicyAuthority},
    version::SCHEMA_V1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActorType {
    User,
    Agent,
    Tool,
    System,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub actor_type: ActorType,
    pub id: String,
    pub vendor: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventKind {
    #[serde(rename = "mcp.discovery")]
    McpDiscovery,
    #[serde(rename = "mcp.invocation")]
    McpInvocation,
    #[serde(rename = "git.operation")]
    GitOperation,
    #[serde(rename = "approval")]
    Approval,
    #[serde(rename = "denial")]
    Denial,
    #[serde(rename = "tool.result")]
    ToolResult,
    #[serde(rename = "guard.error")]
    GuardError,
    #[serde(rename = "prompt.input")]
    PromptInput,
    #[serde(rename = "model.request")]
    ModelRequest,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.edit")]
    FileEdit,
    #[serde(rename = "shell.command")]
    ShellCommand,
    #[serde(rename = "subprocess.spawn")]
    SubprocessSpawn,
    #[serde(rename = "network.access")]
    NetworkAccess,
    #[serde(rename = "package.install")]
    PackageInstall,
    #[serde(rename = "dependency.change")]
    DependencyChange,
    #[serde(rename = "secret.access")]
    SecretAccess,
    #[serde(rename = "env.access")]
    EnvAccess,
    #[serde(rename = "ci.change")]
    CiChange,
    #[serde(rename = "iac.change")]
    IacChange,
}

/// Trusted in-process event draft. This type is serializable for hashing/schema
/// generation but deliberately not directly deserializable from untrusted JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSecurityEventDraft {
    pub schema_version: String,
    pub session_id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub actor: Actor,
    pub kind: EventKind,
    /// Intent is represented as a digest/label, not raw prompt content.
    pub intent_digest: Option<String>,
    pub target: BTreeMap<String, String>,
    pub params_digest: Option<String>,
    pub result_digest: Option<String>,
    pub policy_decision: Option<PolicyDecision>,
    pub provenance: BTreeMap<String, String>,
    pub previous_event_hash: Option<String>,
}

/// Authoritative sealed ASEL event. It cannot be directly deserialized and its
/// hash/draft are private.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSecurityEvent {
    event_hash: String,
    #[serde(flatten)]
    draft: AgentSecurityEventDraft,
}

/// Untrusted wire/persistence record. If it embeds a policy decision, callers
/// must supply the trusted policy authority/action binding before acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSecurityEventRecord {
    pub event_hash: String,
    pub schema_version: String,
    pub session_id: String,
    pub sequence: u64,
    pub timestamp: String,
    pub actor: Actor,
    pub kind: EventKind,
    pub intent_digest: Option<String>,
    pub target: BTreeMap<String, String>,
    pub params_digest: Option<String>,
    pub result_digest: Option<String>,
    pub policy_decision: Option<PolicyDecisionRecord>,
    pub provenance: BTreeMap<String, String>,
    pub previous_event_hash: Option<String>,
}

pub struct EventPolicyBinding<'a> {
    pub authority: &'a TrustedPolicyAuthority,
    pub expected_action_digest: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionIntegrity {
    ValidRelativeToProvidedHead,
    NoTrustedHead,
    TrustedHeadMismatch,
    HashMismatch,
    SessionMismatch,
    SequenceGap,
    PreviousHashMismatch,
    EmptySession,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionVerification {
    pub integrity: SessionIntegrity,
    pub event_count: u64,
    pub session_id: Option<String>,
    pub computed_head: Option<String>,
}

#[derive(Debug)]
pub enum AselValidationError {
    UnsupportedSchemaVersion(String),
    EmptySession,
    EmptyActor,
    RootHasPreviousHash,
    NonRootMissingPreviousHash,
    ForgedEventHash,
    PolicyBindingRequired,
    UnexpectedPolicyBinding,
    Policy(PolicyDecisionError),
    Canonical(String),
}

impl fmt::Display for AselValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported ASEL schema version: {version}")
            }
            Self::EmptySession => write!(f, "ASEL session id must not be empty"),
            Self::EmptyActor => write!(f, "ASEL actor id must not be empty"),
            Self::RootHasPreviousHash => {
                write!(f, "ASEL sequence 0 root must not have a previous hash")
            }
            Self::NonRootMissingPreviousHash => {
                write!(f, "non-root ASEL event must include previous hash")
            }
            Self::ForgedEventHash => write!(f, "ASEL event hash does not match canonical event"),
            Self::PolicyBindingRequired => {
                write!(
                    f,
                    "embedded policy decision requires trusted authority/action binding"
                )
            }
            Self::UnexpectedPolicyBinding => {
                write!(
                    f,
                    "policy binding supplied for event without a policy decision"
                )
            }
            Self::Policy(error) => write!(f, "invalid embedded policy decision: {error}"),
            Self::Canonical(message) => write!(f, "ASEL canonicalization failed: {message}"),
        }
    }
}

impl Error for AselValidationError {}

impl From<CanonicalError> for AselValidationError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value.to_string())
    }
}

impl From<PolicyDecisionError> for AselValidationError {
    fn from(value: PolicyDecisionError) -> Self {
        Self::Policy(value)
    }
}

impl AgentSecurityEventDraft {
    pub fn validate(&self) -> Result<(), AselValidationError> {
        if self.schema_version != SCHEMA_V1 {
            return Err(AselValidationError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        if self.session_id.trim().is_empty() {
            return Err(AselValidationError::EmptySession);
        }
        if self.actor.id.trim().is_empty() {
            return Err(AselValidationError::EmptyActor);
        }
        match (self.sequence, self.previous_event_hash.is_some()) {
            (0, true) => Err(AselValidationError::RootHasPreviousHash),
            (0, false) => Ok(()),
            (_, false) => Err(AselValidationError::NonRootMissingPreviousHash),
            (_, true) => Ok(()),
        }
    }

    pub fn seal(self) -> Result<AgentSecurityEvent, AselValidationError> {
        self.validate()?;
        let event_hash = content_id("asel-event", &self)?;
        Ok(AgentSecurityEvent {
            event_hash,
            draft: self,
        })
    }
}

impl AgentSecurityEvent {
    pub fn try_from_record(
        record: AgentSecurityEventRecord,
        policy_binding: Option<EventPolicyBinding<'_>>,
    ) -> Result<Self, AselValidationError> {
        let policy_decision = match (record.policy_decision, policy_binding) {
            (Some(policy), Some(binding)) => Some(PolicyDecision::try_from_record(
                policy,
                binding.expected_action_digest,
                binding.authority,
            )?),
            (Some(_), None) => return Err(AselValidationError::PolicyBindingRequired),
            (None, Some(_)) => return Err(AselValidationError::UnexpectedPolicyBinding),
            (None, None) => None,
        };

        let expected_hash = record.event_hash;
        let event = AgentSecurityEventDraft {
            schema_version: record.schema_version,
            session_id: record.session_id,
            sequence: record.sequence,
            timestamp: record.timestamp,
            actor: record.actor,
            kind: record.kind,
            intent_digest: record.intent_digest,
            target: record.target,
            params_digest: record.params_digest,
            result_digest: record.result_digest,
            policy_decision,
            provenance: record.provenance,
            previous_event_hash: record.previous_event_hash,
        }
        .seal()?;

        if event.event_hash != expected_hash {
            return Err(AselValidationError::ForgedEventHash);
        }
        Ok(event)
    }

    pub fn to_record(&self) -> AgentSecurityEventRecord {
        AgentSecurityEventRecord {
            event_hash: self.event_hash.clone(),
            schema_version: self.draft.schema_version.clone(),
            session_id: self.draft.session_id.clone(),
            sequence: self.draft.sequence,
            timestamp: self.draft.timestamp.clone(),
            actor: self.draft.actor.clone(),
            kind: self.draft.kind.clone(),
            intent_digest: self.draft.intent_digest.clone(),
            target: self.draft.target.clone(),
            params_digest: self.draft.params_digest.clone(),
            result_digest: self.draft.result_digest.clone(),
            policy_decision: self
                .draft
                .policy_decision
                .as_ref()
                .map(PolicyDecision::to_record),
            provenance: self.draft.provenance.clone(),
            previous_event_hash: self.draft.previous_event_hash.clone(),
        }
    }

    pub fn event_hash(&self) -> &str {
        &self.event_hash
    }

    pub fn session_id(&self) -> &str {
        &self.draft.session_id
    }

    pub fn sequence(&self) -> u64 {
        self.draft.sequence
    }

    pub fn previous_event_hash(&self) -> Option<&str> {
        self.draft.previous_event_hash.as_deref()
    }

    pub fn verify_hash(&self) -> Result<bool, AselValidationError> {
        self.draft.validate()?;
        Ok(content_id("asel-event", &self.draft)? == self.event_hash)
    }
}

/// Verify a complete ordered in-memory session. `ValidRelativeToProvidedHead`
/// is returned only after every event hash, session id, exact sequence, link,
/// and the supplied trusted head have all been checked.
pub fn verify_session(
    events: &[AgentSecurityEvent],
    trusted_head: Option<&str>,
) -> SessionVerification {
    if events.is_empty() {
        return SessionVerification {
            integrity: SessionIntegrity::EmptySession,
            event_count: 0,
            session_id: None,
            computed_head: None,
        };
    }

    let session_id = events[0].session_id().to_owned();
    for (index, event) in events.iter().enumerate() {
        if event.verify_hash().ok() != Some(true) {
            return session_result(SessionIntegrity::HashMismatch, events, &session_id);
        }
        if event.session_id() != session_id {
            return session_result(SessionIntegrity::SessionMismatch, events, &session_id);
        }
        if event.sequence() != index as u64 {
            return session_result(SessionIntegrity::SequenceGap, events, &session_id);
        }
        if index == 0 {
            if event.previous_event_hash().is_some() {
                return session_result(SessionIntegrity::PreviousHashMismatch, events, &session_id);
            }
        } else if event.previous_event_hash() != Some(events[index - 1].event_hash()) {
            return session_result(SessionIntegrity::PreviousHashMismatch, events, &session_id);
        }
    }

    let computed_head = events.last().map(|event| event.event_hash().to_owned());
    let integrity = match (trusted_head, computed_head.as_deref()) {
        (Some(expected), Some(actual)) if expected == actual => {
            SessionIntegrity::ValidRelativeToProvidedHead
        }
        (Some(_), Some(_)) => SessionIntegrity::TrustedHeadMismatch,
        (None, Some(_)) => SessionIntegrity::NoTrustedHead,
        _ => SessionIntegrity::EmptySession,
    };

    SessionVerification {
        integrity,
        event_count: events.len() as u64,
        session_id: Some(session_id),
        computed_head,
    }
}

fn session_result(
    integrity: SessionIntegrity,
    events: &[AgentSecurityEvent],
    session_id: &str,
) -> SessionVerification {
    SessionVerification {
        integrity,
        event_count: events.len() as u64,
        session_id: Some(session_id.to_owned()),
        computed_head: events.last().map(|event| event.event_hash().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> AgentSecurityEventDraft {
        AgentSecurityEventDraft {
            schema_version: SCHEMA_V1.to_owned(),
            session_id: "session-fixture".to_owned(),
            sequence: 0,
            timestamp: "2026-08-24T00:00:00Z".to_owned(),
            actor: Actor {
                actor_type: ActorType::System,
                id: "sentrdel-guard".to_owned(),
                vendor: None,
                version: None,
            },
            kind: EventKind::McpDiscovery,
            intent_digest: None,
            target: BTreeMap::new(),
            params_digest: None,
            result_digest: None,
            policy_decision: None,
            provenance: BTreeMap::new(),
            previous_event_hash: None,
        }
    }

    #[test]
    fn forged_event_record_is_rejected() {
        let event = root().seal().expect("seal");
        let mut record = event.to_record();
        record.event_hash = "sha256:forged".to_owned();
        assert!(matches!(
            AgentSecurityEvent::try_from_record(record, None),
            Err(AselValidationError::ForgedEventHash)
        ));
    }

    #[test]
    fn session_verifier_checks_exact_chain_and_trusted_head() {
        let first = root().seal().expect("root");
        let mut second_draft = root();
        second_draft.sequence = 1;
        second_draft.previous_event_hash = Some(first.event_hash().to_owned());
        let second = second_draft.seal().expect("second");
        let trusted = second.event_hash().to_owned();
        let result = verify_session(&[first, second], Some(&trusted));
        assert_eq!(
            result.integrity,
            SessionIntegrity::ValidRelativeToProvidedHead
        );
        assert_eq!(result.event_count, 2);
    }

    #[test]
    fn internally_valid_chain_without_anchor_is_not_called_trusted() {
        let first = root().seal().expect("root");
        let result = verify_session(&[first], None);
        assert_eq!(result.integrity, SessionIntegrity::NoTrustedHead);
    }
}
