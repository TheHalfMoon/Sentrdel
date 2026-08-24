//! Agent Security Event Log (ASEL) canonical envelopes.

use crate::{canonical::{content_id, CanonicalError}, policy::PolicyDecision, version::SCHEMA_V1};
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

/// Hashable event envelope without a caller-controlled `event_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSecurityEvent {
    pub event_hash: String,
    #[serde(flatten)]
    pub draft: AgentSecurityEventDraft,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionIntegrity {
    ValidRelativeToProvidedHead,
    HashMismatch,
    SequenceGap,
    PreviousHashMismatch,
    NoTrustedHead,
}

#[derive(Debug)]
pub enum AselValidationError {
    UnsupportedSchemaVersion(String),
    EmptySession,
    EmptyActor,
    RootHasPreviousHash,
    NonRootMissingPreviousHash,
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
    pub fn verify_hash(&self) -> Result<bool, AselValidationError> {
        self.draft.validate()?;
        Ok(content_id("asel-event", &self.draft)? == self.event_hash)
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
    fn event_hash_is_not_caller_controlled() {
        let event = root().seal().expect("seal");
        assert!(event.verify_hash().expect("verify"));
    }

    #[test]
    fn non_root_event_requires_previous_hash() {
        let mut event = root();
        event.sequence = 1;
        assert!(matches!(
            event.seal().expect_err("must reject"),
            AselValidationError::NonRootMissingPreviousHash
        ));
    }
}
