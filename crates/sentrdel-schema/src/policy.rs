//! Guard policy decision contracts with an explicit trusted-authority binding.

use crate::canonical::{content_id, CanonicalError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
    Undecidable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnforcementFidelity {
    Enforced,
    Partial,
    Advisory,
}

/// Untrusted/deserializable policy result. A claim is not an authoritative
/// decision until bound to a runtime-selected trusted authority and action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionClaim {
    pub verdict: Verdict,
    pub enforcement_fidelity: EnforcementFidelity,
    pub reason_codes: Vec<String>,
    pub rule_ids: Vec<String>,
    pub kernel_invariant_ids: Vec<String>,
    pub policy_version_digests: Vec<String>,
    pub action_digest: String,
    pub decided_at: String,
}

/// Opaque-to-serialization runtime trust anchor selected outside untrusted
/// repository/model/engine input paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPolicyAuthority {
    id: String,
    configuration_digest: String,
}

impl TrustedPolicyAuthority {
    /// Trusted runtime/bootstrap code creates this value. It deliberately does
    /// not implement Deserialize, so untrusted JSON cannot manufacture one.
    pub fn from_runtime(id: impl Into<String>, configuration_digest: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            configuration_digest: configuration_digest.into(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn configuration_digest(&self) -> &str {
        &self.configuration_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    decision_id: String,
    authority_id: String,
    authority_configuration_digest: String,
    #[serde(flatten)]
    claim: PolicyDecisionClaim,
}

/// Persistence/wire representation. Deserializing this remains untrusted until
/// `PolicyDecision::try_from_record` rebinds it to the expected authority/action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionRecord {
    pub decision_id: String,
    pub authority_id: String,
    pub authority_configuration_digest: String,
    #[serde(flatten)]
    pub claim: PolicyDecisionClaim,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyDecisionError {
    EmptyActionDigest,
    ActionDigestMismatch,
    AuthorityMismatch,
    ForgedDecisionId,
    Canonical(String),
}

impl fmt::Display for PolicyDecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyActionDigest => write!(f, "policy action digest must not be empty"),
            Self::ActionDigestMismatch => write!(f, "policy decision action digest mismatch"),
            Self::AuthorityMismatch => write!(f, "policy authority binding mismatch"),
            Self::ForgedDecisionId => write!(f, "policy decision id does not match canonical content"),
            Self::Canonical(message) => write!(f, "policy canonicalization failed: {message}"),
        }
    }
}

impl Error for PolicyDecisionError {}

impl From<CanonicalError> for PolicyDecisionError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value.to_string())
    }
}

impl PolicyDecision {
    pub fn bind(
        claim: PolicyDecisionClaim,
        expected_action_digest: &str,
        authority: &TrustedPolicyAuthority,
    ) -> Result<Self, PolicyDecisionError> {
        if expected_action_digest.is_empty() || claim.action_digest.is_empty() {
            return Err(PolicyDecisionError::EmptyActionDigest);
        }
        if claim.action_digest != expected_action_digest {
            return Err(PolicyDecisionError::ActionDigestMismatch);
        }
        let mut decision = Self {
            decision_id: String::new(),
            authority_id: authority.id.clone(),
            authority_configuration_digest: authority.configuration_digest.clone(),
            claim,
        };
        decision.decision_id = content_id("policy-decision", &decision.unsigned_view())?;
        Ok(decision)
    }

    pub fn try_from_record(
        record: PolicyDecisionRecord,
        expected_action_digest: &str,
        authority: &TrustedPolicyAuthority,
    ) -> Result<Self, PolicyDecisionError> {
        if record.authority_id != authority.id
            || record.authority_configuration_digest != authority.configuration_digest
        {
            return Err(PolicyDecisionError::AuthorityMismatch);
        }
        let expected_id = record.decision_id.clone();
        let decision = Self::bind(record.claim, expected_action_digest, authority)?;
        if decision.decision_id != expected_id {
            return Err(PolicyDecisionError::ForgedDecisionId);
        }
        Ok(decision)
    }

    pub fn to_record(&self) -> PolicyDecisionRecord {
        PolicyDecisionRecord {
            decision_id: self.decision_id.clone(),
            authority_id: self.authority_id.clone(),
            authority_configuration_digest: self.authority_configuration_digest.clone(),
            claim: self.claim.clone(),
        }
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn action_digest(&self) -> &str {
        &self.claim.action_digest
    }

    pub fn verdict(&self) -> Verdict {
        self.claim.verdict
    }

    pub fn enforcement_fidelity(&self) -> EnforcementFidelity {
        self.claim.enforcement_fidelity
    }

    pub fn has_kernel_deny(&self) -> bool {
        self.claim.verdict == Verdict::Deny && !self.claim.kernel_invariant_ids.is_empty()
    }

    fn unsigned_view(&self) -> PolicyDecisionUnsigned<'_> {
        PolicyDecisionUnsigned {
            authority_id: &self.authority_id,
            authority_configuration_digest: &self.authority_configuration_digest,
            claim: &self.claim,
        }
    }
}

#[derive(Serialize)]
struct PolicyDecisionUnsigned<'a> {
    authority_id: &'a str,
    authority_configuration_digest: &'a str,
    claim: &'a PolicyDecisionClaim,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(action: &str) -> PolicyDecisionClaim {
        PolicyDecisionClaim {
            verdict: Verdict::Allow,
            enforcement_fidelity: EnforcementFidelity::Enforced,
            reason_codes: Vec::new(),
            rule_ids: Vec::new(),
            kernel_invariant_ids: Vec::new(),
            policy_version_digests: vec!["sha256:policy".to_owned()],
            action_digest: action.to_owned(),
            decided_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn decision_is_bound_to_expected_action() {
        let authority = TrustedPolicyAuthority::from_runtime("kernel", "sha256:config");
        assert!(matches!(
            PolicyDecision::bind(claim("sha256:a"), "sha256:b", &authority),
            Err(PolicyDecisionError::ActionDigestMismatch)
        ));
    }

    #[test]
    fn forged_record_is_rejected() {
        let authority = TrustedPolicyAuthority::from_runtime("kernel", "sha256:config");
        let decision = PolicyDecision::bind(claim("sha256:a"), "sha256:a", &authority)
            .expect("bind");
        let mut record = decision.to_record();
        record.decision_id = "sha256:forged".to_owned();
        assert!(matches!(
            PolicyDecision::try_from_record(record, "sha256:a", &authority),
            Err(PolicyDecisionError::ForgedDecisionId)
        ));
    }
}
