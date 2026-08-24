//! Guard policy decision contracts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub decision_id: String,
    pub verdict: Verdict,
    pub enforcement_fidelity: EnforcementFidelity,
    pub reason_codes: Vec<String>,
    pub rule_ids: Vec<String>,
    pub kernel_invariant_ids: Vec<String>,
    pub policy_version_digests: Vec<String>,
    pub action_digest: String,
    pub decided_at: String,
}

impl PolicyDecision {
    pub fn has_kernel_deny(&self) -> bool {
        self.verdict == Verdict::Deny && !self.kernel_invariant_ids.is_empty()
    }
}
