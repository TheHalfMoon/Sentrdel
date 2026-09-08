//! S1 security-invariant regression contracts and bounded local substrates.
//!
//! This module provides exact local revision identity validation, bounded
//! composition/compatibility validation for canonical semantic snapshots, and
//! frozen internal pair/comparison authority. It does not perform forge
//! discovery, network access, target execution, provider access, external-model
//! execution, or canonical Finding creation.

pub mod model;
pub mod revision;
pub mod snapshot;

pub const S1_REGRESSION_CONTRACT_VERSION: &str = "sentrdel.security-regression/v1";
pub const S1_SNAPSHOT_CONTRACT_VERSION: &str = "sentrdel.security-regression-snapshot/v1";
pub const S1_FIXTURE_IDENTITY_NAMESPACE: &str = "sentrdel.fixture.security-regression/v1";

pub const S1_DIRECT_FINDING_CREATION_ALLOWED: bool = false;
pub const S1_FACT_VERIFIED_MINTING_ALLOWED: bool = false;
pub const S1_POLICY_OVERRIDE_ALLOWED: bool = false;
pub const S1_KERNEL_OVERRIDE_ALLOWED: bool = false;
pub const S1_RECONCILER_OVERRIDE_ALLOWED: bool = false;
pub const S1_GRAPH_OR_MODEL_AUTHORITY_ALLOWED: bool = false;
pub const S1_NETWORK_ACCESS_ALLOWED: bool = false;
pub const S1_FORGE_DISCOVERY_ALLOWED: bool = false;
pub const S1_PROVIDER_CREDENTIALS_ALLOWED: bool = false;
pub const S1_TARGET_EXECUTION_ALLOWED: bool = false;
pub const S1_LLM_OR_EXTERNAL_ENGINE_ALLOWED: bool = false;
pub const S1_MISSING_OUTPUT_CAN_BECOME_PASS: bool = false;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s1_phase1_authority_ceiling_is_fail_closed() {
        const { assert!(!S1_DIRECT_FINDING_CREATION_ALLOWED) };
        const { assert!(!S1_FACT_VERIFIED_MINTING_ALLOWED) };
        const { assert!(!S1_POLICY_OVERRIDE_ALLOWED) };
        const { assert!(!S1_KERNEL_OVERRIDE_ALLOWED) };
        const { assert!(!S1_RECONCILER_OVERRIDE_ALLOWED) };
        const { assert!(!S1_GRAPH_OR_MODEL_AUTHORITY_ALLOWED) };
        const { assert!(!S1_NETWORK_ACCESS_ALLOWED) };
        const { assert!(!S1_FORGE_DISCOVERY_ALLOWED) };
        const { assert!(!S1_PROVIDER_CREDENTIALS_ALLOWED) };
        const { assert!(!S1_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!S1_LLM_OR_EXTERNAL_ENGINE_ALLOWED) };
        const { assert!(!S1_MISSING_OUTPUT_CAN_BECOME_PASS) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }
}
