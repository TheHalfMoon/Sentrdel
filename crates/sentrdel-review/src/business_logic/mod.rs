//! R3 static business-logic pack and bounded cross-layer analysis contracts.
//!
//! This module owns only static Evidence/Coverage inputs. It grants no Finding,
//! policy, target-execution, provider-credential, network, or runtime authority.

pub mod actor;
#[path = "data.rs"]
mod data_raw;
#[path = "data_gate.rs"]
pub mod data;
#[path = "guard_tdz_scope.rs"]
pub mod guard;
pub mod invariant;
pub mod model;
pub mod ordering;
#[path = "route_gate.rs"]
pub mod route;
#[path = "value_final.rs"]
pub mod value;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::pack::{SecurityPackManifest, SourceProvenance};

use crate::pack_registry::{PackRegistryError, SecurityPackRegistry, ValidatedPackManifest};

pub const R3_BUSINESS_LOGIC_PACK_ID: &str = "sentrdel.business-logic.static";
pub const R3_BUSINESS_LOGIC_PACK_VERSION: &str = "1";
pub const R3_BUSINESS_LOGIC_PROVIDER: &str = "cross-layer";
pub const COVERAGE_BUSINESS_LOGIC: &str = "BUSINESS_LOGIC";
pub const COVERAGE_CROSS_LAYER_BUSINESS_LOGIC: &str = "CROSS_LAYER_BUSINESS_LOGIC";
pub const R3_TARGET_EXECUTION_ALLOWED: bool = false;
pub const R3_PROVIDER_CREDENTIALS_ALLOWED: bool = false;
pub const R3_DIRECT_FINDING_CREATION_ALLOWED: bool = false;

pub const R3_BUSINESS_LOGIC_COVERAGE_AREAS: &[&str] = &[
    "ROUTES",
    "ACTOR_IDENTITY",
    "GUARDS",
    "VALUE_ORIGINS",
    "DATA_OPERATIONS",
    "LOCAL_LINKING",
    "SEMANTIC_LINKING",
    "R2_PROVIDER_CORRELATION",
    "PROJECT_INVARIANTS",
    "INVARIANT_EVALUATION",
];

#[must_use]
pub fn manifest() -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: R3_BUSINESS_LOGIC_PACK_ID.to_owned(),
        version: R3_BUSINESS_LOGIC_PACK_VERSION.to_owned(),
        provider_or_framework: R3_BUSINESS_LOGIC_PROVIDER.to_owned(),
        source_provenance: SourceProvenance {
            source_id: "sentrdel-owned".to_owned(),
            exact_ref: "specs/003-business-logic-invariants".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec!["business-logic-detection".to_owned()],
        evidence_capabilities: vec!["cross-layer-authorization-evidence".to_owned()],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: vec![COVERAGE_BUSINESS_LOGIC.to_owned()],
    }
}

pub fn register_r3_pack(
    registry: &mut SecurityPackRegistry,
) -> Result<&ValidatedPackManifest, PackRegistryError> {
    registry.register(manifest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack_registry::{PackCoverageDimension, PackOutputKind};

    #[test]
    fn manifest_is_versioned_dependency_free_and_business_logic_only() {
        let value = manifest();
        assert_eq!(value.schema_version, SCHEMA_V1);
        assert_eq!(value.pack_id, R3_BUSINESS_LOGIC_PACK_ID);
        assert_eq!(value.version, R3_BUSINESS_LOGIC_PACK_VERSION);
        assert_eq!(value.provider_or_framework, R3_BUSINESS_LOGIC_PROVIDER);
        assert_eq!(value.source_provenance.source_id, "sentrdel-owned");
        assert!(value.required_engines.is_empty());
        assert!(value.required_features.is_empty());
        assert_eq!(value.coverage_dimensions, vec![COVERAGE_BUSINESS_LOGIC]);
    }

    #[test]
    fn pack_registration_preserves_evidence_coverage_only_authority() {
        let mut registry = SecurityPackRegistry::new();
        let registered = register_r3_pack(&mut registry).expect("register R3 pack");
        assert_eq!(registered.pack_id(), R3_BUSINESS_LOGIC_PACK_ID);
        assert!(
            registered
                .coverage_dimensions()
                .contains(&PackCoverageDimension::BusinessLogic)
        );
        assert_eq!(
            ValidatedPackManifest::output_kinds(),
            [PackOutputKind::Evidence, PackOutputKind::Coverage]
        );
        assert!(!registered.manifest().declares_capability("finding"));
        assert!(!registered.manifest().declares_capability("policy-override"));
    }

    #[test]
    fn detailed_provider_coverage_does_not_widen_r1_manifest_vocabulary() {
        assert_eq!(
            COVERAGE_CROSS_LAYER_BUSINESS_LOGIC,
            "CROSS_LAYER_BUSINESS_LOGIC"
        );
        assert!(
            !manifest()
                .coverage_dimensions
                .contains(&COVERAGE_CROSS_LAYER_BUSINESS_LOGIC.to_owned())
        );
        assert_eq!(R3_BUSINESS_LOGIC_COVERAGE_AREAS.len(), 10);
    }

    #[test]
    fn r3_manifest_grants_no_execution_credentials_or_finding_authority() {
        const { assert!(!R3_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!R3_PROVIDER_CREDENTIALS_ALLOWED) };
        const { assert!(!R3_DIRECT_FINDING_CREATION_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }
}
