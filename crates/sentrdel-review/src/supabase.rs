//! Supabase R2 provider contract.
//!
//! This module defines only the versioned Sentrdel-owned provider manifest and
//! provider coverage capability names. It grants no Finding or policy authority.

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::pack::{SecurityPackManifest, SourceProvenance};

pub const SUPABASE_R2_PACK_ID: &str = "sentrdel.supabase.static-posture";
pub const SUPABASE_R2_PACK_VERSION: &str = "1";
pub const SUPABASE_PROVIDER: &str = "supabase";

pub const COVERAGE_DETECTION: &str = "DETECTION";
pub const COVERAGE_STATIC_POSTURE_DATABASE: &str = "STATIC_POSTURE_DATABASE";
pub const COVERAGE_STATIC_POSTURE_STORAGE: &str = "STATIC_POSTURE_STORAGE";
pub const COVERAGE_STATIC_POSTURE_AUTH_CONFIG: &str = "STATIC_POSTURE_AUTH_CONFIG";
pub const COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS: &str = "STATIC_POSTURE_EDGE_FUNCTIONS";
pub const COVERAGE_STATIC_POSTURE_KEY_BOUNDARY: &str = "STATIC_POSTURE_KEY_BOUNDARY";
pub const COVERAGE_LIVE_POSTURE: &str = "LIVE_POSTURE";
pub const COVERAGE_BUSINESS_LOGIC: &str = "BUSINESS_LOGIC";
pub const COVERAGE_RUNTIME: &str = "RUNTIME";

pub const SUPABASE_R2_COVERAGE_DIMENSIONS: &[&str] = &[
    COVERAGE_DETECTION,
    COVERAGE_STATIC_POSTURE_DATABASE,
    COVERAGE_STATIC_POSTURE_STORAGE,
    COVERAGE_STATIC_POSTURE_AUTH_CONFIG,
    COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS,
    COVERAGE_STATIC_POSTURE_KEY_BOUNDARY,
    COVERAGE_LIVE_POSTURE,
    COVERAGE_BUSINESS_LOGIC,
    COVERAGE_RUNTIME,
];

#[must_use]
pub fn manifest() -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: SUPABASE_R2_PACK_ID.to_owned(),
        version: SUPABASE_R2_PACK_VERSION.to_owned(),
        provider_or_framework: SUPABASE_PROVIDER.to_owned(),
        source_provenance: SourceProvenance {
            source_id: "sentrdel-owned".to_owned(),
            exact_ref: "specs/002-supabase-static-posture".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec!["provider-detection".to_owned()],
        evidence_capabilities: vec!["static-posture-evidence".to_owned()],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: SUPABASE_R2_COVERAGE_DIMENSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_versioned_provider_owned_and_dependency_free() {
        let value = manifest();
        assert_eq!(value.schema_version, SCHEMA_V1);
        assert_eq!(value.pack_id, SUPABASE_R2_PACK_ID);
        assert_eq!(value.version, SUPABASE_R2_PACK_VERSION);
        assert_eq!(value.provider_or_framework, SUPABASE_PROVIDER);
        assert_eq!(value.source_provenance.source_id, "sentrdel-owned");
        assert_eq!(value.source_provenance.license_expression, "Apache-2.0");
        assert!(value.required_engines.is_empty());
        assert!(value.required_features.is_empty());
    }

    #[test]
    fn manifest_exposes_exact_r2_coverage_dimensions() {
        let value = manifest();
        let expected: Vec<String> = SUPABASE_R2_COVERAGE_DIMENSIONS
            .iter()
            .map(|dimension| (*dimension).to_owned())
            .collect();
        assert_eq!(value.coverage_dimensions, expected);
    }

    #[test]
    fn manifest_has_evidence_but_no_finding_or_policy_override_capability() {
        let value = manifest();
        assert!(value.declares_capability("static-posture-evidence"));
        assert!(!value.declares_capability("finding"));
        assert!(!value.declares_capability("policy-override"));
    }
}
