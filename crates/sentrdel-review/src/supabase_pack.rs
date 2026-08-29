//! Versioned Supabase R2 Security Pack manifest and capability names.
//!
//! The pack is declarative provider metadata only. It grants no Finding,
//! policy, verification, process, filesystem, credential, or network authority.

use sentrdel_schema::{
    SCHEMA_V1,
    pack::{SecurityPackManifest, SourceProvenance},
};

pub const SUPABASE_R2_PACK_ID: &str = "sentrdel.supabase.static-posture";
pub const SUPABASE_R2_PACK_VERSION: &str = "1";
pub const SUPABASE_R2_PROVIDER: &str = "supabase";
pub const SUPABASE_R2_SOURCE_ID: &str = "sentrdel-owned";
pub const SUPABASE_R2_EXACT_REF: &str = "specs/002-supabase-static-posture";

pub const SUPABASE_CAPABILITY_DETECTION: &str = "supabase.detection";
pub const SUPABASE_CAPABILITY_STATIC_DATABASE: &str = "supabase.static-posture.database";
pub const SUPABASE_CAPABILITY_STATIC_STORAGE: &str = "supabase.static-posture.storage";
pub const SUPABASE_CAPABILITY_STATIC_AUTH_CONFIG: &str = "supabase.static-posture.auth-config";
pub const SUPABASE_CAPABILITY_STATIC_EDGE_FUNCTIONS: &str =
    "supabase.static-posture.edge-functions";
pub const SUPABASE_CAPABILITY_STATIC_KEY_BOUNDARY: &str = "supabase.static-posture.key-boundary";
pub const SUPABASE_CAPABILITY_LIVE_POSTURE: &str = "supabase.live-posture";
pub const SUPABASE_CAPABILITY_BUSINESS_LOGIC: &str = "supabase.business-logic";
pub const SUPABASE_CAPABILITY_RUNTIME: &str = "supabase.runtime";

pub const SUPABASE_R2_STATIC_POSTURE_CAPABILITIES: &[&str] = &[
    SUPABASE_CAPABILITY_STATIC_DATABASE,
    SUPABASE_CAPABILITY_STATIC_STORAGE,
    SUPABASE_CAPABILITY_STATIC_AUTH_CONFIG,
    SUPABASE_CAPABILITY_STATIC_EDGE_FUNCTIONS,
    SUPABASE_CAPABILITY_STATIC_KEY_BOUNDARY,
];

/// Build the reviewed R2 Supabase pack manifest using the generic R1 pack
/// coverage dimensions. Provider-specific subdimensions remain capability names
/// so the public R1 coverage enum does not need provider-specific variants.
#[must_use]
pub fn supabase_r2_manifest() -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: SUPABASE_R2_PACK_ID.to_owned(),
        version: SUPABASE_R2_PACK_VERSION.to_owned(),
        provider_or_framework: SUPABASE_R2_PROVIDER.to_owned(),
        source_provenance: SourceProvenance {
            source_id: SUPABASE_R2_SOURCE_ID.to_owned(),
            exact_ref: SUPABASE_R2_EXACT_REF.to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec![SUPABASE_CAPABILITY_DETECTION.to_owned()],
        evidence_capabilities: SUPABASE_R2_STATIC_POSTURE_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect(),
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: vec![
            "DETECTION".to_owned(),
            "STATIC_POSTURE".to_owned(),
            "LIVE_POSTURE".to_owned(),
            "BUSINESS_LOGIC".to_owned(),
            "RUNTIME".to_owned(),
        ],
    }
}
