//! Provider/framework Security Pack manifest contract.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceProvenance {
    pub source_id: String,
    pub exact_ref: String,
    pub license_expression: String,
    pub integrity_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityPackManifest {
    pub schema_version: String,
    pub pack_id: String,
    pub version: String,
    pub provider_or_framework: String,
    pub source_provenance: SourceProvenance,
    pub detection_capabilities: Vec<String>,
    pub evidence_capabilities: Vec<String>,
    pub required_engines: Vec<String>,
    pub required_features: Vec<String>,
    pub coverage_dimensions: Vec<String>,
}

impl SecurityPackManifest {
    /// Security packs are evidence producers only; the manifest intentionally
    /// contains no finding/policy-override capability field.
    pub fn declares_capability(&self, capability: &str) -> bool {
        self.evidence_capabilities
            .iter()
            .any(|candidate| candidate == capability)
    }
}
