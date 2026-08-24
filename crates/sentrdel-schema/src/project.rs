//! Detected project/profile state. Detection never implies security posture.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackStatus {
    Available,
    NotInstalled,
    NotImplemented,
    Partial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectedProvider {
    pub provider_id: String,
    pub evidence_ids: Vec<String>,
    pub detection_confidence: String,
    pub pack_status: PackStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectedFramework {
    pub framework_id: String,
    pub evidence_ids: Vec<String>,
    pub detection_confidence: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectProfile {
    pub schema_version: String,
    pub repository_id: String,
    pub repository_root_digest: String,
    pub languages: Vec<String>,
    pub package_ecosystems: Vec<String>,
    pub ci_systems: Vec<String>,
    pub mcp_configurations: Vec<String>,
    pub detected_providers: Vec<DetectedProvider>,
    pub detected_frameworks: Vec<DetectedFramework>,
    pub security_packs: Vec<String>,
    pub created_at: String,
    pub refreshed_at: String,
}

impl ProjectProfile {
    pub fn has_provider(&self, provider_id: &str) -> bool {
        self.detected_providers
            .iter()
            .any(|provider| provider.provider_id == provider_id)
    }
}
