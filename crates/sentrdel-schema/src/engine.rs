//! External evidence-engine manifests and run metadata.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NetworkRequirement {
    None,
    Optional,
    Required,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineManifest {
    pub schema_version: String,
    pub engine_id: String,
    pub adapter_version: String,
    pub executable_source: String,
    pub executable_digest: Option<String>,
    pub expected_version_constraint: Option<String>,
    pub input_dialects: Vec<String>,
    pub output_dialects: Vec<String>,
    pub capabilities: Vec<String>,
    pub timeout_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    /// Child-process environment authority is deny-by-default. Only names in
    /// this trusted manifest allowlist may be considered for explicit passing
    /// by the future engine runner; repository data must not widen this list.
    pub allowed_environment_names: Vec<String>,
    pub network_requirement: NetworkRequirement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TerminationReason {
    Completed,
    NonZero,
    Timeout,
    OutputCap,
    SpawnFailed,
    MalformedOutput,
    PolicyBlocked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineRun {
    pub schema_version: String,
    pub run_id: String,
    pub engine_manifest_digest: String,
    pub input_digests: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub exit_status: Option<i32>,
    pub termination_reason: TerminationReason,
    pub stdout_digest: Option<String>,
    pub stderr_digest: Option<String>,
    pub produced_evidence_ids: Vec<String>,
    pub coverage_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::EngineManifest;

    fn manifest_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": "1",
            "engine_id": "fixture",
            "adapter_version": "1",
            "executable_source": "trusted-config",
            "executable_digest": null,
            "expected_version_constraint": null,
            "input_dialects": ["repo"],
            "output_dialects": ["json"],
            "capabilities": ["fixture"],
            "timeout_ms": 1000,
            "max_stdout_bytes": 4096,
            "max_stderr_bytes": 4096,
            "allowed_environment_names": ["PATH", "LANG"],
            "network_requirement": "NONE"
        })
    }

    #[test]
    fn manifest_requires_explicit_environment_allowlist() {
        let value = manifest_json();
        let manifest: EngineManifest =
            serde_json::from_value(value).expect("explicit allowlist manifest should decode");
        assert_eq!(manifest.allowed_environment_names, ["PATH", "LANG"]);

        let mut missing = manifest_json();
        missing
            .as_object_mut()
            .expect("fixture object")
            .remove("allowed_environment_names");
        assert!(serde_json::from_value::<EngineManifest>(missing).is_err());
    }
}
