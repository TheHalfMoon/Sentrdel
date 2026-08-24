//! Explicit analysis and provider coverage state.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageState {
    Covered,
    Partial,
    Unsupported,
    Unavailable,
    Failed,
    TimedOut,
    SkippedByPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderCoverageDimension {
    Detection,
    StaticPosture,
    CredentialedLivePosture,
    CrossLayerBusinessLogic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageRecord {
    pub schema_version: String,
    pub coverage_id: String,
    pub capability: String,
    pub scope: String,
    pub producer: Option<String>,
    pub provider_dimension: Option<ProviderCoverageDimension>,
    pub state: CoverageState,
    pub reason_code: Option<String>,
    pub details: Option<String>,
    pub input_digests: Vec<String>,
    pub observed_at: String,
}

impl CoverageRecord {
    pub fn is_complete(&self) -> bool {
        self.state == CoverageState::Covered
    }

    pub fn is_gap(&self) -> bool {
        !self.is_complete()
    }

    /// Provider detection is intentionally insufficient to claim static/live
    /// security coverage.
    pub fn can_support_provider_security_posture(&self) -> bool {
        matches!(
            self.provider_dimension,
            Some(
                ProviderCoverageDimension::StaticPosture
                    | ProviderCoverageDimension::CredentialedLivePosture
                    | ProviderCoverageDimension::CrossLayerBusinessLogic
            )
        ) && self.state == CoverageState::Covered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: CoverageState) -> CoverageRecord {
        CoverageRecord {
            schema_version: "1".to_owned(),
            coverage_id: "coverage:fixture".to_owned(),
            capability: "fixture".to_owned(),
            scope: ".".to_owned(),
            producer: None,
            provider_dimension: None,
            state,
            reason_code: None,
            details: None,
            input_digests: Vec::new(),
            observed_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn failures_never_look_complete() {
        for state in [
            CoverageState::Partial,
            CoverageState::Unsupported,
            CoverageState::Unavailable,
            CoverageState::Failed,
            CoverageState::TimedOut,
            CoverageState::SkippedByPolicy,
        ] {
            assert!(record(state).is_gap());
        }
    }

    #[test]
    fn provider_detection_is_not_posture() {
        let mut value = record(CoverageState::Covered);
        value.provider_dimension = Some(ProviderCoverageDimension::Detection);
        assert!(!value.can_support_provider_security_posture());
    }
}
