//! Bounded repository-visible Supabase Auth/API configuration posture for R2.
//!
//! This module consumes only the already-bounded `supabase/config.toml` posture
//! produced by `config`. It does not reparse raw target bytes, contact Supabase,
//! inspect hosted settings, execute target code, or create Findings. Unsupported
//! or ambiguous Auth/API configuration remains an explicit coverage gap.

use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension};

use super::COVERAGE_STATIC_POSTURE_AUTH_CONFIG;
use super::config::{
    ConfigDiagnostic, ConfigParseCoverage, SUPABASE_CONFIG_PATH, SupabaseConfigPosture,
};

const PRODUCER_ID: &str = "sentrdel.supabase.auth-api-config";
pub const AUTH_API_TARGET_EXECUTION_ALLOWED: bool = false;
pub const AUTH_API_PROVIDER_NETWORK_ALLOWED: bool = false;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthApiConfigPosture {
    pub repository_api_enabled: Option<bool>,
    pub repository_exposed_schema_count: Option<usize>,
    pub auth_api_coverage: CoverageRecord,
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthApiConfigError {
    EmptyObservedAt,
    WrongConfigPath,
    EmptyContentDigest,
}

impl fmt::Display for AuthApiConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyObservedAt => formatter.write_str("observed_at must not be empty"),
            Self::WrongConfigPath => formatter
                .write_str("Auth/API posture accepts only bounded supabase/config.toml posture"),
            Self::EmptyContentDigest => {
                formatter.write_str("Auth/API posture requires a config content digest")
            }
        }
    }
}

impl Error for AuthApiConfigError {}

#[must_use]
fn auth_api_diagnostic(diagnostic: &ConfigDiagnostic) -> bool {
    let table_relevant = diagnostic.table.as_deref().is_some_and(|table| {
        table == "auth" || table == "api" || table.starts_with("auth.") || table.starts_with("api.")
    });
    let root_relevant = diagnostic.table.is_none()
        && diagnostic
            .key
            .as_deref()
            .is_some_and(|key| key == "auth" || key == "api");
    table_relevant || root_relevant
}

pub fn assess_auth_api_config(
    posture: &SupabaseConfigPosture,
    observed_at: &str,
) -> Result<AuthApiConfigPosture, AuthApiConfigError> {
    if observed_at.trim().is_empty() {
        return Err(AuthApiConfigError::EmptyObservedAt);
    }
    if posture.provenance.path.as_str() != SUPABASE_CONFIG_PATH {
        return Err(AuthApiConfigError::WrongConfigPath);
    }
    if posture.provenance.content_digest.trim().is_empty() {
        return Err(AuthApiConfigError::EmptyContentDigest);
    }

    let relevant_diagnostic_count = posture
        .diagnostics
        .iter()
        .filter(|diagnostic| auth_api_diagnostic(diagnostic))
        .count();
    let api_enabled = posture.api_enabled.as_ref().map(|value| value.value);
    let schema_count = posture
        .api_exposed_schemas
        .as_ref()
        .map(|value| value.value.len());

    let missing_required_api_fact = match api_enabled {
        Some(true) => schema_count.is_none(),
        Some(false) => false,
        None => true,
    };
    let partial = relevant_diagnostic_count > 0
        || missing_required_api_fact
        || posture.parse_coverage == ConfigParseCoverage::Partial && relevant_diagnostic_count > 0;

    let (state, reason_code, details) = if partial {
        (
            CoverageState::Partial,
            Some("UNSUPPORTED_OR_AMBIGUOUS_AUTH_API_CONFIG".to_owned()),
            Some(format!(
                "Repository-visible Auth/API configuration is only partially supported or ambiguous; relevant_diagnostics={relevant_diagnostic_count}. Hosted Auth/API state remains UNKNOWN and LIVE_POSTURE was NOT_EXECUTED."
            )),
        )
    } else {
        (
            CoverageState::Covered,
            None,
            Some(
                "Supported repository-visible Auth/API configuration was analyzed completely for the bounded R2 subset. Hosted Auth/API state remains UNKNOWN and LIVE_POSTURE was NOT_EXECUTED."
                    .to_owned(),
            ),
        )
    };

    let coverage = CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: format!(
            "coverage:{PRODUCER_ID}:{}",
            posture.provenance.content_digest
        ),
        capability: COVERAGE_STATIC_POSTURE_AUTH_CONFIG.to_owned(),
        scope: posture.provenance.path.as_str().to_owned(),
        producer: Some(PRODUCER_ID.to_owned()),
        provider_dimension: Some(ProviderCoverageDimension::StaticPosture),
        state,
        reason_code,
        details,
        input_digests: vec![posture.provenance.content_digest.clone()],
        observed_at: observed_at.to_owned(),
    };

    Ok(AuthApiConfigPosture {
        repository_api_enabled: api_enabled,
        repository_exposed_schema_count: schema_count,
        auth_api_coverage: coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supabase::config::{SupabaseConfigLimits, parse_supabase_config};
    use crate::view::NormalizedRepoPath;

    const OBSERVED_AT: &str = "2026-08-31T22:50:00Z";

    fn parse(text: &str) -> SupabaseConfigPosture {
        parse_supabase_config(
            &NormalizedRepoPath::parse(SUPABASE_CONFIG_PATH, 4096).unwrap(),
            "sha256:r2-t021-config",
            text.as_bytes(),
            SupabaseConfigLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn explicit_supported_api_configuration_is_covered_but_not_hosted_truth() {
        let posture = parse("[api]\nenabled = true\nschemas = [\"public\", \"storage\"]\n");
        let assessment = assess_auth_api_config(&posture, OBSERVED_AT).unwrap();

        assert_eq!(assessment.repository_api_enabled, Some(true));
        assert_eq!(assessment.repository_exposed_schema_count, Some(2));
        assert_eq!(assessment.auth_api_coverage.state, CoverageState::Covered);
        assert_eq!(
            assessment.auth_api_coverage.capability,
            COVERAGE_STATIC_POSTURE_AUTH_CONFIG
        );
        let details = assessment.auth_api_coverage.details.unwrap();
        assert!(details.contains("Hosted Auth/API state remains UNKNOWN"));
        assert!(details.contains("LIVE_POSTURE was NOT_EXECUTED"));
    }

    #[test]
    fn enabled_api_without_supported_schema_set_is_partial_not_clean() {
        let posture = parse("[api]\nenabled = true\n");
        let assessment = assess_auth_api_config(&posture, OBSERVED_AT).unwrap();

        assert_eq!(assessment.auth_api_coverage.state, CoverageState::Partial);
        assert_eq!(
            assessment.auth_api_coverage.reason_code.as_deref(),
            Some("UNSUPPORTED_OR_AMBIGUOUS_AUTH_API_CONFIG")
        );
    }

    #[test]
    fn unsupported_repository_auth_settings_remain_visible_coverage_gaps() {
        let posture = parse(
            "[api]\nenabled = true\nschemas = [\"public\"]\n[auth]\nenabled = true\nsite_url = \"https://example.invalid\"\n",
        );
        let assessment = assess_auth_api_config(&posture, OBSERVED_AT).unwrap();

        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Partial);
        assert_eq!(assessment.auth_api_coverage.state, CoverageState::Partial);
        assert!(
            assessment
                .auth_api_coverage
                .details
                .as_deref()
                .unwrap()
                .contains("relevant_diagnostics=2")
        );
    }

    #[test]
    fn unrelated_edge_function_parser_gap_does_not_poison_auth_api_dimension() {
        let posture = parse(
            "[api]\nenabled = true\nschemas = [\"public\"]\n[functions.webhook]\nunknown_security_toggle = true\n",
        );
        let assessment = assess_auth_api_config(&posture, OBSERVED_AT).unwrap();

        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Partial);
        assert_eq!(assessment.auth_api_coverage.state, CoverageState::Covered);
    }

    #[test]
    fn disabled_repository_api_is_a_supported_static_fact_without_hosted_claim() {
        let posture = parse("[api]\nenabled = false\n");
        let assessment = assess_auth_api_config(&posture, OBSERVED_AT).unwrap();

        assert_eq!(assessment.repository_api_enabled, Some(false));
        assert_eq!(assessment.auth_api_coverage.state, CoverageState::Covered);
    }

    #[test]
    fn timestamp_and_provenance_are_required_and_execution_remains_forbidden() {
        let posture = parse("[api]\nenabled = false\n");
        assert_eq!(
            assess_auth_api_config(&posture, "").unwrap_err(),
            AuthApiConfigError::EmptyObservedAt
        );
        const { assert!(!AUTH_API_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!AUTH_API_PROVIDER_NETWORK_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }
}
