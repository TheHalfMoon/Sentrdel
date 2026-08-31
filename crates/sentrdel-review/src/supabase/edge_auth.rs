//! Bounded Supabase Edge Function authorization posture for R2.
//!
//! This module combines repository-visible `verify_jwt` configuration with a
//! deliberately narrow source pattern for explicit replacement authorization.
//! It does not execute Edge Functions, contact Supabase, inspect hosted state,
//! or create Findings. `verify_jwt = false` remains a posture signal rather than
//! an unconditional vulnerability.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension};
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};
use serde_json::Value;

use super::COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS;
use super::config::{ConfigParseCoverage, SupabaseConfigPosture};
use crate::view::NormalizedRepoPath;

const PRODUCER_ID: &str = "sentrdel.supabase.edge-function-auth";
const PRODUCER_VERSION: &str = "1";
pub const DEFAULT_MAX_EDGE_AUTH_SOURCE_BYTES: usize = 1024 * 1024;
pub const EDGE_AUTH_TARGET_EXECUTION_ALLOWED: bool = false;
pub const EDGE_AUTH_PROVIDER_NETWORK_ALLOWED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformJwtVerification {
    Enabled,
    Disabled,
    Unknown,
}

impl PlatformJwtVerification {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "ENABLED",
            Self::Disabled => "DISABLED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupportedReplacementAuth {
    Proven,
    NotProven,
    Unknown,
}

impl SupportedReplacementAuth {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "PROVEN",
            Self::NotProven => "NOT_PROVEN",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeAuthLimits {
    pub max_source_bytes: usize,
}

impl Default for EdgeAuthLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_EDGE_AUTH_SOURCE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeAuthPosture {
    pub function_name: String,
    pub platform_jwt_verification: PlatformJwtVerification,
    pub supported_replacement_auth: SupportedReplacementAuth,
    pub coverage: CoverageRecord,
    pub evidence: Option<Evidence>,
}

#[derive(Debug)]
pub enum EdgeAuthError {
    InvalidLimits,
    EmptyFunctionName,
    InvalidFunctionPath,
    EmptySourceContentDigest,
    EmptyCapturedAt,
    SourceTooLarge { bytes: usize, max: usize },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for EdgeAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("Edge Function auth limits must be non-zero"),
            Self::EmptyFunctionName => formatter.write_str("Edge Function name must not be empty"),
            Self::InvalidFunctionPath => formatter.write_str(
                "Edge Function auth source must be under supabase/functions/<function_name>/",
            ),
            Self::EmptySourceContentDigest => {
                formatter.write_str("Edge Function source content digest must not be empty")
            }
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::SourceTooLarge { bytes, max } => write!(
                formatter,
                "Edge Function auth source size {bytes} exceeds cap {max}"
            ),
            Self::Evidence(error) => write!(formatter, "cannot seal Edge Function auth evidence: {error}"),
        }
    }
}

impl Error for EdgeAuthError {}

impl From<EvidenceValidationError> for EdgeAuthError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn assess_edge_function_auth(
    config: &SupabaseConfigPosture,
    function_name: &str,
    source_path: &NormalizedRepoPath,
    source: &str,
    source_content_digest: &str,
    captured_at: &str,
    limits: EdgeAuthLimits,
) -> Result<EdgeAuthPosture, EdgeAuthError> {
    if limits.max_source_bytes == 0 {
        return Err(EdgeAuthError::InvalidLimits);
    }
    if function_name.trim().is_empty() {
        return Err(EdgeAuthError::EmptyFunctionName);
    }
    let expected_prefix = format!("supabase/functions/{function_name}/");
    if !source_path.as_str().starts_with(&expected_prefix) {
        return Err(EdgeAuthError::InvalidFunctionPath);
    }
    if source_content_digest.trim().is_empty() {
        return Err(EdgeAuthError::EmptySourceContentDigest);
    }
    if captured_at.trim().is_empty() {
        return Err(EdgeAuthError::EmptyCapturedAt);
    }
    if source.len() > limits.max_source_bytes {
        return Err(EdgeAuthError::SourceTooLarge {
            bytes: source.len(),
            max: limits.max_source_bytes,
        });
    }

    let platform_jwt_verification = config
        .edge_function_auth
        .get(function_name)
        .and_then(|posture| posture.platform_jwt_verification.as_ref())
        .map_or(PlatformJwtVerification::Unknown, |value| {
            if value.value {
                PlatformJwtVerification::Enabled
            } else {
                PlatformJwtVerification::Disabled
            }
        });

    let replacement_pattern = supported_replacement_auth_pattern(source);
    let supported_replacement_auth = match platform_jwt_verification {
        PlatformJwtVerification::Disabled => {
            if replacement_pattern {
                SupportedReplacementAuth::Proven
            } else {
                SupportedReplacementAuth::NotProven
            }
        }
        PlatformJwtVerification::Enabled => SupportedReplacementAuth::Unknown,
        PlatformJwtVerification::Unknown => {
            if replacement_pattern {
                SupportedReplacementAuth::Proven
            } else {
                SupportedReplacementAuth::Unknown
            }
        }
    };

    let function_diagnostic_prefix = format!("functions.{function_name}");
    let relevant_diagnostics = config
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic
                .table
                .as_deref()
                .is_some_and(|table| table == function_diagnostic_prefix)
        })
        .count();

    let partial = relevant_diagnostics > 0
        || platform_jwt_verification == PlatformJwtVerification::Unknown
        || config.parse_coverage == ConfigParseCoverage::Partial && relevant_diagnostics > 0;
    let (coverage_state, reason_code) = if partial {
        (
            CoverageState::Partial,
            Some("UNSUPPORTED_OR_AMBIGUOUS_EDGE_AUTH".to_owned()),
        )
    } else {
        (CoverageState::Covered, None)
    };

    let coverage = CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: format!(
            "coverage:{PRODUCER_ID}:{function_name}:{}",
            source_content_digest
        ),
        capability: COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS.to_owned(),
        scope: source_path.as_str().to_owned(),
        producer: Some(PRODUCER_ID.to_owned()),
        provider_dimension: Some(ProviderCoverageDimension::StaticPosture),
        state: coverage_state,
        reason_code,
        details: Some(format!(
            "Repository-visible Edge Function auth posture: platform_jwt_verification={}, supported_replacement_auth={}, relevant_config_diagnostics={relevant_diagnostics}. Hosted authorization state remains UNKNOWN and LIVE_POSTURE was NOT_EXECUTED.",
            platform_jwt_verification.as_str(),
            supported_replacement_auth.as_str(),
        )),
        input_digests: vec![
            config.provenance.content_digest.clone(),
            source_content_digest.to_owned(),
        ],
        observed_at: captured_at.to_owned(),
    };

    let evidence = if platform_jwt_verification == PlatformJwtVerification::Disabled
        && supported_replacement_auth == SupportedReplacementAuth::NotProven
    {
        Some(disabled_without_replacement_evidence(
            function_name,
            source_path,
            source_content_digest,
            captured_at,
        )?)
    } else {
        None
    };

    Ok(EdgeAuthPosture {
        function_name: function_name.to_owned(),
        platform_jwt_verification,
        supported_replacement_auth,
        coverage,
        evidence,
    })
}

fn supported_replacement_auth_pattern(source: &str) -> bool {
    let mut authorization_header = false;
    let mut verified_user = false;

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('*') {
            continue;
        }

        let assignment_like = line.starts_with("const ") || line.starts_with("let ");
        if assignment_like
            && (line.contains(".headers.get(\"Authorization\")")
                || line.contains(".headers.get('Authorization')")
                || line.contains(".headers.get(\"authorization\")")
                || line.contains(".headers.get('authorization')"))
        {
            authorization_header = true;
        }

        if line.contains("await ") && line.contains(".auth.getUser(") {
            verified_user = true;
        }
    }

    authorization_header && verified_user
}

fn disabled_without_replacement_evidence(
    function_name: &str,
    source_path: &NormalizedRepoPath,
    source_content_digest: &str,
    captured_at: &str,
) -> Result<Evidence, EvidenceValidationError> {
    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "platform_jwt_verification".to_owned(),
        Value::String(PlatformJwtVerification::Disabled.as_str().to_owned()),
    );
    attributes.insert(
        "supported_replacement_auth".to_owned(),
        Value::String(SupportedReplacementAuth::NotProven.as_str().to_owned()),
    );
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "hosted_authorization_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "live_posture".to_owned(),
        Value::String("NOT_EXECUTED".to_owned()),
    );

    authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![source_content_digest.to_owned()],
        observation: format!(
            "Edge Function {function_name} has repository-visible platform JWT verification disabled; no supported explicit replacement authorization pattern was proven"
        ),
        security_interpretation: None,
        category: "supabase_edge_function_auth_posture".to_owned(),
        epistemic_class: EpistemicClass::Inference,
        confidence_band: None,
        subjects: vec![EvidenceSubject {
            kind: "supabase_edge_function".to_owned(),
            id: function_name.to_owned(),
        }],
        locations: vec![EvidenceLocation {
            repo_relative_path: source_path.as_str().to_owned(),
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            symbol: None,
            content_digest: Some(source_content_digest.to_owned()),
        }],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::config::{SUPABASE_CONFIG_PATH, SupabaseConfigLimits, parse_supabase_config};

    const CAPTURED_AT: &str = "2026-09-01T00:10:00Z";
    const CONFIG_DIGEST: &str = "sha256:r2-t022-config";
    const SOURCE_DIGEST: &str = "sha256:r2-t022-source";

    fn path(value: &str) -> NormalizedRepoPath {
        NormalizedRepoPath::parse(value, 4096).unwrap()
    }

    fn config(text: &str) -> SupabaseConfigPosture {
        parse_supabase_config(
            &path(SUPABASE_CONFIG_PATH),
            CONFIG_DIGEST,
            text.as_bytes(),
            SupabaseConfigLimits::default(),
        )
        .unwrap()
    }

    fn assess(config: &SupabaseConfigPosture, source: &str) -> EdgeAuthPosture {
        assess_edge_function_auth(
            config,
            "webhook",
            &path("supabase/functions/webhook/index.ts"),
            source,
            SOURCE_DIGEST,
            CAPTURED_AT,
            EdgeAuthLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn platform_verification_enabled_is_covered_without_misuse_evidence() {
        let posture = config("[functions.webhook]\nverify_jwt = true\n");
        let result = assess(&posture, "Deno.serve(() => new Response('ok'));\n");

        assert_eq!(result.platform_jwt_verification, PlatformJwtVerification::Enabled);
        assert_eq!(result.supported_replacement_auth, SupportedReplacementAuth::Unknown);
        assert_eq!(result.coverage.state, CoverageState::Covered);
        assert!(result.evidence.is_none());
    }

    #[test]
    fn disabled_verification_with_supported_explicit_replacement_auth_does_not_escalate() {
        let posture = config("[functions.webhook]\nverify_jwt = false\n");
        let source = "const auth = req.headers.get(\"Authorization\");\nconst { data } = await supabase.auth.getUser(auth);\n";
        let result = assess(&posture, source);

        assert_eq!(result.platform_jwt_verification, PlatformJwtVerification::Disabled);
        assert_eq!(result.supported_replacement_auth, SupportedReplacementAuth::Proven);
        assert_eq!(result.coverage.state, CoverageState::Covered);
        assert!(result.evidence.is_none());
    }

    #[test]
    fn disabled_verification_without_supported_replacement_emits_bounded_inference() {
        let posture = config("[functions.webhook]\nverify_jwt = false\n");
        let result = assess(&posture, "Deno.serve(() => new Response('ok'));\n");

        assert_eq!(result.supported_replacement_auth, SupportedReplacementAuth::NotProven);
        let evidence = result.evidence.unwrap();
        assert_eq!(evidence.claim().epistemic_class, EpistemicClass::Inference);
        assert!(evidence.claim().security_interpretation.is_none());
        assert_eq!(
            evidence.claim().attributes.get("hosted_authorization_state"),
            Some(&Value::String("UNKNOWN".to_owned()))
        );
    }

    #[test]
    fn missing_or_ambiguous_verify_jwt_remains_partial_not_clean() {
        let missing = config("[functions.webhook]\n");
        let missing_result = assess(&missing, "Deno.serve(() => new Response('ok'));\n");
        assert_eq!(missing_result.platform_jwt_verification, PlatformJwtVerification::Unknown);
        assert_eq!(missing_result.coverage.state, CoverageState::Partial);

        let ambiguous = config(
            "[functions.webhook]\nverify_jwt = false\nverify_jwt = true\n",
        );
        let ambiguous_result = assess(&ambiguous, "Deno.serve(() => new Response('ok'));\n");
        assert_eq!(ambiguous_result.platform_jwt_verification, PlatformJwtVerification::Unknown);
        assert_eq!(ambiguous_result.coverage.state, CoverageState::Partial);
    }

    #[test]
    fn comments_do_not_prove_replacement_authorization() {
        let posture = config("[functions.webhook]\nverify_jwt = false\n");
        let source = "// const auth = req.headers.get(\"Authorization\");\n// const user = await supabase.auth.getUser(auth);\nDeno.serve(() => new Response('ok'));\n";
        let result = assess(&posture, source);

        assert_eq!(result.supported_replacement_auth, SupportedReplacementAuth::NotProven);
        assert!(result.evidence.is_some());
    }

    #[test]
    fn bounds_provenance_and_execution_invariants_fail_closed() {
        let posture = config("[functions.webhook]\nverify_jwt = true\n");
        assert!(matches!(
            assess_edge_function_auth(
                &posture,
                "webhook",
                &path("src/webhook.ts"),
                "x",
                SOURCE_DIGEST,
                CAPTURED_AT,
                EdgeAuthLimits::default(),
            ),
            Err(EdgeAuthError::InvalidFunctionPath)
        ));
        assert!(matches!(
            assess_edge_function_auth(
                &posture,
                "webhook",
                &path("supabase/functions/webhook/index.ts"),
                "xx",
                SOURCE_DIGEST,
                CAPTURED_AT,
                EdgeAuthLimits { max_source_bytes: 1 },
            ),
            Err(EdgeAuthError::SourceTooLarge { bytes: 2, max: 1 })
        ));
        const { assert!(!EDGE_AUTH_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!EDGE_AUTH_PROVIDER_NETWORK_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }
}
