//! Supabase R2 elevated-key browser/client boundary Evidence.
//!
//! This producer consumes only the redaction-first key-authority observation and
//! bounded source execution-context classification. It never receives raw secret
//! material, never creates Findings, never executes target code, and never contacts
//! Supabase or another network service.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};
use serde_json::Value;

use super::key_authority::KeyAuthorityObservation;
use super::source_context::SourceExecutionContext;

const PRODUCER_ID: &str = "sentrdel.supabase.elevated-key-client-boundary";
const PRODUCER_VERSION: &str = "1";

#[derive(Debug)]
pub enum KeyBoundaryError {
    EmptyCapturedAt,
    EmptySourceContentDigest,
    Evidence(EvidenceValidationError),
}

impl fmt::Display for KeyBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::EmptySourceContentDigest => {
                formatter.write_str("source content digest must not be empty")
            }
            Self::Evidence(error) => {
                write!(formatter, "cannot seal Supabase key-boundary evidence: {error}")
            }
        }
    }
}

impl Error for KeyBoundaryError {}

impl From<EvidenceValidationError> for KeyBoundaryError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_elevated_key_client_boundary(
    observation: &KeyAuthorityObservation,
    context: SourceExecutionContext,
    source_content_digest: &str,
    captured_at: &str,
) -> Result<Option<Evidence>, KeyBoundaryError> {
    if captured_at.trim().is_empty() {
        return Err(KeyBoundaryError::EmptyCapturedAt);
    }

    if !observation.key_class.is_elevated() || context != SourceExecutionContext::BrowserOrClient {
        return Ok(None);
    }

    if source_content_digest.trim().is_empty() {
        return Err(KeyBoundaryError::EmptySourceContentDigest);
    }

    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let path = observation.location.path.as_str();
    let key_class = observation.key_class.as_str();
    let mut attributes = BTreeMap::new();
    attributes.insert("key_class".to_owned(), Value::String(key_class.to_owned()));
    attributes.insert(
        "execution_context".to_owned(),
        Value::String(context.as_str().to_owned()),
    );
    attributes.insert(
        "redacted_display".to_owned(),
        Value::String(observation.redacted_display.clone()),
    );
    attributes.insert(
        "sanitized_non_secret_fingerprint".to_owned(),
        Value::String(observation.sanitized_non_secret_fingerprint.clone()),
    );
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "hosted_authority_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "live_posture".to_owned(),
        Value::String("NOT_EXECUTED".to_owned()),
    );

    Ok(Some(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![source_content_digest.to_owned()],
        observation: format!(
            "Elevated Supabase key class {key_class} is referenced from supported browser/client source context at {path}"
        ),
        security_interpretation: None,
        category: "supabase_elevated_key_client_boundary".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![EvidenceSubject {
            kind: "supabase_key_boundary".to_owned(),
            id: observation.sanitized_non_secret_fingerprint.clone(),
        }],
        locations: vec![EvidenceLocation {
            repo_relative_path: path.to_owned(),
            start_line: Some(observation.location.line),
            start_column: Some(observation.location.start_column),
            end_line: Some(observation.location.line),
            end_column: Some(observation.location.end_column),
            symbol: None,
            content_digest: Some(source_content_digest.to_owned()),
        }],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supabase::key_authority::{
        KeyAuthorityLocation, SupabaseKeyClass, observe_key_literal, observe_key_reference,
    };
    use crate::view::NormalizedRepoPath;

    const CAPTURED_AT: &str = "2026-08-31T21:50:00Z";
    const DIGEST: &str = "sha256:r2-t020-source";

    fn location(path: &str, line: u64) -> KeyAuthorityLocation {
        KeyAuthorityLocation {
            path: NormalizedRepoPath::parse(path, 4096).unwrap(),
            line,
            start_column: 5,
            end_column: 40,
        }
    }

    #[test]
    fn elevated_secret_in_browser_context_emits_redacted_direct_evidence() {
        let canary = "sb_secret_SENTRDEL_CANARY_BROWSER_ELEVATED_NOT_A_CREDENTIAL";
        let key = observe_key_literal(canary, location("src/browser.ts", 4))
            .unwrap()
            .unwrap();
        let evidence = observe_elevated_key_client_boundary(
            &key,
            SourceExecutionContext::BrowserOrClient,
            DIGEST,
            CAPTURED_AT,
        )
        .unwrap()
        .unwrap();

        assert_eq!(key.key_class, SupabaseKeyClass::Secret);
        assert_eq!(evidence.claim().category, "supabase_elevated_key_client_boundary");
        assert_eq!(evidence.claim().epistemic_class, EpistemicClass::Fact);
        assert!(evidence.claim().security_interpretation.is_none());
        assert_eq!(evidence.claim().input_digests, vec![DIGEST.to_owned()]);
        assert_eq!(
            evidence.claim().attributes.get("execution_context"),
            Some(&Value::String("BROWSER_OR_CLIENT".to_owned()))
        );
        assert_eq!(evidence.claim().locations[0].repo_relative_path, "src/browser.ts");
        assert!(!format!("{evidence:?}").contains(canary));
    }

    #[test]
    fn legacy_service_role_reference_in_browser_context_is_supported() {
        let key = observe_key_reference(
            "process.env.SUPABASE_SERVICE_ROLE_KEY",
            location("src/client/supabase.ts", 9),
        )
        .unwrap()
        .unwrap();
        let evidence = observe_elevated_key_client_boundary(
            &key,
            SourceExecutionContext::BrowserOrClient,
            DIGEST,
            CAPTURED_AT,
        )
        .unwrap()
        .unwrap();

        assert_eq!(key.key_class, SupabaseKeyClass::LegacyServiceRole);
        assert_eq!(
            evidence.claim().attributes.get("key_class"),
            Some(&Value::String("LEGACY_SERVICE_ROLE".to_owned()))
        );
        assert!(!format!("{evidence:?}").contains("SERVICE_ROLE_KEY"));
    }

    #[test]
    fn elevated_keys_in_server_edge_test_or_unknown_contexts_are_not_misuse_evidence() {
        for (path, context) in [
            ("src/server.ts", SourceExecutionContext::Server),
            (
                "supabase/functions/webhook/index.ts",
                SourceExecutionContext::EdgeFunction,
            ),
            ("tests/client.ts", SourceExecutionContext::TestOrFixture),
            ("src/lib/supabase.ts", SourceExecutionContext::Unknown),
        ] {
            let key = observe_key_literal("sb_secret_SYNTHETIC_SAFE_CONTEXT", location(path, 3))
                .unwrap()
                .unwrap();
            assert!(
                observe_elevated_key_client_boundary(&key, context, DIGEST, CAPTURED_AT)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn low_authority_keys_do_not_become_client_boundary_evidence() {
        let publishable = observe_key_literal(
            "sb_publishable_SENTRDEL_CANARY_BROWSER_SAFE",
            location("src/browser.ts", 2),
        )
        .unwrap()
        .unwrap();
        let anon = observe_key_reference(
            "process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY",
            location("src/browser.ts", 3),
        )
        .unwrap()
        .unwrap();

        assert!(
            observe_elevated_key_client_boundary(
                &publishable,
                SourceExecutionContext::BrowserOrClient,
                DIGEST,
                CAPTURED_AT,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            observe_elevated_key_client_boundary(
                &anon,
                SourceExecutionContext::BrowserOrClient,
                DIGEST,
                CAPTURED_AT,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn browser_evidence_requires_timestamp_and_source_digest() {
        let key = observe_key_literal(
            "sb_secret_SYNTHETIC_BROWSER",
            location("src/browser.ts", 7),
        )
        .unwrap()
        .unwrap();

        assert!(matches!(
            observe_elevated_key_client_boundary(
                &key,
                SourceExecutionContext::BrowserOrClient,
                DIGEST,
                "",
            ),
            Err(KeyBoundaryError::EmptyCapturedAt)
        ));
        assert!(matches!(
            observe_elevated_key_client_boundary(
                &key,
                SourceExecutionContext::BrowserOrClient,
                "",
                CAPTURED_AT,
            ),
            Err(KeyBoundaryError::EmptySourceContentDigest)
        ));
    }
}
