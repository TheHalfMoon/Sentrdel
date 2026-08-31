//! Bounded Supabase key-authority classification with redaction-first observations.
//!
//! This module classifies only the authority class of a caller-supplied key token
//! or semantic key reference. It does not discover source execution context, emit
//! Findings, contact Supabase, validate credentials, decode legacy JWT payloads,
//! or persist raw key material. Elevated literal material is discarded before an
//! observation is returned and shares the R1 sanitized secret-fingerprint boundary.

use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::content_id;

use crate::secrets::{redacted_secret_display, sanitized_secret_fingerprint};
use crate::view::NormalizedRepoPath;

pub const DEFAULT_MAX_SUPABASE_KEY_TOKEN_BYTES: usize = 1_024;
pub const DEFAULT_MAX_SUPABASE_KEY_REFERENCE_BYTES: usize = 256;

const MODERN_PUBLISHABLE_PREFIX: &str = "sb_publishable_";
const MODERN_SECRET_PREFIX: &str = "sb_secret_";
const SUPABASE_KEY_PREFIX: &str = "sb_";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SupabaseKeyClass {
    Publishable,
    LegacyAnon,
    Secret,
    LegacyServiceRole,
    UnknownSupabaseKey,
}

impl SupabaseKeyClass {
    #[must_use]
    pub const fn is_elevated(self) -> bool {
        matches!(self, Self::Secret | Self::LegacyServiceRole)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publishable => "PUBLISHABLE",
            Self::LegacyAnon => "LEGACY_ANON",
            Self::Secret => "SECRET",
            Self::LegacyServiceRole => "LEGACY_SERVICE_ROLE",
            Self::UnknownSupabaseKey => "UNKNOWN_SUPABASE_KEY",
        }
    }

    const fn secret_type(self) -> Option<&'static str> {
        match self {
            Self::Secret => Some("supabase_secret_key"),
            Self::LegacyServiceRole => Some("supabase_legacy_service_role_key"),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KeyAuthoritySignal {
    Literal,
    SemanticReference,
}

impl KeyAuthoritySignal {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "LITERAL",
            Self::SemanticReference => "SEMANTIC_REFERENCE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyAuthorityLocation {
    pub path: NormalizedRepoPath,
    pub line: u64,
    pub start_column: u64,
    pub end_column: u64,
}

impl KeyAuthorityLocation {
    fn validate(&self) -> Result<(), KeyAuthorityError> {
        if self.line == 0
            || self.start_column == 0
            || self.end_column <= self.start_column
        {
            return Err(KeyAuthorityError::InvalidLocation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyAuthorityObservation {
    pub key_class: SupabaseKeyClass,
    pub signal: KeyAuthoritySignal,
    pub location: KeyAuthorityLocation,
    pub redacted_display: String,
    pub sanitized_non_secret_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAuthorityError {
    LiteralTooLarge { bytes: usize, max: usize },
    ReferenceTooLarge { bytes: usize, max: usize },
    InvalidLocation,
    Canonical(String),
}

impl fmt::Display for KeyAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiteralTooLarge { bytes, max } => {
                write!(formatter, "Supabase key literal is {bytes} bytes and exceeds cap {max}")
            }
            Self::ReferenceTooLarge { bytes, max } => write!(
                formatter,
                "Supabase key semantic reference is {bytes} bytes and exceeds cap {max}"
            ),
            Self::InvalidLocation => formatter.write_str(
                "Supabase key observation location must use non-zero line/column values and end_column > start_column",
            ),
            Self::Canonical(message) => write!(
                formatter,
                "cannot create sanitized Supabase key fingerprint: {message}"
            ),
        }
    }
}

impl Error for KeyAuthorityError {}

pub fn classify_key_literal(
    raw: &str,
) -> Result<Option<SupabaseKeyClass>, KeyAuthorityError> {
    if raw.len() > DEFAULT_MAX_SUPABASE_KEY_TOKEN_BYTES {
        return Err(KeyAuthorityError::LiteralTooLarge {
            bytes: raw.len(),
            max: DEFAULT_MAX_SUPABASE_KEY_TOKEN_BYTES,
        });
    }

    if let Some(suffix) = raw.strip_prefix(MODERN_PUBLISHABLE_PREFIX) {
        return Ok(Some(if valid_modern_suffix(suffix) {
            SupabaseKeyClass::Publishable
        } else {
            SupabaseKeyClass::UnknownSupabaseKey
        }));
    }
    if let Some(suffix) = raw.strip_prefix(MODERN_SECRET_PREFIX) {
        return Ok(Some(if valid_modern_suffix(suffix) {
            SupabaseKeyClass::Secret
        } else {
            SupabaseKeyClass::UnknownSupabaseKey
        }));
    }
    if raw.starts_with(SUPABASE_KEY_PREFIX) {
        return Ok(Some(SupabaseKeyClass::UnknownSupabaseKey));
    }
    Ok(None)
}

pub fn classify_key_reference(
    reference: &str,
) -> Result<Option<SupabaseKeyClass>, KeyAuthorityError> {
    if reference.len() > DEFAULT_MAX_SUPABASE_KEY_REFERENCE_BYTES {
        return Err(KeyAuthorityError::ReferenceTooLarge {
            bytes: reference.len(),
            max: DEFAULT_MAX_SUPABASE_KEY_REFERENCE_BYTES,
        });
    }

    let normalized = normalize_reference(reference);
    if normalized.is_empty() {
        return Ok(None);
    }
    if normalized.ends_with("SUPABASE_SERVICE_ROLE_KEY") {
        return Ok(Some(SupabaseKeyClass::LegacyServiceRole));
    }
    if normalized.ends_with("SUPABASE_ANON_KEY") {
        return Ok(Some(SupabaseKeyClass::LegacyAnon));
    }
    if normalized.ends_with("SUPABASE_SECRET_KEY") {
        return Ok(Some(SupabaseKeyClass::Secret));
    }
    if normalized.ends_with("SUPABASE_PUBLISHABLE_KEY") {
        return Ok(Some(SupabaseKeyClass::Publishable));
    }
    if normalized.contains("SUPABASE") && normalized.ends_with("KEY") {
        return Ok(Some(SupabaseKeyClass::UnknownSupabaseKey));
    }
    Ok(None)
}

pub fn observe_key_literal(
    raw: &str,
    location: KeyAuthorityLocation,
) -> Result<Option<KeyAuthorityObservation>, KeyAuthorityError> {
    let Some(key_class) = classify_key_literal(raw)? else {
        return Ok(None);
    };
    build_observation(key_class, KeyAuthoritySignal::Literal, location)
        .map(Some)
}

pub fn observe_key_reference(
    reference: &str,
    location: KeyAuthorityLocation,
) -> Result<Option<KeyAuthorityObservation>, KeyAuthorityError> {
    let Some(key_class) = classify_key_reference(reference)? else {
        return Ok(None);
    };
    build_observation(key_class, KeyAuthoritySignal::SemanticReference, location)
        .map(Some)
}

fn build_observation(
    key_class: SupabaseKeyClass,
    signal: KeyAuthoritySignal,
    location: KeyAuthorityLocation,
) -> Result<KeyAuthorityObservation, KeyAuthorityError> {
    location.validate()?;

    let (redacted_display, fingerprint) = if let Some(secret_type) = key_class.secret_type() {
        let rule_id = match key_class {
            SupabaseKeyClass::Secret => "secret.supabase-secret-key",
            SupabaseKeyClass::LegacyServiceRole => "secret.supabase-legacy-service-role-key",
            _ => unreachable!("only elevated classes have a secret type"),
        };
        let fingerprint = sanitized_secret_fingerprint(
            rule_id,
            secret_type,
            &location.path,
            location.line,
            location.start_column,
            location.end_column,
        )
        .map_err(KeyAuthorityError::Canonical)?;
        (redacted_secret_display(secret_type), fingerprint)
    } else {
        let fingerprint = content_id(
            "supabase-key-authority-fingerprint",
            &(
                key_class.as_str(),
                signal.as_str(),
                location.path.as_str(),
                location.line,
                location.start_column,
                location.end_column,
            ),
        )
        .map_err(|error| KeyAuthorityError::Canonical(error.to_string()))?;
        (
            format!("[SUPABASE_KEY:{}]", key_class.as_str()),
            fingerprint,
        )
    };

    Ok(KeyAuthorityObservation {
        key_class,
        signal,
        location,
        redacted_display,
        sanitized_non_secret_fingerprint: fingerprint,
    })
}

fn valid_modern_suffix(suffix: &str) -> bool {
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn normalize_reference(reference: &str) -> String {
    let mut normalized = String::with_capacity(reference.len());
    let mut last_was_separator = false;
    for byte in reference.bytes() {
        if byte.is_ascii_alphanumeric() {
            normalized.push(char::from(byte.to_ascii_uppercase()));
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location(line: u64, start_column: u64, end_column: u64) -> KeyAuthorityLocation {
        KeyAuthorityLocation {
            path: NormalizedRepoPath::parse("src/browser.ts", 4096).unwrap(),
            line,
            start_column,
            end_column,
        }
    }

    #[test]
    fn modern_key_prefixes_map_to_authority_classes_without_decoding() {
        assert_eq!(
            classify_key_literal("sb_publishable_SENTRDEL_CANARY_BROWSER_SAFE").unwrap(),
            Some(SupabaseKeyClass::Publishable)
        );
        assert_eq!(
            classify_key_literal("sb_secret_SENTRDEL_CANARY_SERVER_ONLY_NOT_A_CREDENTIAL").unwrap(),
            Some(SupabaseKeyClass::Secret)
        );
        assert_eq!(
            classify_key_literal("sb_future_SENTRDEL_CANARY").unwrap(),
            Some(SupabaseKeyClass::UnknownSupabaseKey)
        );
        assert_eq!(classify_key_literal("ordinary-value").unwrap(), None);
    }

    #[test]
    fn malformed_modern_prefixes_do_not_gain_known_authority() {
        assert_eq!(
            classify_key_literal("sb_publishable_").unwrap(),
            Some(SupabaseKeyClass::UnknownSupabaseKey)
        );
        assert_eq!(
            classify_key_literal("sb_secret_bad value").unwrap(),
            Some(SupabaseKeyClass::UnknownSupabaseKey)
        );
    }

    #[test]
    fn semantic_reference_names_cover_modern_and_legacy_classes() {
        assert_eq!(
            classify_key_reference("process.env.SUPABASE_SERVICE_ROLE_KEY").unwrap(),
            Some(SupabaseKeyClass::LegacyServiceRole)
        );
        assert_eq!(
            classify_key_reference("NEXT_PUBLIC_SUPABASE_ANON_KEY").unwrap(),
            Some(SupabaseKeyClass::LegacyAnon)
        );
        assert_eq!(
            classify_key_reference("SUPABASE_SECRET_KEY").unwrap(),
            Some(SupabaseKeyClass::Secret)
        );
        assert_eq!(
            classify_key_reference("VITE_SUPABASE_PUBLISHABLE_KEY").unwrap(),
            Some(SupabaseKeyClass::Publishable)
        );
        assert_eq!(
            classify_key_reference("SUPABASE_FUTURE_KEY").unwrap(),
            Some(SupabaseKeyClass::UnknownSupabaseKey)
        );
        assert_eq!(classify_key_reference("DATABASE_URL").unwrap(), None);
    }

    #[test]
    fn elevated_literal_observation_discards_secret_plaintext_before_return() {
        let canary = "sb_secret_SENTRDEL_CANARY_BROWSER_ELEVATED_NOT_A_CREDENTIAL";
        let observation = observe_key_literal(canary, location(4, 34, 94))
            .unwrap()
            .unwrap();
        assert_eq!(observation.key_class, SupabaseKeyClass::Secret);
        assert!(observation.key_class.is_elevated());
        assert_eq!(
            observation.redacted_display,
            "[REDACTED:supabase_secret_key]"
        );
        let debug = format!("{observation:?}");
        assert!(!debug.contains(canary));
        assert!(!observation.sanitized_non_secret_fingerprint.contains("SENTRDEL_CANARY"));
    }

    #[test]
    fn elevated_fingerprint_is_value_independent_and_location_bound() {
        let first = observe_key_literal("sb_secret_SYNTHETIC_ONE", location(8, 5, 28))
            .unwrap()
            .unwrap();
        let second = observe_key_literal("sb_secret_SYNTHETIC_TWO", location(8, 5, 28))
            .unwrap()
            .unwrap();
        let moved = observe_key_literal("sb_secret_SYNTHETIC_ONE", location(9, 5, 28))
            .unwrap()
            .unwrap();
        assert_eq!(
            first.sanitized_non_secret_fingerprint,
            second.sanitized_non_secret_fingerprint
        );
        assert_ne!(
            first.sanitized_non_secret_fingerprint,
            moved.sanitized_non_secret_fingerprint
        );
    }

    #[test]
    fn legacy_service_role_reference_uses_redacted_elevated_boundary() {
        let observation = observe_key_reference(
            "process.env.SUPABASE_SERVICE_ROLE_KEY",
            location(12, 17, 42),
        )
        .unwrap()
        .unwrap();
        assert_eq!(observation.key_class, SupabaseKeyClass::LegacyServiceRole);
        assert_eq!(
            observation.redacted_display,
            "[REDACTED:supabase_legacy_service_role_key]"
        );
        assert!(observation.key_class.is_elevated());
        assert!(!observation
            .sanitized_non_secret_fingerprint
            .contains("SERVICE_ROLE"));
    }

    #[test]
    fn low_authority_observations_keep_only_class_metadata() {
        let observation = observe_key_literal(
            "sb_publishable_SENTRDEL_CANARY_BROWSER_SAFE",
            location(2, 36, 78),
        )
        .unwrap()
        .unwrap();
        assert_eq!(observation.key_class, SupabaseKeyClass::Publishable);
        assert!(!observation.key_class.is_elevated());
        assert_eq!(observation.redacted_display, "[SUPABASE_KEY:PUBLISHABLE]");
        assert!(!format!("{observation:?}").contains("SENTRDEL_CANARY"));
    }

    #[test]
    fn caller_controlled_size_and_location_inputs_fail_boundedly() {
        let oversized_literal = format!("sb_secret_{}", "A".repeat(DEFAULT_MAX_SUPABASE_KEY_TOKEN_BYTES));
        assert!(matches!(
            classify_key_literal(&oversized_literal),
            Err(KeyAuthorityError::LiteralTooLarge { .. })
        ));
        let oversized_reference = "A".repeat(DEFAULT_MAX_SUPABASE_KEY_REFERENCE_BYTES + 1);
        assert!(matches!(
            classify_key_reference(&oversized_reference),
            Err(KeyAuthorityError::ReferenceTooLarge { .. })
        ));
        assert!(matches!(
            observe_key_literal("sb_secret_SYNTHETIC", location(0, 1, 2)),
            Err(KeyAuthorityError::InvalidLocation)
        ));
    }
}
