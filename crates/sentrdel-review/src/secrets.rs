//! Changed-source secret observations with redaction-before-Evidence construction.
//!
//! Secret plaintext is inspected only in the caller-provided changed bytes. It is
//! never copied into Evidence, fingerprints, locations, diagnostics, or persisted
//! digests. Fingerprints are derived only from rule/type/location metadata.

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::canonical::content_id;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

use crate::view::NormalizedRepoPath;

pub const MAX_SECRET_SCAN_BYTES: usize = 4 * 1024 * 1024;
const PRODUCER_ID: &str = "sentrdel.changed-secret";
const PRODUCER_VERSION: &str = "1";

#[derive(Clone, Copy, Debug)]
pub struct SecretRule {
    pub id: &'static str,
    pub secret_type: &'static str,
    prefix: &'static str,
    total_len: usize,
    alphabet: fn(u8) -> bool,
}

pub const GITHUB_CLASSIC_PAT: SecretRule = SecretRule {
    id: "secret.github-classic-pat",
    secret_type: "github_classic_pat",
    prefix: "ghp_",
    total_len: 40,
    alphabet: is_ascii_alphanumeric,
};

pub const AWS_ACCESS_KEY_ID: SecretRule = SecretRule {
    id: "secret.aws-access-key-id",
    secret_type: "aws_access_key_id",
    prefix: "AKIA",
    total_len: 20,
    alphabet: is_ascii_uppercase_or_digit,
};

pub const CHANGED_SECRET_RULES: &[SecretRule] = &[GITHUB_CLASSIC_PAT, AWS_ACCESS_KEY_ID];

#[derive(Debug)]
pub enum SecretScanError {
    DocumentTooLarge { bytes: usize, max: usize },
    NonUtf8Source,
    EmptyCapturedAt,
    Canonical(String),
    Evidence(EvidenceValidationError),
}

impl fmt::Display for SecretScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocumentTooLarge { bytes, max } => {
                write!(
                    formatter,
                    "changed source size {bytes} exceeds secret scan cap {max}"
                )
            }
            Self::NonUtf8Source => formatter.write_str("changed source must be valid UTF-8"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::Canonical(message) => {
                write!(formatter, "cannot create sanitized fingerprint: {message}")
            }
            Self::Evidence(error) => write!(formatter, "cannot seal secret evidence: {error}"),
        }
    }
}

impl std::error::Error for SecretScanError {}

impl From<EvidenceValidationError> for SecretScanError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn scan_changed_secrets(
    path: &NormalizedRepoPath,
    bytes: &[u8],
    captured_at: &str,
) -> Result<Vec<Evidence>, SecretScanError> {
    if bytes.len() > MAX_SECRET_SCAN_BYTES {
        return Err(SecretScanError::DocumentTooLarge {
            bytes: bytes.len(),
            max: MAX_SECRET_SCAN_BYTES,
        });
    }
    let source = std::str::from_utf8(bytes).map_err(|_| SecretScanError::NonUtf8Source)?;
    if captured_at.trim().is_empty() {
        return Err(SecretScanError::EmptyCapturedAt);
    }

    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let mut evidence = Vec::new();

    for (line_index, line) in source.lines().enumerate() {
        for rule in CHANGED_SECRET_RULES {
            for start in matching_offsets(line.as_bytes(), *rule) {
                let line_number = u64::try_from(line_index + 1).unwrap_or(u64::MAX);
                let start_column = u64::try_from(start + 1).unwrap_or(u64::MAX);
                let end_column = u64::try_from(start + rule.total_len + 1).unwrap_or(u64::MAX);
                let fingerprint = content_id(
                    "secret-observation-fingerprint",
                    &(
                        rule.id,
                        rule.secret_type,
                        path.as_str(),
                        line_number,
                        start_column,
                        end_column,
                    ),
                )
                .map_err(|error| SecretScanError::Canonical(error.to_string()))?;

                let mut attributes = BTreeMap::new();
                attributes.insert("rule_id".to_owned(), Value::String(rule.id.to_owned()));
                attributes.insert(
                    "secret_type".to_owned(),
                    Value::String(rule.secret_type.to_owned()),
                );
                attributes.insert(
                    "redacted_display".to_owned(),
                    Value::String(format!("[REDACTED:{}]", rule.secret_type)),
                );
                attributes.insert(
                    "sanitized_fingerprint".to_owned(),
                    Value::String(fingerprint),
                );

                let claim = EvidenceClaim {
                    schema_version: SCHEMA_V1.to_owned(),
                    input_digests: Vec::new(),
                    observation: format!(
                        "Changed source matches Sentrdel-owned secret format rule {}",
                        rule.id
                    ),
                    security_interpretation: None,
                    category: "secret".to_owned(),
                    epistemic_class: EpistemicClass::Fact,
                    confidence_band: None,
                    subjects: vec![EvidenceSubject {
                        kind: "repository_path".to_owned(),
                        id: path.as_str().to_owned(),
                    }],
                    locations: vec![EvidenceLocation {
                        repo_relative_path: path.as_str().to_owned(),
                        start_line: Some(line_number),
                        start_column: Some(start_column),
                        end_line: Some(line_number),
                        end_column: Some(end_column),
                        symbol: None,
                        content_digest: None,
                    }],
                    attributes,
                    reproduction: None,
                    captured_at: captured_at.to_owned(),
                };
                evidence.push(authority.seal(claim)?);
            }
        }
    }

    evidence.sort_by(|left, right| {
        let left = left.claim();
        let right = right.claim();
        let left_location = left.locations.first();
        let right_location = right.locations.first();
        left_location
            .and_then(|location| location.start_line)
            .cmp(&right_location.and_then(|location| location.start_line))
            .then_with(|| {
                left_location
                    .and_then(|location| location.start_column)
                    .cmp(&right_location.and_then(|location| location.start_column))
            })
            .then_with(|| {
                left.attributes
                    .get("rule_id")
                    .and_then(Value::as_str)
                    .cmp(&right.attributes.get("rule_id").and_then(Value::as_str))
            })
    });
    Ok(evidence)
}

fn matching_offsets(line: &[u8], rule: SecretRule) -> Vec<usize> {
    let prefix = rule.prefix.as_bytes();
    if line.len() < rule.total_len || prefix.len() > rule.total_len {
        return Vec::new();
    }

    let mut offsets = Vec::new();
    for start in 0..=line.len() - rule.total_len {
        let end = start + rule.total_len;
        let candidate = &line[start..end];
        if !candidate.starts_with(prefix) {
            continue;
        }
        if !candidate[prefix.len()..].iter().copied().all(rule.alphabet) {
            continue;
        }
        if start > 0 && is_token_boundary_char(line[start - 1]) {
            continue;
        }
        if end < line.len() && is_token_boundary_char(line[end]) {
            continue;
        }
        offsets.push(start);
    }
    offsets
}

const fn is_ascii_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

const fn is_ascii_uppercase_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

const fn is_token_boundary_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
