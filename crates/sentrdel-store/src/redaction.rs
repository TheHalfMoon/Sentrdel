use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

pub const REDACTED_SECRET_TOKEN: &str = "[REDACTED_SECRET]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistentSink {
    Sqlite,
    Export,
    Log,
    Snapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretPatternKind {
    Plaintext,
    JsonEscapedPlaintext,
    Sha256Raw,
    Sha256Hex,
    Sha256Tagged,
    RegisteredDerivative,
}

#[derive(Debug)]
pub enum RedactionError {
    EmptySecret,
    EmptyDerivative,
    JsonEncoding(serde_json::Error),
    SensitiveDataRejected {
        sink: PersistentSink,
        pattern_kind: SecretPatternKind,
    },
}

impl fmt::Display for RedactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySecret => write!(formatter, "discovered secret value must not be empty"),
            Self::EmptyDerivative => {
                write!(
                    formatter,
                    "secret-derived forbidden representation must not be empty"
                )
            }
            Self::JsonEncoding(error) => {
                write!(formatter, "secret redaction JSON encoding failed: {error}")
            }
            Self::SensitiveDataRejected { sink, pattern_kind } => write!(
                formatter,
                "refusing {sink:?} sink bytes containing forbidden secret material ({pattern_kind:?})"
            ),
        }
    }
}

impl Error for RedactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::JsonEncoding(error) => Some(error),
            Self::EmptySecret | Self::EmptyDerivative | Self::SensitiveDataRejected { .. } => None,
        }
    }
}

#[derive(Clone)]
struct ForbiddenPattern {
    bytes: Vec<u8>,
    kind: SecretPatternKind,
}

/// In-memory guard for secret material that has crossed the discovery boundary.
///
/// The boundary never serializes registered values. Callers redact transient
/// text before creating canonical objects, and durable sinks additionally call
/// `ensure_safe` so already-sealed unsafe objects fail closed rather than being
/// rewritten after their identity was computed.
#[derive(Default)]
pub struct PersistenceRedactionBoundary {
    patterns: Vec<ForbiddenPattern>,
}

impl fmt::Debug for PersistenceRedactionBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistenceRedactionBoundary")
            .field("registered_pattern_count", &self.patterns.len())
            .finish()
    }
}

impl PersistenceRedactionBoundary {
    /// Register one discovered plaintext secret in memory.
    ///
    /// In addition to plaintext and its JSON-escaped representation, Sentrdel
    /// blocks the common accidental value-only SHA-256 representations because
    /// they remain stable dictionary-attack targets even when plaintext is gone.
    pub fn register_discovered_secret(&mut self, secret: &str) -> Result<bool, RedactionError> {
        if secret.is_empty() {
            return Err(RedactionError::EmptySecret);
        }

        let before = self.patterns.len();
        self.add_pattern(secret.as_bytes().to_vec(), SecretPatternKind::Plaintext);

        let encoded = serde_json::to_string(secret).map_err(RedactionError::JsonEncoding)?;
        let escaped = &encoded.as_bytes()[1..encoded.len() - 1];
        if escaped != secret.as_bytes() {
            self.add_pattern(escaped.to_vec(), SecretPatternKind::JsonEscapedPlaintext);
        }

        let digest = Sha256::digest(secret.as_bytes());
        self.add_pattern(digest.to_vec(), SecretPatternKind::Sha256Raw);
        let lower_hex = encode_hex(&digest);
        let upper_hex = lower_hex.to_ascii_uppercase();
        self.add_pattern(lower_hex.as_bytes().to_vec(), SecretPatternKind::Sha256Hex);
        self.add_pattern(upper_hex.as_bytes().to_vec(), SecretPatternKind::Sha256Hex);
        for tagged in [
            format!("sha256:{lower_hex}"),
            format!("sha256:{upper_hex}"),
            format!("SHA256:{lower_hex}"),
            format!("SHA256:{upper_hex}"),
        ] {
            self.add_pattern(tagged.into_bytes(), SecretPatternKind::Sha256Tagged);
        }

        self.sort_longest_first();
        Ok(self.patterns.len() != before)
    }

    /// Register another known stable representation derived solely from secret
    /// material. This exists for bounded adapters that encounter a representation
    /// they did not create; it must never be used as a reason to persist such a
    /// representation.
    pub fn register_forbidden_derivative(
        &mut self,
        derivative: &[u8],
    ) -> Result<bool, RedactionError> {
        if derivative.is_empty() {
            return Err(RedactionError::EmptyDerivative);
        }
        let before = self.patterns.len();
        self.add_pattern(derivative.to_vec(), SecretPatternKind::RegisteredDerivative);
        self.sort_longest_first();
        Ok(self.patterns.len() != before)
    }

    /// Reject bytes that still contain any registered secret representation.
    pub fn ensure_safe(&self, sink: PersistentSink, bytes: &[u8]) -> Result<(), RedactionError> {
        for pattern in &self.patterns {
            if contains_subslice(bytes, &pattern.bytes) {
                return Err(RedactionError::SensitiveDataRejected {
                    sink,
                    pattern_kind: pattern.kind,
                });
            }
        }
        Ok(())
    }

    /// Redact non-canonical sink bytes before export/log/snapshot persistence.
    ///
    /// Canonical schema objects must be redacted before sealing/hashing instead;
    /// durable Store APIs reject unsafe canonical bytes rather than silently
    /// changing their identity here.
    pub fn redact_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let mut redacted = bytes.to_vec();
        for pattern in &self.patterns {
            redacted = replace_all(&redacted, &pattern.bytes, REDACTED_SECRET_TOKEN.as_bytes());
        }
        redacted
    }

    pub fn redact_text(&self, text: &str) -> String {
        String::from_utf8(self.redact_bytes(text.as_bytes()))
            .expect("redacting UTF-8 text with an ASCII token preserves UTF-8")
    }

    fn add_pattern(&mut self, bytes: Vec<u8>, kind: SecretPatternKind) {
        if !self.patterns.iter().any(|pattern| pattern.bytes == bytes) {
            self.patterns.push(ForbiddenPattern { bytes, kind });
        }
    }

    fn sort_longest_first(&mut self) {
        self.patterns
            .sort_by(|left, right| right.bytes.len().cmp(&left.bytes.len()));
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn replace_all(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return input.to_vec();
    }

    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while offset < input.len() {
        if input[offset..].starts_with(needle) {
            output.extend_from_slice(replacement);
            offset += needle.len();
        } else {
            output.push(input[offset]);
            offset += 1;
        }
    }
    output
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::{
        PersistenceRedactionBoundary, PersistentSink, REDACTED_SECRET_TOKEN, RedactionError,
        SecretPatternKind,
    };

    const SECRET: &str = "t019-canary-\"line\nvalue-9F7x";

    fn sha256_hex(value: &str) -> String {
        let digest = Sha256::digest(value.as_bytes());
        super::encode_hex(&digest)
    }

    #[test]
    fn registration_detects_plaintext_json_escaped_and_value_only_sha256() {
        let mut boundary = PersistenceRedactionBoundary::default();
        assert!(
            boundary
                .register_discovered_secret(SECRET)
                .expect("register")
        );
        assert!(!boundary.register_discovered_secret(SECRET).expect("dedupe"));

        assert!(matches!(
            boundary.ensure_safe(PersistentSink::Sqlite, SECRET.as_bytes()),
            Err(RedactionError::SensitiveDataRejected {
                pattern_kind: SecretPatternKind::Plaintext,
                ..
            })
        ));

        let json = serde_json::to_string(SECRET).expect("fixture JSON");
        assert!(
            boundary
                .ensure_safe(PersistentSink::Snapshot, json.as_bytes())
                .is_err()
        );

        let digest = sha256_hex(SECRET);
        for representation in [digest.clone(), format!("sha256:{digest}")] {
            assert!(
                boundary
                    .ensure_safe(PersistentSink::Export, representation.as_bytes())
                    .is_err()
            );
        }
    }

    #[test]
    fn redaction_output_and_debug_do_not_disclose_registered_material() {
        let mut boundary = PersistenceRedactionBoundary::default();
        boundary
            .register_discovered_secret(SECRET)
            .expect("register");
        boundary
            .register_forbidden_derivative(b"derived-secret-token")
            .expect("register derivative");

        let digest = sha256_hex(SECRET);
        let input = format!("secret={SECRET} digest={digest} other=derived-secret-token");
        let redacted = boundary.redact_text(&input);
        assert!(!redacted.contains(SECRET));
        assert!(!redacted.contains(&digest));
        assert!(!redacted.contains("derived-secret-token"));
        assert!(redacted.contains(REDACTED_SECRET_TOKEN));

        let debug = format!("{boundary:?}");
        assert!(!debug.contains(SECRET));
        assert!(!debug.contains(&digest));
        assert!(!debug.contains("derived-secret-token"));
    }
}
