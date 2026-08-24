//! Deterministic canonical JSON and content identifiers.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

/// Errors raised before security-relevant content is accepted as canonical.
#[derive(Debug)]
pub enum CanonicalError {
    Serialize(serde_json::Error),
    FloatingPointNumber,
    EmptyNamespace,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(error) => write!(f, "canonical JSON serialization failed: {error}"),
            Self::FloatingPointNumber => {
                write!(
                    f,
                    "floating-point numbers are not permitted in canonical v1 objects"
                )
            }
            Self::EmptyNamespace => write!(f, "content-id namespace must not be empty"),
        }
    }
}

impl Error for CanonicalError {}

impl From<serde_json::Error> for CanonicalError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialize(value)
    }
}

/// Serialize into the R1 canonical JSON profile.
///
/// The profile is intentionally narrower than general JSON: object keys are
/// lexicographically ordered by `serde_json`'s default map representation,
/// insignificant whitespace is absent, array order is preserved, and floating
/// point numbers are rejected. This keeps hashes deterministic without
/// pretending to implement every RFC 8785 edge case in R1.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let value = serde_json::to_value(value)?;
    reject_floats(&value)?;
    Ok(serde_json::to_vec(&value)?)
}

/// Compute a namespaced SHA-256 content identifier.
///
/// Domain separation prevents equal canonical bytes used for different object
/// classes from silently sharing an identifier namespace.
pub fn content_id<T: Serialize>(namespace: &str, value: &T) -> Result<String, CanonicalError> {
    if namespace.is_empty() {
        return Err(CanonicalError::EmptyNamespace);
    }

    let canonical = canonical_json_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(b"sentrdel:v1\0");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(&canonical);
    let digest = hasher.finalize();

    Ok(format!("sha256:{}", encode_hex(&digest)))
}

fn reject_floats(value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Number(number) if !(number.is_i64() || number.is_u64()) => {
            Err(CanonicalError::FloatingPointNumber)
        }
        Value::Array(values) => values.iter().try_for_each(reject_floats),
        Value::Object(values) => values.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
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
    use super::{CanonicalError, canonical_json_bytes, content_id};
    use serde::Serialize;
    use std::collections::BTreeMap;

    #[derive(Serialize)]
    struct Example {
        z: u64,
        a: BTreeMap<String, String>,
    }

    #[test]
    fn canonical_output_and_id_are_stable() {
        let mut map = BTreeMap::new();
        map.insert("b".to_owned(), "two".to_owned());
        map.insert("a".to_owned(), "one".to_owned());
        let example = Example { z: 7, a: map };

        let first = canonical_json_bytes(&example).expect("canonicalize");
        let second = canonical_json_bytes(&example).expect("canonicalize");
        assert_eq!(first, second);
        assert_eq!(
            String::from_utf8(first).expect("utf8"),
            r#"{"a":{"a":"one","b":"two"},"z":7}"#
        );
        assert_eq!(
            content_id("example", &example).expect("content id"),
            content_id("example", &example).expect("content id")
        );
    }

    #[test]
    fn floats_are_rejected() {
        let error = canonical_json_bytes(&serde_json::json!({"score": 0.5}))
            .expect_err("float must be rejected");
        assert!(matches!(error, CanonicalError::FloatingPointNumber));
    }

    #[test]
    fn namespaces_are_domain_separated() {
        let value = serde_json::json!({"value": 1});
        assert_ne!(
            content_id("evidence", &value).expect("id"),
            content_id("event", &value).expect("id")
        );
    }
}
