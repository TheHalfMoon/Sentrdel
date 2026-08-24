#![forbid(unsafe_code)]
//! Canonical, versioned security data contracts for Sentrdel.

/// Bootstrap schema version. The concrete public schemas land in Phase 2.
pub const SCHEMA_BOOTSTRAP_VERSION: &str = "0";

#[cfg(test)]
mod tests {
    use super::SCHEMA_BOOTSTRAP_VERSION;

    #[test]
    fn bootstrap_version_is_explicit() {
        assert_eq!(SCHEMA_BOOTSTRAP_VERSION, "0");
    }
}
