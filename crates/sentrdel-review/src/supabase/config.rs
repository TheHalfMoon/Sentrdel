//! Bounded allowlisted parser for repository-visible `supabase/config.toml`.
//!
//! The parser retains only R2 security-relevant configuration facts that are
//! explicitly supported. It is not a general TOML implementation. Unsupported
//! or malformed security-relevant configuration degrades parse coverage instead
//! of being guessed, while hard resource or canonical-input violations fail
//! closed. No provider access, secret retention, or Finding authority exists
//! here.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::view::NormalizedRepoPath;

pub const SUPABASE_CONFIG_PATH: &str = "supabase/config.toml";
pub const DEFAULT_MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_CONFIG_LINES: usize = 4_096;
pub const DEFAULT_MAX_CONFIG_LINE_BYTES: usize = 4_096;
pub const DEFAULT_MAX_CONFIG_SECTIONS: usize = 512;
pub const DEFAULT_MAX_CONFIG_SCHEMAS: usize = 128;
pub const DEFAULT_MAX_CONFIG_FUNCTIONS: usize = 512;
pub const DEFAULT_MAX_CONFIG_IDENTIFIER_BYTES: usize = 128;
pub const DEFAULT_MAX_CONFIG_DIAGNOSTICS: usize = 128;
pub const MAX_SUPPORTED_TABLE_DEPTH: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupabaseConfigLimits {
    pub max_bytes: usize,
    pub max_lines: usize,
    pub max_line_bytes: usize,
    pub max_sections: usize,
    pub max_schemas: usize,
    pub max_functions: usize,
    pub max_identifier_bytes: usize,
    pub max_diagnostics: usize,
}

impl Default for SupabaseConfigLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_CONFIG_BYTES,
            max_lines: DEFAULT_MAX_CONFIG_LINES,
            max_line_bytes: DEFAULT_MAX_CONFIG_LINE_BYTES,
            max_sections: DEFAULT_MAX_CONFIG_SECTIONS,
            max_schemas: DEFAULT_MAX_CONFIG_SCHEMAS,
            max_functions: DEFAULT_MAX_CONFIG_FUNCTIONS,
            max_identifier_bytes: DEFAULT_MAX_CONFIG_IDENTIFIER_BYTES,
            max_diagnostics: DEFAULT_MAX_CONFIG_DIAGNOSTICS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigParseCoverage {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigDiagnosticKind {
    MalformedSyntax,
    DuplicateSupportedKey,
    UnsupportedSecurityRelevantKey,
    UnsupportedSecurityRelevantTable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigDiagnostic {
    pub line: usize,
    pub kind: ConfigDiagnosticKind,
    pub table: Option<String>,
    pub key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigProvenance {
    pub path: NormalizedRepoPath,
    pub content_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigValue<T> {
    pub value: T,
    pub line: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeFunctionConfigPosture {
    pub platform_jwt_verification: Option<ConfigValue<bool>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupabaseConfigPosture {
    pub api_enabled: Option<ConfigValue<bool>>,
    pub api_exposed_schemas: Option<ConfigValue<BTreeSet<String>>>,
    pub edge_function_auth: BTreeMap<String, EdgeFunctionConfigPosture>,
    pub parse_coverage: ConfigParseCoverage,
    pub diagnostics: Vec<ConfigDiagnostic>,
    pub provenance: ConfigProvenance,
}

impl SupabaseConfigPosture {
    fn new(path: NormalizedRepoPath, content_digest: String) -> Self {
        Self {
            api_enabled: None,
            api_exposed_schemas: None,
            edge_function_auth: BTreeMap::new(),
            parse_coverage: ConfigParseCoverage::Complete,
            diagnostics: Vec::new(),
            provenance: ConfigProvenance {
                path,
                content_digest,
            },
        }
    }

    fn degrade(
        &mut self,
        limits: SupabaseConfigLimits,
        diagnostic: ConfigDiagnostic,
    ) -> Result<(), SupabaseConfigError> {
        if self.diagnostics.len() >= limits.max_diagnostics {
            return Err(SupabaseConfigError::TooManyDiagnostics {
                max: limits.max_diagnostics,
            });
        }
        self.parse_coverage = ConfigParseCoverage::Partial;
        self.diagnostics.push(diagnostic);
        Ok(())
    }
}

#[derive(Debug)]
pub enum SupabaseConfigError {
    InvalidLimits,
    NonCanonicalPath,
    EmptyContentDigest,
    ConfigTooLarge { max: usize },
    TooManyLines { max: usize },
    LineTooLong { line: usize, max: usize },
    TooManySections { max: usize },
    TooManySchemas { max: usize },
    TooManyFunctions { max: usize },
    IdentifierTooLong { line: usize, max: usize },
    TooManyDiagnostics { max: usize },
    NonUtf8,
}

impl fmt::Display for SupabaseConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("Supabase config limits must be non-zero"),
            Self::NonCanonicalPath => formatter.write_str(
                "Supabase configuration parser accepts only canonical supabase/config.toml",
            ),
            Self::EmptyContentDigest => formatter.write_str("config content digest must not be empty"),
            Self::ConfigTooLarge { max } => {
                write!(formatter, "Supabase config exceeds byte cap {max}")
            }
            Self::TooManyLines { max } => {
                write!(formatter, "Supabase config exceeds line cap {max}")
            }
            Self::LineTooLong { line, max } => {
                write!(formatter, "Supabase config line {line} exceeds byte cap {max}")
            }
            Self::TooManySections { max } => {
                write!(formatter, "Supabase config exceeds table cap {max}")
            }
            Self::TooManySchemas { max } => {
                write!(formatter, "Supabase config exposed schema count exceeds cap {max}")
            }
            Self::TooManyFunctions { max } => {
                write!(formatter, "Supabase config function table count exceeds cap {max}")
            }
            Self::IdentifierTooLong { line, max } => write!(
                formatter,
                "Supabase config identifier at line {line} exceeds byte cap {max}"
            ),
            Self::TooManyDiagnostics { max } => {
                write!(formatter, "Supabase config diagnostic count exceeds cap {max}")
            }
            Self::NonUtf8 => formatter.write_str("Supabase config must be UTF-8"),
        }
    }
}

impl Error for SupabaseConfigError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ConfigTable {
    Root,
    Api,
    Function(String),
    Auth,
    Other,
}

pub fn parse_supabase_config(
    path: &NormalizedRepoPath,
    content_digest: &str,
    bytes: &[u8],
    limits: SupabaseConfigLimits,
) -> Result<SupabaseConfigPosture, SupabaseConfigError> {
    validate_limits(limits)?;
    if path.as_str() != SUPABASE_CONFIG_PATH {
        return Err(SupabaseConfigError::NonCanonicalPath);
    }
    if content_digest.trim().is_empty() {
        return Err(SupabaseConfigError::EmptyContentDigest);
    }
    if bytes.len() > limits.max_bytes {
        return Err(SupabaseConfigError::ConfigTooLarge {
            max: limits.max_bytes,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SupabaseConfigError::NonUtf8)?;
    let line_count = text.lines().count();
    if line_count > limits.max_lines {
        return Err(SupabaseConfigError::TooManyLines {
            max: limits.max_lines,
        });
    }

    let mut posture = SupabaseConfigPosture::new(path.clone(), content_digest.to_owned());
    let mut table = ConfigTable::Root;
    let mut section_count = 0_usize;
    let mut seen_api_enabled = false;
    let mut seen_api_schemas = false;
    let mut ambiguous_function_jwt = BTreeSet::<String>::new();

    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        if raw_line.len() > limits.max_line_bytes {
            return Err(SupabaseConfigError::LineTooLong {
                line: line_number,
                max: limits.max_line_bytes,
            });
        }
        let without_comment = strip_comment(raw_line);
        let line = without_comment.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') {
            section_count = section_count.saturating_add(1);
            if section_count > limits.max_sections {
                return Err(SupabaseConfigError::TooManySections {
                    max: limits.max_sections,
                });
            }
            table = parse_table_header(line, line_number, limits, &mut posture)?;
            continue;
        }

        let Some((raw_key, raw_value)) = split_assignment(line) else {
            posture.degrade(
                limits,
                ConfigDiagnostic {
                    line: line_number,
                    kind: ConfigDiagnosticKind::MalformedSyntax,
                    table: table_name(&table),
                    key: None,
                },
            )?;
            continue;
        };
        let key = raw_key.trim();
        if !valid_identifier(key, limits.max_identifier_bytes) {
            if key.len() > limits.max_identifier_bytes {
                return Err(SupabaseConfigError::IdentifierTooLong {
                    line: line_number,
                    max: limits.max_identifier_bytes,
                });
            }
            posture.degrade(
                limits,
                ConfigDiagnostic {
                    line: line_number,
                    kind: ConfigDiagnosticKind::MalformedSyntax,
                    table: table_name(&table),
                    key: bounded_label(key, limits.max_identifier_bytes),
                },
            )?;
            continue;
        }

        match &table {
            ConfigTable::Root | ConfigTable::Other => {}
            ConfigTable::Api => match key {
                "enabled" => {
                    if seen_api_enabled {
                        posture.api_enabled = None;
                        posture.degrade(
                            limits,
                            duplicate_key(line_number, "api", key),
                        )?;
                    } else if let Some(value) = parse_bool(raw_value.trim()) {
                        posture.api_enabled = Some(ConfigValue {
                            value,
                            line: line_number,
                        });
                        seen_api_enabled = true;
                    } else {
                        seen_api_enabled = true;
                        posture.degrade(
                            limits,
                            malformed_key(line_number, "api", key),
                        )?;
                    }
                }
                "schemas" => {
                    if seen_api_schemas {
                        posture.api_exposed_schemas = None;
                        posture.degrade(
                            limits,
                            duplicate_key(line_number, "api", key),
                        )?;
                    } else {
                        seen_api_schemas = true;
                        match parse_string_array(
                            raw_value.trim(),
                            line_number,
                            limits,
                        )? {
                            Some(value) => {
                                posture.api_exposed_schemas = Some(ConfigValue {
                                    value,
                                    line: line_number,
                                });
                            }
                            None => posture.degrade(
                                limits,
                                malformed_key(line_number, "api", key),
                            )?,
                        }
                    }
                }
                _ => posture.degrade(
                    limits,
                    unsupported_key(line_number, "api", key),
                )?,
            },
            ConfigTable::Function(function_name) => {
                if key != "verify_jwt" {
                    posture.degrade(
                        limits,
                        unsupported_key(
                            line_number,
                            &format!("functions.{function_name}"),
                            key,
                        ),
                    )?;
                    continue;
                }
                let entry = posture
                    .edge_function_auth
                    .entry(function_name.clone())
                    .or_insert(EdgeFunctionConfigPosture {
                        platform_jwt_verification: None,
                    });
                if ambiguous_function_jwt.contains(function_name)
                    || entry.platform_jwt_verification.is_some()
                {
                    entry.platform_jwt_verification = None;
                    ambiguous_function_jwt.insert(function_name.clone());
                    posture.degrade(
                        limits,
                        duplicate_key(
                            line_number,
                            &format!("functions.{function_name}"),
                            key,
                        ),
                    )?;
                } else if let Some(value) = parse_bool(raw_value.trim()) {
                    entry.platform_jwt_verification = Some(ConfigValue {
                        value,
                        line: line_number,
                    });
                } else {
                    ambiguous_function_jwt.insert(function_name.clone());
                    posture.degrade(
                        limits,
                        malformed_key(
                            line_number,
                            &format!("functions.{function_name}"),
                            key,
                        ),
                    )?;
                }
            }
            ConfigTable::Auth => posture.degrade(
                limits,
                unsupported_key(line_number, "auth", key),
            )?,
        }
    }

    Ok(posture)
}

fn validate_limits(limits: SupabaseConfigLimits) -> Result<(), SupabaseConfigError> {
    if limits.max_bytes == 0
        || limits.max_lines == 0
        || limits.max_line_bytes == 0
        || limits.max_sections == 0
        || limits.max_schemas == 0
        || limits.max_functions == 0
        || limits.max_identifier_bytes == 0
        || limits.max_diagnostics == 0
    {
        return Err(SupabaseConfigError::InvalidLimits);
    }
    Ok(())
}

fn parse_table_header(
    line: &str,
    line_number: usize,
    limits: SupabaseConfigLimits,
    posture: &mut SupabaseConfigPosture,
) -> Result<ConfigTable, SupabaseConfigError> {
    if line.starts_with("[[") || !line.ends_with(']') || line.len() < 3 {
        posture.degrade(
            limits,
            ConfigDiagnostic {
                line: line_number,
                kind: ConfigDiagnosticKind::MalformedSyntax,
                table: None,
                key: None,
            },
        )?;
        return Ok(ConfigTable::Other);
    }
    let inner = &line[1..line.len() - 1];
    if inner.contains('[') || inner.contains(']') {
        posture.degrade(
            limits,
            ConfigDiagnostic {
                line: line_number,
                kind: ConfigDiagnosticKind::MalformedSyntax,
                table: bounded_label(inner, limits.max_identifier_bytes),
                key: None,
            },
        )?;
        return Ok(ConfigTable::Other);
    }
    let parts: Vec<&str> = inner.split('.').map(str::trim).collect();
    if parts.len() > MAX_SUPPORTED_TABLE_DEPTH {
        posture.degrade(
            limits,
            ConfigDiagnostic {
                line: line_number,
                kind: ConfigDiagnosticKind::UnsupportedSecurityRelevantTable,
                table: bounded_label(inner, limits.max_identifier_bytes),
                key: None,
            },
        )?;
        return Ok(ConfigTable::Other);
    }
    if parts.iter().any(|part| {
        !valid_identifier(part, limits.max_identifier_bytes)
    }) {
        if parts
            .iter()
            .any(|part| part.len() > limits.max_identifier_bytes)
        {
            return Err(SupabaseConfigError::IdentifierTooLong {
                line: line_number,
                max: limits.max_identifier_bytes,
            });
        }
        posture.degrade(
            limits,
            ConfigDiagnostic {
                line: line_number,
                kind: ConfigDiagnosticKind::MalformedSyntax,
                table: bounded_label(inner, limits.max_identifier_bytes),
                key: None,
            },
        )?;
        return Ok(ConfigTable::Other);
    }

    match parts.as_slice() {
        ["api"] => Ok(ConfigTable::Api),
        ["auth"] => Ok(ConfigTable::Auth),
        ["functions", function_name] => {
            if !posture.edge_function_auth.contains_key(*function_name)
                && posture.edge_function_auth.len() >= limits.max_functions
            {
                return Err(SupabaseConfigError::TooManyFunctions {
                    max: limits.max_functions,
                });
            }
            posture
                .edge_function_auth
                .entry((*function_name).to_owned())
                .or_insert(EdgeFunctionConfigPosture {
                    platform_jwt_verification: None,
                });
            Ok(ConfigTable::Function((*function_name).to_owned()))
        }
        ["functions"] => {
            posture.degrade(
                limits,
                ConfigDiagnostic {
                    line: line_number,
                    kind: ConfigDiagnosticKind::UnsupportedSecurityRelevantTable,
                    table: Some("functions".to_owned()),
                    key: None,
                },
            )?;
            Ok(ConfigTable::Other)
        }
        _ => Ok(ConfigTable::Other),
    }
}

fn parse_string_array(
    raw: &str,
    line_number: usize,
    limits: SupabaseConfigLimits,
) -> Result<Option<BTreeSet<String>>, SupabaseConfigError> {
    if !raw.starts_with('[') || !raw.ends_with(']') {
        return Ok(None);
    }
    let inner = raw[1..raw.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Some(BTreeSet::new()));
    }

    let mut values = BTreeSet::new();
    let mut item_count = 0_usize;
    for item in inner.split(',') {
        item_count = item_count.saturating_add(1);
        if item_count > limits.max_schemas {
            return Err(SupabaseConfigError::TooManySchemas {
                max: limits.max_schemas,
            });
        }
        let item = item.trim();
        let Some(value) = parse_simple_quoted_string(item) else {
            return Ok(None);
        };
        if value.len() > limits.max_identifier_bytes {
            return Err(SupabaseConfigError::IdentifierTooLong {
                line: line_number,
                max: limits.max_identifier_bytes,
            });
        }
        if !valid_schema_name(value, limits.max_identifier_bytes) {
            return Ok(None);
        }
        values.insert(value.to_owned());
    }
    Ok(Some(values))
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quoted {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if character == '#' && !quoted {
            return &line[..index];
        }
    }
    line
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quoted {
            escaped = true;
            continue;
        }
        if character == '"' {
            quoted = !quoted;
            continue;
        }
        if character == '=' && !quoted {
            return Some((&line[..index], &line[index + 1..]));
        }
    }
    None
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn parse_simple_quoted_string(raw: &str) -> Option<&str> {
    if raw.len() < 2 || !raw.starts_with('"') || !raw.ends_with('"') {
        return None;
    }
    let value = &raw[1..raw.len() - 1];
    if value.contains('"') || value.contains('\\') || value.contains('\n') || value.contains('\r') {
        return None;
    }
    Some(value)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    if value.is_empty() || value.len() > max_bytes {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_schema_name(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if value.len() > max_bytes || !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
}

fn table_name(table: &ConfigTable) -> Option<String> {
    match table {
        ConfigTable::Root => None,
        ConfigTable::Api => Some("api".to_owned()),
        ConfigTable::Function(name) => Some(format!("functions.{name}")),
        ConfigTable::Auth => Some("auth".to_owned()),
        ConfigTable::Other => None,
    }
}

fn bounded_label(value: &str, max_bytes: usize) -> Option<String> {
    if value.is_empty() {
        None
    } else if value.len() <= max_bytes {
        Some(value.to_owned())
    } else {
        None
    }
}

fn malformed_key(line: usize, table: &str, key: &str) -> ConfigDiagnostic {
    ConfigDiagnostic {
        line,
        kind: ConfigDiagnosticKind::MalformedSyntax,
        table: Some(table.to_owned()),
        key: Some(key.to_owned()),
    }
}

fn duplicate_key(line: usize, table: &str, key: &str) -> ConfigDiagnostic {
    ConfigDiagnostic {
        line,
        kind: ConfigDiagnosticKind::DuplicateSupportedKey,
        table: Some(table.to_owned()),
        key: Some(key.to_owned()),
    }
}

fn unsupported_key(line: usize, table: &str, key: &str) -> ConfigDiagnostic {
    ConfigDiagnostic {
        line,
        kind: ConfigDiagnosticKind::UnsupportedSecurityRelevantKey,
        table: Some(table.to_owned()),
        key: Some(key.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> NormalizedRepoPath {
        NormalizedRepoPath::parse(SUPABASE_CONFIG_PATH, 4096).unwrap()
    }

    fn parse(text: &str) -> SupabaseConfigPosture {
        parse_supabase_config(
            &path(),
            "sha256:config",
            text.as_bytes(),
            SupabaseConfigLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn parses_allowlisted_api_and_edge_function_configuration() {
        let posture = parse(
            "project_id = \"fixture\"\n\n[api]\nenabled = true\nschemas = [\"public\", \"storage\"]\n\n[functions.webhook]\nverify_jwt = true\n",
        );
        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Complete);
        assert_eq!(posture.api_enabled.as_ref().map(|value| value.value), Some(true));
        assert_eq!(
            posture.api_exposed_schemas.as_ref().map(|value| value.value.clone()),
            Some(BTreeSet::from(["public".to_owned(), "storage".to_owned()]))
        );
        assert_eq!(
            posture
                .edge_function_auth
                .get("webhook")
                .and_then(|value| value.platform_jwt_verification.as_ref())
                .map(|value| value.value),
            Some(true)
        );
        assert!(posture.diagnostics.is_empty());
    }

    #[test]
    fn disabled_edge_jwt_is_a_direct_config_fact_not_an_interpretation() {
        let posture = parse(
            "[api]\nenabled = true\nschemas = [\"public\"]\n[functions.webhook]\nverify_jwt = false\n",
        );
        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Complete);
        assert_eq!(
            posture
                .edge_function_auth
                .get("webhook")
                .and_then(|value| value.platform_jwt_verification.as_ref())
                .map(|value| value.value),
            Some(false)
        );
    }

    #[test]
    fn malformed_security_table_degrades_coverage_without_inventing_state() {
        let posture = parse(
            "project_id = \"fixture\"\n[functions.webhook\nverify_jwt = false\n",
        );
        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Partial);
        assert!(posture.edge_function_auth.is_empty());
        assert!(posture
            .diagnostics
            .iter()
            .any(|item| item.kind == ConfigDiagnosticKind::MalformedSyntax));
    }

    #[test]
    fn duplicate_supported_keys_become_unknown_and_partial() {
        let posture = parse(
            "[api]\nenabled = true\nenabled = false\n[functions.webhook]\nverify_jwt = true\nverify_jwt = false\n",
        );
        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Partial);
        assert!(posture.api_enabled.is_none());
        assert!(posture
            .edge_function_auth
            .get("webhook")
            .unwrap()
            .platform_jwt_verification
            .is_none());
        assert!(posture.diagnostics.iter().all(|item| {
            item.kind == ConfigDiagnosticKind::DuplicateSupportedKey
        }));
    }

    #[test]
    fn unknown_security_relevant_keys_and_auth_config_degrade_coverage() {
        let posture = parse(
            "[api]\nenabled = true\nunknown_security_toggle = true\n[auth]\nenabled = true\n",
        );
        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Partial);
        assert_eq!(posture.diagnostics.len(), 2);
        assert!(posture.diagnostics.iter().all(|item| {
            item.kind == ConfigDiagnosticKind::UnsupportedSecurityRelevantKey
        }));
    }

    #[test]
    fn comments_are_bounded_and_do_not_change_allowlisted_values() {
        let posture = parse(
            "[api] # api table\nenabled = true # direct fact\nschemas = [\"public\", \"storage\"] # static exposure\n",
        );
        assert_eq!(posture.parse_coverage, ConfigParseCoverage::Complete);
        assert_eq!(posture.api_enabled.unwrap().value, true);
        assert_eq!(posture.api_exposed_schemas.unwrap().value.len(), 2);
    }

    #[test]
    fn hard_resource_and_canonical_input_caps_fail_closed() {
        let default = SupabaseConfigLimits::default();
        assert!(matches!(
            parse_supabase_config(
                &NormalizedRepoPath::parse("config.toml", 4096).unwrap(),
                "sha256:x",
                b"[api]\nenabled=true\n",
                default,
            ),
            Err(SupabaseConfigError::NonCanonicalPath)
        ));
        assert!(matches!(
            parse_supabase_config(&path(), "", b"", default),
            Err(SupabaseConfigError::EmptyContentDigest)
        ));
        assert!(matches!(
            parse_supabase_config(
                &path(),
                "sha256:x",
                b"x",
                SupabaseConfigLimits {
                    max_bytes: 0,
                    ..default
                },
            ),
            Err(SupabaseConfigError::InvalidLimits)
        ));
        assert!(matches!(
            parse_supabase_config(
                &path(),
                "sha256:x",
                b"[api]\nschemas=[\"a\",\"b\"]\n",
                SupabaseConfigLimits {
                    max_schemas: 1,
                    ..default
                },
            ),
            Err(SupabaseConfigError::TooManySchemas { max: 1 })
        ));
        assert!(matches!(
            parse_supabase_config(&path(), "sha256:x", &[0xff], default),
            Err(SupabaseConfigError::NonUtf8)
        ));
    }
}