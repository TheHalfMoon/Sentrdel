//! Supabase R2 provider contract and bounded migration discovery.
//!
//! This module defines the versioned Sentrdel-owned provider manifest,
//! provider coverage capability names, and deterministic repository-path-only
//! migration ordering. It grants no Finding or policy authority and never
//! executes migration SQL or provider tooling.

pub mod config;
pub mod function_authority;
pub mod grants;
pub mod key_authority;
pub mod key_boundary;
pub mod policy;
pub mod posture;
pub mod rls;
pub mod source_context;
pub mod sql;
pub mod sql_model;
pub mod state;
pub mod storage;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::pack::{SecurityPackManifest, SourceProvenance};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath, RepoViewError};

pub const SUPABASE_R2_PACK_ID: &str = "sentrdel.supabase.static-posture";
pub const SUPABASE_R2_PACK_VERSION: &str = "1";
pub const SUPABASE_PROVIDER: &str = "supabase";

pub const COVERAGE_DETECTION: &str = "DETECTION";
pub const COVERAGE_STATIC_POSTURE_DATABASE: &str = "STATIC_POSTURE_DATABASE";
pub const COVERAGE_STATIC_POSTURE_STORAGE: &str = "STATIC_POSTURE_STORAGE";
pub const COVERAGE_STATIC_POSTURE_AUTH_CONFIG: &str = "STATIC_POSTURE_AUTH_CONFIG";
pub const COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS: &str = "STATIC_POSTURE_EDGE_FUNCTIONS";
pub const COVERAGE_STATIC_POSTURE_KEY_BOUNDARY: &str = "STATIC_POSTURE_KEY_BOUNDARY";
pub const COVERAGE_LIVE_POSTURE: &str = "LIVE_POSTURE";
pub const COVERAGE_BUSINESS_LOGIC: &str = "BUSINESS_LOGIC";
pub const COVERAGE_RUNTIME: &str = "RUNTIME";

pub const SUPABASE_R2_COVERAGE_DIMENSIONS: &[&str] = &[
    COVERAGE_DETECTION,
    COVERAGE_STATIC_POSTURE_DATABASE,
    COVERAGE_STATIC_POSTURE_STORAGE,
    COVERAGE_STATIC_POSTURE_AUTH_CONFIG,
    COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS,
    COVERAGE_STATIC_POSTURE_KEY_BOUNDARY,
    COVERAGE_LIVE_POSTURE,
    COVERAGE_BUSINESS_LOGIC,
    COVERAGE_RUNTIME,
];

pub const SUPABASE_MIGRATION_DIRECTORY: &str = "supabase/migrations/";
pub const SUPABASE_MIGRATION_ORDER_KEY_BYTES: usize = 14;
pub const DEFAULT_MAX_SUPABASE_MIGRATIONS: usize = 4_096;
pub const DEFAULT_MAX_SUPABASE_MIGRATION_TOTAL_PATH_BYTES: usize = 1024 * 1024;
pub const SUPABASE_MIGRATION_EXECUTION_ALLOWED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupabaseMigrationDiscoveryLimits {
    pub max_migrations: usize,
    pub max_path_bytes: usize,
    pub max_total_path_bytes: usize,
}

impl Default for SupabaseMigrationDiscoveryLimits {
    fn default() -> Self {
        Self {
            max_migrations: DEFAULT_MAX_SUPABASE_MIGRATIONS,
            max_path_bytes: DEFAULT_MAX_REPO_PATH_BYTES,
            max_total_path_bytes: DEFAULT_MAX_SUPABASE_MIGRATION_TOTAL_PATH_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupabaseMigrationPath {
    pub path: NormalizedRepoPath,
    pub order_key: String,
}

#[derive(Debug)]
pub enum SupabaseMigrationDiscoveryError {
    InvalidLimits,
    TooManyMigrations {
        max: usize,
    },
    TotalPathBytesExceeded {
        max: usize,
    },
    InvalidPath {
        index: usize,
        source: RepoViewError,
    },
    UnsupportedMigrationFilename {
        path: NormalizedRepoPath,
    },
    AmbiguousOrderKey {
        order_key: String,
        first: NormalizedRepoPath,
        second: NormalizedRepoPath,
    },
}

impl fmt::Display for SupabaseMigrationDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                formatter.write_str("Supabase migration discovery limits must be non-zero")
            }
            Self::TooManyMigrations { max } => write!(
                formatter,
                "Supabase migration count exceeds discovery cap {max}"
            ),
            Self::TotalPathBytesExceeded { max } => write!(
                formatter,
                "Supabase migration path bytes exceed discovery cap {max}"
            ),
            Self::InvalidPath { index, source } => write!(
                formatter,
                "Supabase migration path at input index {index} is invalid: {source}"
            ),
            Self::UnsupportedMigrationFilename { path } => write!(
                formatter,
                "Supabase migration path {path} does not use the supported 14-digit order-key filename form"
            ),
            Self::AmbiguousOrderKey {
                order_key,
                first,
                second,
            } => write!(
                formatter,
                "Supabase migration order key {order_key} is ambiguous between {first} and {second}"
            ),
        }
    }
}

impl Error for SupabaseMigrationDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn discover_migration_paths<I, S>(
    paths: I,
    limits: SupabaseMigrationDiscoveryLimits,
) -> Result<Vec<SupabaseMigrationPath>, SupabaseMigrationDiscoveryError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if limits.max_migrations == 0 || limits.max_path_bytes == 0 || limits.max_total_path_bytes == 0
    {
        return Err(SupabaseMigrationDiscoveryError::InvalidLimits);
    }

    let mut migrations = Vec::new();
    let mut seen_order_keys = BTreeMap::<String, NormalizedRepoPath>::new();
    let mut total_path_bytes = 0_usize;

    for (index, raw_path) in paths.into_iter().enumerate() {
        let raw_path = raw_path.as_ref();
        let Some(relative) = raw_path.strip_prefix(SUPABASE_MIGRATION_DIRECTORY) else {
            continue;
        };
        if relative.is_empty() || relative.contains('/') || !relative.ends_with(".sql") {
            continue;
        }
        if migrations.len() >= limits.max_migrations {
            return Err(SupabaseMigrationDiscoveryError::TooManyMigrations {
                max: limits.max_migrations,
            });
        }

        let path = NormalizedRepoPath::parse(raw_path, limits.max_path_bytes)
            .map_err(|source| SupabaseMigrationDiscoveryError::InvalidPath { index, source })?;
        let order_key = migration_order_key(relative)
            .ok_or_else(
                || SupabaseMigrationDiscoveryError::UnsupportedMigrationFilename {
                    path: path.clone(),
                },
            )?
            .to_owned();

        total_path_bytes = total_path_bytes.saturating_add(path.as_str().len());
        if total_path_bytes > limits.max_total_path_bytes {
            return Err(SupabaseMigrationDiscoveryError::TotalPathBytesExceeded {
                max: limits.max_total_path_bytes,
            });
        }

        if let Some(first) = seen_order_keys.insert(order_key.clone(), path.clone()) {
            return Err(SupabaseMigrationDiscoveryError::AmbiguousOrderKey {
                order_key,
                first,
                second: path,
            });
        }

        migrations.push(SupabaseMigrationPath { path, order_key });
    }

    migrations.sort_by(|left, right| {
        left.order_key
            .cmp(&right.order_key)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(migrations)
}

fn migration_order_key(file_name: &str) -> Option<&str> {
    let bytes = file_name.as_bytes();
    let key = bytes.get(..SUPABASE_MIGRATION_ORDER_KEY_BYTES)?;
    if !key.iter().all(u8::is_ascii_digit) {
        return None;
    }

    let separator = *bytes.get(SUPABASE_MIGRATION_ORDER_KEY_BYTES)?;
    match separator {
        b'.' if bytes.len() == SUPABASE_MIGRATION_ORDER_KEY_BYTES + ".sql".len() => {}
        b'_' if bytes.len() > SUPABASE_MIGRATION_ORDER_KEY_BYTES + 1 + ".sql".len() => {}
        _ => return None,
    }

    std::str::from_utf8(key).ok()
}

#[must_use]
pub fn manifest() -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: SUPABASE_R2_PACK_ID.to_owned(),
        version: SUPABASE_R2_PACK_VERSION.to_owned(),
        provider_or_framework: SUPABASE_PROVIDER.to_owned(),
        source_provenance: SourceProvenance {
            source_id: "sentrdel-owned".to_owned(),
            exact_ref: "specs/002-supabase-static-posture".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec!["provider-detection".to_owned()],
        evidence_capabilities: vec!["static-posture-evidence".to_owned()],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: SUPABASE_R2_COVERAGE_DIMENSIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_is_versioned_provider_owned_and_dependency_free() {
        let value = manifest();
        assert_eq!(value.schema_version, SCHEMA_V1);
        assert_eq!(value.pack_id, SUPABASE_R2_PACK_ID);
        assert_eq!(value.version, SUPABASE_R2_PACK_VERSION);
        assert_eq!(value.provider_or_framework, SUPABASE_PROVIDER);
        assert_eq!(value.source_provenance.source_id, "sentrdel-owned");
        assert_eq!(value.source_provenance.license_expression, "Apache-2.0");
        assert!(value.required_engines.is_empty());
        assert!(value.required_features.is_empty());
    }

    #[test]
    fn manifest_exposes_exact_r2_coverage_dimensions() {
        let value = manifest();
        let expected: Vec<String> = SUPABASE_R2_COVERAGE_DIMENSIONS
            .iter()
            .map(|dimension| (*dimension).to_owned())
            .collect();
        assert_eq!(value.coverage_dimensions, expected);
    }

    #[test]
    fn manifest_has_evidence_but_no_finding_or_policy_override_capability() {
        let value = manifest();
        assert!(value.declares_capability("static-posture-evidence"));
        assert!(!value.declares_capability("finding"));
        assert!(!value.declares_capability("policy-override"));
    }

    #[test]
    fn migration_discovery_is_canonical_deterministic_and_non_executing() {
        let migrations = discover_migration_paths(
            [
                "src/lib.rs",
                "supabase/migrations/20260829000300_third.sql",
                "supabase/migrations/README.md",
                "supabase/migrations/nested/20260829000000_ignored.sql",
                "supabase/migrations/20260829000100_first.sql",
                "supabase/migrations/20260829000200_second.sql",
            ],
            SupabaseMigrationDiscoveryLimits::default(),
        )
        .unwrap();

        assert_eq!(migrations.len(), 3);
        assert_eq!(migrations[0].order_key, "20260829000100");
        assert_eq!(migrations[1].order_key, "20260829000200");
        assert_eq!(migrations[2].order_key, "20260829000300");
        assert_eq!(
            migrations[0].path.as_str(),
            "supabase/migrations/20260829000100_first.sql"
        );
        const { assert!(!SUPABASE_MIGRATION_EXECUTION_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }

    #[test]
    fn duplicate_migration_order_keys_fail_closed() {
        let result = discover_migration_paths(
            [
                "supabase/migrations/20260829000300_enable.sql",
                "supabase/migrations/20260829000300_disable.sql",
            ],
            SupabaseMigrationDiscoveryLimits::default(),
        );

        assert!(matches!(
            result,
            Err(SupabaseMigrationDiscoveryError::AmbiguousOrderKey {
                ref order_key,
                ..
            }) if order_key == "20260829000300"
        ));
    }

    #[test]
    fn unsupported_migration_filename_fails_closed() {
        let result = discover_migration_paths(
            ["supabase/migrations/not-a-timestamp.sql"],
            SupabaseMigrationDiscoveryLimits::default(),
        );

        assert!(matches!(
            result,
            Err(SupabaseMigrationDiscoveryError::UnsupportedMigrationFilename { .. })
        ));
    }

    #[test]
    fn migration_discovery_resource_caps_are_enforced() {
        assert!(matches!(
            discover_migration_paths(
                ["supabase/migrations/20260829000100_one.sql"],
                SupabaseMigrationDiscoveryLimits {
                    max_migrations: 0,
                    max_path_bytes: 1,
                    max_total_path_bytes: 1,
                }
            ),
            Err(SupabaseMigrationDiscoveryError::InvalidLimits)
        ));

        assert!(matches!(
            discover_migration_paths(
                [
                    "supabase/migrations/20260829000100_one.sql",
                    "supabase/migrations/20260829000200_two.sql",
                ],
                SupabaseMigrationDiscoveryLimits {
                    max_migrations: 1,
                    ..SupabaseMigrationDiscoveryLimits::default()
                }
            ),
            Err(SupabaseMigrationDiscoveryError::TooManyMigrations { max: 1 })
        ));

        assert!(matches!(
            discover_migration_paths(
                ["supabase/migrations/20260829000100_one.sql"],
                SupabaseMigrationDiscoveryLimits {
                    max_total_path_bytes: 10,
                    ..SupabaseMigrationDiscoveryLimits::default()
                }
            ),
            Err(SupabaseMigrationDiscoveryError::TotalPathBytesExceeded { max: 10 })
        ));
    }
}
