//! Bounded lockfile dependency deltas and offline advisory fixtures.
//!
//! Target lockfiles are parsed as untrusted data. This module never executes
//! Cargo, npm, pnpm, pip, package-manager hooks, repository configuration, or
//! network operations.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_LOCKFILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_LOCKFILE_PACKAGES: usize = 50_000;
pub const MAX_ADVISORY_FIXTURE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OFFLINE_ADVISORIES: usize = 10_000;
const MAX_FIELD_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Ecosystem {
    Cargo,
    Npm,
}

impl Ecosystem {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockfileKind {
    Cargo,
    Npm,
}

impl LockfileKind {
    #[must_use]
    pub const fn ecosystem(self) -> Ecosystem {
        match self {
            Self::Cargo => Ecosystem::Cargo,
            Self::Npm => Ecosystem::Npm,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackageVersion {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyDelta {
    pub added: Vec<PackageVersion>,
    pub removed: Vec<PackageVersion>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineAdvisory {
    pub id: String,
    pub ecosystem: Ecosystem,
    pub package: String,
    pub affected_versions: BTreeSet<String>,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvisoryMatch {
    pub advisory_id: String,
    pub package: PackageVersion,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineAdvisoryProvider {
    advisories: Vec<OfflineAdvisory>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DependencyError {
    InputTooLarge { bytes: usize, max: usize },
    NonUtf8,
    InvalidFormat(&'static str),
    InvalidField(&'static str),
    TooManyPackages { count: usize, max: usize },
    TooManyAdvisories { count: usize, max: usize },
}

impl fmt::Display for DependencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { bytes, max } => {
                write!(
                    formatter,
                    "input size {bytes} exceeds dependency parser cap {max}"
                )
            }
            Self::NonUtf8 => formatter.write_str("dependency input must be valid UTF-8"),
            Self::InvalidFormat(message) => {
                write!(formatter, "invalid dependency format: {message}")
            }
            Self::InvalidField(field) => write!(formatter, "invalid dependency field: {field}"),
            Self::TooManyPackages { count, max } => {
                write!(formatter, "package count {count} exceeds cap {max}")
            }
            Self::TooManyAdvisories { count, max } => {
                write!(formatter, "advisory count {count} exceeds cap {max}")
            }
        }
    }
}

impl std::error::Error for DependencyError {}

pub fn dependency_delta(
    kind: LockfileKind,
    before: &[u8],
    after: &[u8],
) -> Result<DependencyDelta, DependencyError> {
    let before = parse_lockfile(kind, before)?;
    let after = parse_lockfile(kind, after)?;
    Ok(DependencyDelta {
        added: after.difference(&before).cloned().collect(),
        removed: before.difference(&after).cloned().collect(),
    })
}

pub fn parse_lockfile(
    kind: LockfileKind,
    bytes: &[u8],
) -> Result<BTreeSet<PackageVersion>, DependencyError> {
    if bytes.len() > MAX_LOCKFILE_BYTES {
        return Err(DependencyError::InputTooLarge {
            bytes: bytes.len(),
            max: MAX_LOCKFILE_BYTES,
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| DependencyError::NonUtf8)?;
    let packages = match kind {
        LockfileKind::Cargo => parse_cargo_lock(text)?,
        LockfileKind::Npm => parse_npm_lock(text)?,
    };
    if packages.len() > MAX_LOCKFILE_PACKAGES {
        return Err(DependencyError::TooManyPackages {
            count: packages.len(),
            max: MAX_LOCKFILE_PACKAGES,
        });
    }
    Ok(packages)
}

fn parse_cargo_lock(text: &str) -> Result<BTreeSet<PackageVersion>, DependencyError> {
    let mut packages = BTreeSet::new();
    let mut current: Option<BTreeMap<&str, String>> = None;
    let mut record_count = 0usize;

    for raw in text.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            record_count += 1;
            if record_count > MAX_LOCKFILE_PACKAGES {
                return Err(DependencyError::TooManyPackages {
                    count: record_count,
                    max: MAX_LOCKFILE_PACKAGES,
                });
            }
            if let Some(fields) = current.take() {
                insert_cargo_package(&mut packages, fields)?;
            }
            current = Some(BTreeMap::new());
            continue;
        }
        let Some(fields) = current.as_mut() else {
            continue;
        };
        if let Some(value) = parse_simple_toml_string(line, "name")? {
            fields.insert("name", value);
        } else if let Some(value) = parse_simple_toml_string(line, "version")? {
            fields.insert("version", value);
        }
    }
    if let Some(fields) = current {
        insert_cargo_package(&mut packages, fields)?;
    }
    if packages.is_empty() {
        return Err(DependencyError::InvalidFormat(
            "Cargo.lock contains no package records",
        ));
    }
    Ok(packages)
}

fn insert_cargo_package(
    packages: &mut BTreeSet<PackageVersion>,
    fields: BTreeMap<&str, String>,
) -> Result<(), DependencyError> {
    let name = fields
        .get("name")
        .ok_or(DependencyError::InvalidFormat("Cargo package missing name"))?;
    let version = fields.get("version").ok_or(DependencyError::InvalidFormat(
        "Cargo package missing version",
    ))?;
    validate_field(name, "package name")?;
    validate_field(version, "package version")?;
    packages.insert(PackageVersion {
        ecosystem: Ecosystem::Cargo,
        name: name.clone(),
        version: version.clone(),
    });
    Ok(())
}

fn parse_simple_toml_string(
    line: &str,
    key: &'static str,
) -> Result<Option<String>, DependencyError> {
    let Some(rest) = line.strip_prefix(key) else {
        return Ok(None);
    };
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix('=') else {
        return Ok(None);
    };
    let value = rest.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return Err(DependencyError::InvalidFormat(
            "unsupported Cargo.lock string",
        ));
    }
    let value = &value[1..value.len() - 1];
    if value
        .chars()
        .any(|character| matches!(character, '\\' | '"' | '\n' | '\r'))
    {
        return Err(DependencyError::InvalidFormat(
            "escaped Cargo.lock identity string",
        ));
    }
    Ok(Some(value.to_owned()))
}

fn parse_npm_lock(text: &str) -> Result<BTreeSet<PackageVersion>, DependencyError> {
    let root: Value = serde_json::from_str(text)
        .map_err(|_| DependencyError::InvalidFormat("package-lock.json is not valid JSON"))?;
    let object = root.as_object().ok_or(DependencyError::InvalidFormat(
        "package-lock.json root must be an object",
    ))?;
    let lockfile_version = object
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .ok_or(DependencyError::InvalidFormat(
            "package-lock.json missing lockfileVersion",
        ))?;
    if !(2..=3).contains(&lockfile_version) {
        return Err(DependencyError::InvalidFormat(
            "only npm lockfileVersion 2 or 3 is supported",
        ));
    }
    let entries =
        object
            .get("packages")
            .and_then(Value::as_object)
            .ok_or(DependencyError::InvalidFormat(
                "package-lock.json missing packages object",
            ))?;
    if entries.len() > MAX_LOCKFILE_PACKAGES + 1 {
        return Err(DependencyError::TooManyPackages {
            count: entries.len(),
            max: MAX_LOCKFILE_PACKAGES,
        });
    }

    let mut packages = BTreeSet::new();
    for (path, value) in entries {
        if path.is_empty() {
            continue;
        }
        let package = value.as_object().ok_or(DependencyError::InvalidFormat(
            "npm package record must be an object",
        ))?;
        if package.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let version = package.get("version").and_then(Value::as_str).ok_or(
            DependencyError::InvalidFormat("npm package record missing version"),
        )?;
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| npm_name_from_package_path(path))
            .ok_or(DependencyError::InvalidFormat(
                "cannot infer npm package name",
            ))?;
        validate_field(&name, "package name")?;
        validate_field(version, "package version")?;
        packages.insert(PackageVersion {
            ecosystem: Ecosystem::Npm,
            name,
            version: version.to_owned(),
        });
    }
    Ok(packages)
}

fn npm_name_from_package_path(path: &str) -> Option<String> {
    let marker = "node_modules/";
    let index = path.rfind(marker)?;
    let suffix = &path[index + marker.len()..];
    if suffix.is_empty() || suffix.contains("/node_modules/") {
        return None;
    }
    Some(suffix.to_owned())
}

impl OfflineAdvisoryProvider {
    pub fn from_fixture(bytes: &[u8]) -> Result<Self, DependencyError> {
        if bytes.len() > MAX_ADVISORY_FIXTURE_BYTES {
            return Err(DependencyError::InputTooLarge {
                bytes: bytes.len(),
                max: MAX_ADVISORY_FIXTURE_BYTES,
            });
        }
        let root: Value = serde_json::from_slice(bytes)
            .map_err(|_| DependencyError::InvalidFormat("advisory fixture is not valid JSON"))?;
        let object = root.as_object().ok_or(DependencyError::InvalidFormat(
            "advisory fixture root must be an object",
        ))?;
        if object.get("schema_version").and_then(Value::as_str) != Some("1") {
            return Err(DependencyError::InvalidFormat(
                "unsupported advisory fixture schema",
            ));
        }
        let entries = object.get("advisories").and_then(Value::as_array).ok_or(
            DependencyError::InvalidFormat("advisory fixture missing advisories"),
        )?;
        if entries.len() > MAX_OFFLINE_ADVISORIES {
            return Err(DependencyError::TooManyAdvisories {
                count: entries.len(),
                max: MAX_OFFLINE_ADVISORIES,
            });
        }

        let mut advisories = Vec::with_capacity(entries.len());
        let mut ids = BTreeSet::new();
        for entry in entries {
            let entry = entry
                .as_object()
                .ok_or(DependencyError::InvalidFormat("advisory must be an object"))?;
            let id = required_string(entry, "id")?;
            if !ids.insert(id.clone()) {
                return Err(DependencyError::InvalidFormat("duplicate advisory id"));
            }
            let ecosystem = match required_string(entry, "ecosystem")?.as_str() {
                "cargo" => Ecosystem::Cargo,
                "npm" => Ecosystem::Npm,
                _ => return Err(DependencyError::InvalidField("ecosystem")),
            };
            let package = required_string(entry, "package")?;
            let summary = required_string(entry, "summary")?;
            let versions = entry
                .get("affected_versions")
                .and_then(Value::as_array)
                .ok_or(DependencyError::InvalidFormat(
                    "advisory missing affected_versions",
                ))?;
            if versions.is_empty() || versions.len() > 1_000 {
                return Err(DependencyError::InvalidField("affected_versions"));
            }
            let mut affected_versions = BTreeSet::new();
            for version in versions {
                let version = version
                    .as_str()
                    .ok_or(DependencyError::InvalidField("affected_versions"))?;
                validate_field(version, "affected version")?;
                affected_versions.insert(version.to_owned());
            }
            advisories.push(OfflineAdvisory {
                id,
                ecosystem,
                package,
                affected_versions,
                summary,
            });
        }
        advisories.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Self { advisories })
    }

    #[must_use]
    pub fn match_added(&self, delta: &DependencyDelta) -> Vec<AdvisoryMatch> {
        let mut matches = Vec::new();
        for package in &delta.added {
            for advisory in &self.advisories {
                if advisory.ecosystem == package.ecosystem
                    && advisory.package == package.name
                    && advisory.affected_versions.contains(&package.version)
                {
                    matches.push(AdvisoryMatch {
                        advisory_id: advisory.id.clone(),
                        package: package.clone(),
                        summary: advisory.summary.clone(),
                    });
                }
            }
        }
        matches.sort_by(|left, right| {
            left.package
                .cmp(&right.package)
                .then_with(|| left.advisory_id.cmp(&right.advisory_id))
        });
        matches
    }
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<String, DependencyError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(DependencyError::InvalidField(key))?;
    validate_field(value, key)?;
    Ok(value.to_owned())
}

fn validate_field(value: &str, field: &'static str) -> Result<(), DependencyError> {
    if value.trim().is_empty()
        || value.len() > MAX_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(DependencyError::InvalidField(field));
    }
    Ok(())
}
