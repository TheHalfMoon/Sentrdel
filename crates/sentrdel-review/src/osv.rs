//! Bounded OSV-compatible advisory lookup and cache primitives.
//!
//! This module owns the untrusted OSV request/response boundary but does not
//! embed an HTTP client. Callers may provide an explicitly authorized transport;
//! `NetworkPolicy::NoNetwork` guarantees that transport is never invoked.

use crate::dependency::{AdvisoryMatch, Ecosystem, PackageVersion};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_OSV_REQUEST_BYTES: usize = 8 * 1024;
pub const MAX_OSV_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OSV_CACHE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OSV_CACHE_ENTRIES: usize = 10_000;
pub const MAX_OSV_ADVISORIES_PER_PACKAGE: usize = 10_000;
pub const MAX_OSV_PAGES: usize = 16;
const MAX_OSV_ID_BYTES: usize = 512;
const MAX_OSV_SUMMARY_BYTES: usize = 4 * 1024;
const MAX_OSV_PAGE_TOKEN_BYTES: usize = 4 * 1024;
const MAX_OSV_PACKAGE_FIELD_BYTES: usize = 512;
const CACHE_ENTRY_OVERHEAD_BYTES: usize = 128;
const CACHE_ADVISORY_OVERHEAD_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicy {
    NoNetwork,
    AllowNetwork,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsvLookupStatus {
    FreshCache,
    Network,
    StaleCache,
    SkippedByPolicy,
    NetworkUnavailable,
}

impl OsvLookupStatus {
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::FreshCache | Self::Network)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OsvLookupOutcome {
    pub matches: Vec<AdvisoryMatch>,
    pub status: OsvLookupStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OsvTransportError {
    Unavailable,
    TimedOut,
    Rejected,
}

pub trait OsvTransport {
    fn query(&mut self, request: &[u8]) -> Result<Vec<u8>, OsvTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedAdvisory {
    id: String,
    summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CacheEntry {
    fetched_at_epoch_seconds: u64,
    advisories: Vec<CachedAdvisory>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OsvCache {
    entries: BTreeMap<PackageVersion, CacheEntry>,
    estimated_bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
pub enum OsvError {
    InputTooLarge { bytes: usize, max: usize },
    ResourceLimitExceeded { bytes: usize, max: usize },
    InvalidPackageField(&'static str),
    InvalidResponse(&'static str),
    InvalidCache(&'static str),
    TooManyAdvisories { count: usize, max: usize },
    TooManyCacheEntries { count: usize, max: usize },
    TooManyPages { max: usize },
    RepeatedPageToken,
}

impl fmt::Display for OsvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { bytes, max } => {
                write!(formatter, "OSV input size {bytes} exceeds cap {max}")
            }
            Self::ResourceLimitExceeded { bytes, max } => {
                write!(formatter, "OSV resource estimate {bytes} exceeds cap {max}")
            }
            Self::InvalidPackageField(field) => {
                write!(formatter, "invalid OSV package field: {field}")
            }
            Self::InvalidResponse(message) => write!(formatter, "invalid OSV response: {message}"),
            Self::InvalidCache(message) => write!(formatter, "invalid OSV cache: {message}"),
            Self::TooManyAdvisories { count, max } => {
                write!(formatter, "OSV advisory count {count} exceeds cap {max}")
            }
            Self::TooManyCacheEntries { count, max } => {
                write!(formatter, "OSV cache entry count {count} exceeds cap {max}")
            }
            Self::TooManyPages { max } => {
                write!(formatter, "OSV pagination exceeds page cap {max}")
            }
            Self::RepeatedPageToken => formatter.write_str("OSV pagination repeated a page token"),
        }
    }
}

impl std::error::Error for OsvError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedPage {
    advisories: Vec<CachedAdvisory>,
    next_page_token: Option<String>,
}

pub fn lookup_package<T: OsvTransport>(
    package: &PackageVersion,
    network_policy: NetworkPolicy,
    now_epoch_seconds: u64,
    max_cache_age_seconds: u64,
    cache: &mut OsvCache,
    transport: &mut T,
) -> Result<OsvLookupOutcome, OsvError> {
    validate_package(package)?;
    let cached = cache.entries.get(package).cloned();
    if let Some(entry) = &cached
        && cache_entry_is_fresh(entry, now_epoch_seconds, max_cache_age_seconds)
    {
        return Ok(outcome_from_entry(
            package,
            entry,
            OsvLookupStatus::FreshCache,
        ));
    }

    if network_policy == NetworkPolicy::NoNetwork {
        return Ok(match cached {
            Some(entry) => outcome_from_entry(package, &entry, OsvLookupStatus::StaleCache),
            None => OsvLookupOutcome {
                matches: Vec::new(),
                status: OsvLookupStatus::SkippedByPolicy,
            },
        });
    }

    match query_network(package, transport) {
        Ok(advisories) => {
            cache.insert(package.clone(), now_epoch_seconds, advisories.clone())?;
            Ok(outcome_from_advisories(
                package,
                &advisories,
                OsvLookupStatus::Network,
            ))
        }
        Err(QueryNetworkError::Transport) => Ok(match cached {
            Some(entry) => outcome_from_entry(package, &entry, OsvLookupStatus::StaleCache),
            None => OsvLookupOutcome {
                matches: Vec::new(),
                status: OsvLookupStatus::NetworkUnavailable,
            },
        }),
        Err(QueryNetworkError::Protocol(error)) => Err(error),
    }
}

fn cache_entry_is_fresh(entry: &CacheEntry, now: u64, max_age: u64) -> bool {
    now.checked_sub(entry.fetched_at_epoch_seconds)
        .is_some_and(|age| age <= max_age)
}

fn outcome_from_entry(
    package: &PackageVersion,
    entry: &CacheEntry,
    status: OsvLookupStatus,
) -> OsvLookupOutcome {
    outcome_from_advisories(package, &entry.advisories, status)
}

fn outcome_from_advisories(
    package: &PackageVersion,
    advisories: &[CachedAdvisory],
    status: OsvLookupStatus,
) -> OsvLookupOutcome {
    OsvLookupOutcome {
        matches: advisories
            .iter()
            .map(|advisory| AdvisoryMatch {
                advisory_id: advisory.id.clone(),
                package: package.clone(),
                summary: advisory.summary.clone(),
            })
            .collect(),
        status,
    }
}

#[derive(Debug)]
enum QueryNetworkError {
    Transport,
    Protocol(OsvError),
}

fn query_network<T: OsvTransport>(
    package: &PackageVersion,
    transport: &mut T,
) -> Result<Vec<CachedAdvisory>, QueryNetworkError> {
    let mut page_token: Option<String> = None;
    let mut seen_tokens = BTreeSet::new();
    let mut advisories = BTreeMap::<String, String>::new();
    let mut advisory_bytes = 0usize;

    for _ in 0..MAX_OSV_PAGES {
        let request = build_query_request(package, page_token.as_deref())
            .map_err(QueryNetworkError::Protocol)?;
        let response = transport
            .query(&request)
            .map_err(|_| QueryNetworkError::Transport)?;
        let page = parse_query_response(&response).map_err(QueryNetworkError::Protocol)?;

        for advisory in page.advisories {
            match advisories.entry(advisory.id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    let additional = estimated_advisory_bytes(slot.key(), &advisory.summary);
                    advisory_bytes = bounded_resource_total(
                        advisory_bytes,
                        0,
                        additional,
                        MAX_OSV_CACHE_BYTES,
                    )
                    .map_err(QueryNetworkError::Protocol)?;
                    slot.insert(advisory.summary);
                }
                std::collections::btree_map::Entry::Occupied(_) => {}
            }
            if advisories.len() > MAX_OSV_ADVISORIES_PER_PACKAGE {
                return Err(QueryNetworkError::Protocol(OsvError::TooManyAdvisories {
                    count: advisories.len(),
                    max: MAX_OSV_ADVISORIES_PER_PACKAGE,
                }));
            }
        }

        let Some(next_token) = page.next_page_token else {
            return Ok(advisories
                .into_iter()
                .map(|(id, summary)| CachedAdvisory { id, summary })
                .collect());
        };
        if !seen_tokens.insert(next_token.clone()) {
            return Err(QueryNetworkError::Protocol(OsvError::RepeatedPageToken));
        }
        page_token = Some(next_token);
    }

    Err(QueryNetworkError::Protocol(OsvError::TooManyPages {
        max: MAX_OSV_PAGES,
    }))
}

pub fn build_query_request(
    package: &PackageVersion,
    page_token: Option<&str>,
) -> Result<Vec<u8>, OsvError> {
    validate_package(package)?;
    if let Some(token) = page_token {
        validate_page_token(token)?;
    }

    let ecosystem = match package.ecosystem {
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Npm => "npm",
    };
    let mut root = Map::new();
    root.insert(
        "package".to_owned(),
        json!({"ecosystem": ecosystem, "name": package.name.as_str()}),
    );
    if let Some(token) = page_token {
        root.insert("page_token".to_owned(), Value::String(token.to_owned()));
    }
    root.insert("version".to_owned(), Value::String(package.version.clone()));
    let bytes = serde_json::to_vec(&Value::Object(root))
        .map_err(|_| OsvError::InvalidResponse("cannot serialize query"))?;
    if bytes.len() > MAX_OSV_REQUEST_BYTES {
        return Err(OsvError::InputTooLarge {
            bytes: bytes.len(),
            max: MAX_OSV_REQUEST_BYTES,
        });
    }
    Ok(bytes)
}

fn parse_query_response(bytes: &[u8]) -> Result<ParsedPage, OsvError> {
    if bytes.len() > MAX_OSV_RESPONSE_BYTES {
        return Err(OsvError::InputTooLarge {
            bytes: bytes.len(),
            max: MAX_OSV_RESPONSE_BYTES,
        });
    }
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|_| OsvError::InvalidResponse("response is not valid JSON"))?;
    let object = root
        .as_object()
        .ok_or(OsvError::InvalidResponse("response root must be an object"))?;

    let raw_vulns: &[Value] = match object.get("vulns") {
        Some(value) => value
            .as_array()
            .ok_or(OsvError::InvalidResponse("vulns must be an array"))?
            .as_slice(),
        None => &[],
    };
    if raw_vulns.len() > MAX_OSV_ADVISORIES_PER_PACKAGE {
        return Err(OsvError::TooManyAdvisories {
            count: raw_vulns.len(),
            max: MAX_OSV_ADVISORIES_PER_PACKAGE,
        });
    }

    let mut advisories = Vec::with_capacity(raw_vulns.len());
    for vuln in raw_vulns {
        let vuln = vuln
            .as_object()
            .ok_or(OsvError::InvalidResponse("vulnerability must be an object"))?;
        let id = vuln
            .get("id")
            .and_then(Value::as_str)
            .ok_or(OsvError::InvalidResponse("vulnerability missing id"))?;
        validate_id(id)?;
        let summary = vuln.get("summary").and_then(Value::as_str).unwrap_or("");
        validate_summary(summary)?;
        advisories.push(CachedAdvisory {
            id: id.to_owned(),
            summary: summary.to_owned(),
        });
    }

    let next_page_token = object
        .get("next_page_token")
        .map(|value| {
            value
                .as_str()
                .ok_or(OsvError::InvalidResponse(
                    "next_page_token must be a string",
                ))
                .and_then(|token| {
                    validate_page_token(token)?;
                    Ok(token.to_owned())
                })
        })
        .transpose()?;

    Ok(ParsedPage {
        advisories,
        next_page_token,
    })
}

impl OsvCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OsvError> {
        if bytes.len() > MAX_OSV_CACHE_BYTES {
            return Err(OsvError::InputTooLarge {
                bytes: bytes.len(),
                max: MAX_OSV_CACHE_BYTES,
            });
        }
        let root: Value = serde_json::from_slice(bytes)
            .map_err(|_| OsvError::InvalidCache("cache is not valid JSON"))?;
        let object = root
            .as_object()
            .ok_or(OsvError::InvalidCache("cache root must be an object"))?;
        require_exact_keys(object, &["entries", "schema_version"])?;
        if object.get("schema_version").and_then(Value::as_str) != Some("1") {
            return Err(OsvError::InvalidCache("unsupported cache schema"));
        }
        let raw_entries = object
            .get("entries")
            .and_then(Value::as_array)
            .ok_or(OsvError::InvalidCache("cache entries must be an array"))?;
        if raw_entries.len() > MAX_OSV_CACHE_ENTRIES {
            return Err(OsvError::TooManyCacheEntries {
                count: raw_entries.len(),
                max: MAX_OSV_CACHE_ENTRIES,
            });
        }

        let mut cache = Self::new();
        for raw_entry in raw_entries {
            let entry = raw_entry
                .as_object()
                .ok_or(OsvError::InvalidCache("cache entry must be an object"))?;
            require_exact_keys(
                entry,
                &[
                    "advisories",
                    "ecosystem",
                    "fetched_at_epoch_seconds",
                    "name",
                    "version",
                ],
            )?;
            let ecosystem = match required_cache_string(entry, "ecosystem")? {
                "cargo" => Ecosystem::Cargo,
                "npm" => Ecosystem::Npm,
                _ => return Err(OsvError::InvalidCache("unsupported ecosystem")),
            };
            let package = PackageVersion {
                ecosystem,
                name: required_cache_string(entry, "name")?.to_owned(),
                version: required_cache_string(entry, "version")?.to_owned(),
            };
            validate_package(&package)?;
            if cache.entries.contains_key(&package) {
                return Err(OsvError::InvalidCache("duplicate package entry"));
            }
            let fetched_at_epoch_seconds = entry
                .get("fetched_at_epoch_seconds")
                .and_then(Value::as_u64)
                .ok_or(OsvError::InvalidCache("invalid fetched_at_epoch_seconds"))?;
            let raw_advisories = entry
                .get("advisories")
                .and_then(Value::as_array)
                .ok_or(OsvError::InvalidCache("advisories must be an array"))?;
            if raw_advisories.len() > MAX_OSV_ADVISORIES_PER_PACKAGE {
                return Err(OsvError::TooManyAdvisories {
                    count: raw_advisories.len(),
                    max: MAX_OSV_ADVISORIES_PER_PACKAGE,
                });
            }
            let mut advisories = Vec::with_capacity(raw_advisories.len());
            let mut ids = BTreeSet::new();
            for raw_advisory in raw_advisories {
                let advisory = raw_advisory
                    .as_object()
                    .ok_or(OsvError::InvalidCache("advisory must be an object"))?;
                require_exact_keys(advisory, &["id", "summary"])?;
                let id = required_cache_string(advisory, "id")?;
                validate_id(id)?;
                if !ids.insert(id.to_owned()) {
                    return Err(OsvError::InvalidCache("duplicate advisory id"));
                }
                let summary = required_cache_string(advisory, "summary")?;
                validate_summary(summary)?;
                advisories.push(CachedAdvisory {
                    id: id.to_owned(),
                    summary: summary.to_owned(),
                });
            }
            advisories.sort_by(|left, right| left.id.cmp(&right.id));
            cache.insert(package, fetched_at_epoch_seconds, advisories)?;
        }
        Ok(cache)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, OsvError> {
        let entries: Vec<Value> = self
            .entries
            .iter()
            .map(|(package, entry)| {
                let advisories: Vec<Value> = entry
                    .advisories
                    .iter()
                    .map(|advisory| {
                        json!({
                            "id": advisory.id.as_str(),
                            "summary": advisory.summary.as_str()
                        })
                    })
                    .collect();
                json!({
                    "ecosystem": package.ecosystem.as_str(),
                    "name": package.name.as_str(),
                    "version": package.version.as_str(),
                    "fetched_at_epoch_seconds": entry.fetched_at_epoch_seconds,
                    "advisories": advisories,
                })
            })
            .collect();
        let bytes = serde_json::to_vec(&json!({"schema_version": "1", "entries": entries}))
            .map_err(|_| OsvError::InvalidCache("cannot serialize cache"))?;
        if bytes.len() > MAX_OSV_CACHE_BYTES {
            return Err(OsvError::InputTooLarge {
                bytes: bytes.len(),
                max: MAX_OSV_CACHE_BYTES,
            });
        }
        Ok(bytes)
    }

    fn insert(
        &mut self,
        package: PackageVersion,
        fetched_at_epoch_seconds: u64,
        mut advisories: Vec<CachedAdvisory>,
    ) -> Result<(), OsvError> {
        if advisories.len() > MAX_OSV_ADVISORIES_PER_PACKAGE {
            return Err(OsvError::TooManyAdvisories {
                count: advisories.len(),
                max: MAX_OSV_ADVISORIES_PER_PACKAGE,
            });
        }
        if !self.entries.contains_key(&package) && self.entries.len() >= MAX_OSV_CACHE_ENTRIES {
            return Err(OsvError::TooManyCacheEntries {
                count: self.entries.len() + 1,
                max: MAX_OSV_CACHE_ENTRIES,
            });
        }

        let previous_estimate = self
            .entries
            .get(&package)
            .map(|entry| estimated_cache_entry_bytes(&package, &entry.advisories))
            .unwrap_or(0);
        let proposed_estimate = estimated_cache_entry_bytes(&package, &advisories);
        let next_estimated_bytes = bounded_resource_total(
            self.estimated_bytes,
            previous_estimate,
            proposed_estimate,
            MAX_OSV_CACHE_BYTES,
        )?;

        advisories.sort_by(|left, right| left.id.cmp(&right.id));
        self.entries.insert(
            package,
            CacheEntry {
                fetched_at_epoch_seconds,
                advisories,
            },
        );
        self.estimated_bytes = next_estimated_bytes;
        Ok(())
    }
}

fn estimated_cache_entry_bytes(
    package: &PackageVersion,
    advisories: &[CachedAdvisory],
) -> usize {
    advisories.iter().fold(
        CACHE_ENTRY_OVERHEAD_BYTES
            .saturating_add(package.name.len())
            .saturating_add(package.version.len()),
        |total, advisory| {
            total.saturating_add(estimated_advisory_bytes(&advisory.id, &advisory.summary))
        },
    )
}

fn estimated_advisory_bytes(id: &str, summary: &str) -> usize {
    CACHE_ADVISORY_OVERHEAD_BYTES
        .saturating_add(id.len())
        .saturating_add(summary.len())
}

fn bounded_resource_total(
    current: usize,
    removed: usize,
    added: usize,
    max: usize,
) -> Result<usize, OsvError> {
    let bytes = current.saturating_sub(removed).saturating_add(added);
    if bytes > max {
        return Err(OsvError::ResourceLimitExceeded { bytes, max });
    }
    Ok(bytes)
}

fn required_cache_string<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, OsvError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(OsvError::InvalidCache("required string field missing"))
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<(), OsvError> {
    if object.len() != expected.len() || !expected.iter().all(|key| object.contains_key(*key)) {
        return Err(OsvError::InvalidCache("unexpected cache fields"));
    }
    Ok(())
}

fn validate_package(package: &PackageVersion) -> Result<(), OsvError> {
    validate_package_field(&package.name, "name")?;
    validate_package_field(&package.version, "version")
}

fn validate_package_field(value: &str, field: &'static str) -> Result<(), OsvError> {
    if value.trim().is_empty()
        || value.len() > MAX_OSV_PACKAGE_FIELD_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OsvError::InvalidPackageField(field));
    }
    Ok(())
}

fn validate_id(id: &str) -> Result<(), OsvError> {
    if id.trim().is_empty() || id.len() > MAX_OSV_ID_BYTES || id.chars().any(char::is_control) {
        return Err(OsvError::InvalidResponse("invalid vulnerability id"));
    }
    Ok(())
}

fn validate_summary(summary: &str) -> Result<(), OsvError> {
    if summary.len() > MAX_OSV_SUMMARY_BYTES || summary.chars().any(char::is_control) {
        return Err(OsvError::InvalidResponse("invalid vulnerability summary"));
    }
    Ok(())
}

fn validate_page_token(token: &str) -> Result<(), OsvError> {
    if token.is_empty()
        || token.len() > MAX_OSV_PAGE_TOKEN_BYTES
        || token.chars().any(char::is_control)
    {
        return Err(OsvError::InvalidResponse("invalid page token"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{OsvError, bounded_resource_total};

    #[test]
    fn resource_budget_is_transactional_and_overflow_safe() {
        assert_eq!(bounded_resource_total(80, 10, 30, 100), Ok(100));
        assert_eq!(
            bounded_resource_total(80, 0, 30, 100),
            Err(OsvError::ResourceLimitExceeded {
                bytes: 110,
                max: 100,
            })
        );
        assert_eq!(
            bounded_resource_total(usize::MAX, 0, 1, usize::MAX - 1),
            Err(OsvError::ResourceLimitExceeded {
                bytes: usize::MAX,
                max: usize::MAX - 1,
            })
        );
    }
}
