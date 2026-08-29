//! Generic provider/framework detection extension points.
//!
//! Detector specifications are Sentrdel-owned runtime data, not repository
//! configuration. Detection is path-only descriptive inventory: it grants no
//! pack, policy, Finding, credential, process, filesystem-write, or network
//! authority and performs no deep provider analysis.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::project_detection::DetectionLimits;
use crate::view::{NormalizedRepoPath, RepoViewError};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StackKind {
    Provider,
    Framework,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathMatchRule {
    Exact(&'static str),
    Prefix(&'static str),
    Basename(&'static str),
}

impl PathMatchRule {
    fn matches(self, path: &NormalizedRepoPath) -> bool {
        let value = path.as_str();
        match self {
            Self::Exact(expected) => value == expected,
            Self::Prefix(prefix) => value.starts_with(prefix),
            Self::Basename(expected) => value.rsplit('/').next() == Some(expected),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StackDetectorSpec {
    pub id: &'static str,
    pub kind: StackKind,
    pub any_path_rules: &'static [PathMatchRule],
}

impl StackDetectorSpec {
    pub const fn new(
        id: &'static str,
        kind: StackKind,
        any_path_rules: &'static [PathMatchRule],
    ) -> Self {
        Self {
            id,
            kind,
            any_path_rules,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedStack {
    pub id: String,
    pub kind: StackKind,
    pub matched_paths: Vec<NormalizedRepoPath>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StackDetectionResult {
    pub providers: Vec<DetectedStack>,
    pub frameworks: Vec<DetectedStack>,
}

impl StackDetectionResult {
    #[must_use]
    pub fn has_security_verdict(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum StackDetectorRegistryError {
    EmptyDetectorId,
    DuplicateDetectorId(String),
    EmptyRuleSet(String),
    EmptyRuleValue { detector_id: String },
    InvalidLimits,
    TooManyPaths { max: usize },
    InvalidPath { index: usize, source: RepoViewError },
}

impl fmt::Display for StackDetectorRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDetectorId => formatter.write_str("stack detector id must not be empty"),
            Self::DuplicateDetectorId(id) => write!(formatter, "duplicate stack detector id: {id}"),
            Self::EmptyRuleSet(id) => write!(
                formatter,
                "stack detector {id} must declare at least one path rule"
            ),
            Self::EmptyRuleValue { detector_id } => {
                write!(
                    formatter,
                    "stack detector {detector_id} contains an empty path rule"
                )
            }
            Self::InvalidLimits => formatter.write_str("stack detection limits must be non-zero"),
            Self::TooManyPaths { max } => write!(
                formatter,
                "repository path count exceeds stack detection cap {max}"
            ),
            Self::InvalidPath { index, source } => {
                write!(
                    formatter,
                    "repository path at index {index} is invalid: {source}"
                )
            }
        }
    }
}

impl Error for StackDetectorRegistryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub struct StackDetectorRegistry<'a> {
    specs: &'a [StackDetectorSpec],
}

impl<'a> StackDetectorRegistry<'a> {
    pub fn new(specs: &'a [StackDetectorSpec]) -> Result<Self, StackDetectorRegistryError> {
        let mut ids = BTreeSet::new();
        for spec in specs {
            if spec.id.trim().is_empty() {
                return Err(StackDetectorRegistryError::EmptyDetectorId);
            }
            if !ids.insert(spec.id) {
                return Err(StackDetectorRegistryError::DuplicateDetectorId(
                    spec.id.to_owned(),
                ));
            }
            if spec.any_path_rules.is_empty() {
                return Err(StackDetectorRegistryError::EmptyRuleSet(spec.id.to_owned()));
            }
            if spec
                .any_path_rules
                .iter()
                .any(|rule| rule_value(*rule).is_empty())
            {
                return Err(StackDetectorRegistryError::EmptyRuleValue {
                    detector_id: spec.id.to_owned(),
                });
            }
        }
        Ok(Self { specs })
    }

    pub fn detect<I, S>(
        &self,
        paths: I,
        limits: DetectionLimits,
    ) -> Result<StackDetectionResult, StackDetectorRegistryError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if limits.max_paths == 0 || limits.max_path_bytes == 0 {
            return Err(StackDetectorRegistryError::InvalidLimits);
        }

        let mut normalized = Vec::new();
        for (index, raw_path) in paths.into_iter().enumerate() {
            if index >= limits.max_paths {
                return Err(StackDetectorRegistryError::TooManyPaths {
                    max: limits.max_paths,
                });
            }
            normalized.push(
                NormalizedRepoPath::parse(raw_path.as_ref(), limits.max_path_bytes)
                    .map_err(|source| StackDetectorRegistryError::InvalidPath { index, source })?,
            );
        }

        let mut detected: BTreeMap<(StackKind, &str), BTreeSet<NormalizedRepoPath>> =
            BTreeMap::new();
        for spec in self.specs {
            for path in &normalized {
                if spec.any_path_rules.iter().any(|rule| rule.matches(path)) {
                    detected
                        .entry((spec.kind, spec.id))
                        .or_default()
                        .insert(path.clone());
                }
            }
        }

        let mut providers = Vec::new();
        let mut frameworks = Vec::new();
        for ((kind, id), paths) in detected {
            let value = DetectedStack {
                id: id.to_owned(),
                kind,
                matched_paths: paths.into_iter().collect(),
            };
            match kind {
                StackKind::Provider => providers.push(value),
                StackKind::Framework => frameworks.push(value),
            }
        }

        Ok(StackDetectionResult {
            providers,
            frameworks,
        })
    }
}

const fn rule_value(rule: PathMatchRule) -> &'static str {
    match rule {
        PathMatchRule::Exact(value)
        | PathMatchRule::Prefix(value)
        | PathMatchRule::Basename(value) => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREBASE_RULES: &[PathMatchRule] = &[PathMatchRule::Exact("firebase.json")];
    const NEXT_RULES: &[PathMatchRule] = &[
        PathMatchRule::Basename("next.config.js"),
        PathMatchRule::Basename("next.config.mjs"),
    ];
    const SPECS: &[StackDetectorSpec] = &[
        StackDetectorSpec::new("firebase", StackKind::Provider, FIREBASE_RULES),
        StackDetectorSpec::new("nextjs", StackKind::Framework, NEXT_RULES),
    ];

    #[test]
    fn generic_registry_detects_shallow_provider_and_framework_signals() {
        let registry = StackDetectorRegistry::new(SPECS).unwrap();
        let result = registry
            .detect(
                ["firebase.json", "apps/web/next.config.mjs", "src/main.ts"],
                DetectionLimits::default(),
            )
            .unwrap();

        assert_eq!(result.providers.len(), 1);
        assert_eq!(result.providers[0].id, "firebase");
        assert_eq!(result.frameworks.len(), 1);
        assert_eq!(result.frameworks[0].id, "nextjs");
        assert!(!result.has_security_verdict());
    }

    #[test]
    fn registry_rejects_duplicate_or_empty_specs() {
        const DUPLICATE: &[StackDetectorSpec] = &[
            StackDetectorSpec::new("fixture", StackKind::Provider, FIREBASE_RULES),
            StackDetectorSpec::new("fixture", StackKind::Framework, NEXT_RULES),
        ];
        assert!(matches!(
            StackDetectorRegistry::new(DUPLICATE),
            Err(StackDetectorRegistryError::DuplicateDetectorId(id)) if id == "fixture"
        ));

        const EMPTY_RULES: &[PathMatchRule] = &[];
        const EMPTY_SPEC: &[StackDetectorSpec] = &[StackDetectorSpec::new(
            "fixture",
            StackKind::Provider,
            EMPTY_RULES,
        )];
        assert!(matches!(
            StackDetectorRegistry::new(EMPTY_SPEC),
            Err(StackDetectorRegistryError::EmptyRuleSet(id)) if id == "fixture"
        ));
    }

    #[test]
    fn detection_is_deterministic_and_path_bounded() {
        let registry = StackDetectorRegistry::new(SPECS).unwrap();
        let first = registry
            .detect(
                ["apps/web/next.config.js", "firebase.json"],
                DetectionLimits::default(),
            )
            .unwrap();
        let second = registry
            .detect(
                ["firebase.json", "apps/web/next.config.js"],
                DetectionLimits::default(),
            )
            .unwrap();
        assert_eq!(first, second);

        assert!(matches!(
            registry.detect(
                ["../firebase.json"],
                DetectionLimits {
                    max_paths: 4,
                    max_path_bytes: 128,
                },
            ),
            Err(StackDetectorRegistryError::InvalidPath { index: 0, .. })
        ));
    }
}
