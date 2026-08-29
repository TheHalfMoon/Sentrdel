//! Bounded language and package-ecosystem detection from repository paths only.
//!
//! Detection is descriptive inventory, not security posture. This module never
//! executes package managers, build tools, hooks, interpreters, or network calls.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::view::{NormalizedRepoPath, RepoViewError};

pub const DEFAULT_MAX_DETECTION_PATHS: usize = 50_000;
pub const DEFAULT_MAX_DETECTION_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectionLimits {
    pub max_paths: usize,
    pub max_path_bytes: usize,
}

impl Default for DetectionLimits {
    fn default() -> Self {
        Self {
            max_paths: DEFAULT_MAX_DETECTION_PATHS,
            max_path_bytes: DEFAULT_MAX_DETECTION_PATH_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LanguageEcosystemDetection {
    pub languages: Vec<String>,
    pub package_ecosystems: Vec<String>,
}

#[derive(Debug)]
pub enum ProjectDetectionError {
    InvalidLimits,
    TooManyPaths { max: usize },
    InvalidPath { index: usize, source: RepoViewError },
}

impl fmt::Display for ProjectDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("project detection limits must be non-zero"),
            Self::TooManyPaths { max } => {
                write!(formatter, "repository path count exceeds detection cap {max}")
            }
            Self::InvalidPath { index, source } => {
                write!(formatter, "repository path at index {index} is invalid: {source}")
            }
        }
    }
}

impl Error for ProjectDetectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn detect_language_ecosystems<I, S>(
    paths: I,
    limits: DetectionLimits,
) -> Result<LanguageEcosystemDetection, ProjectDetectionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if limits.max_paths == 0 || limits.max_path_bytes == 0 {
        return Err(ProjectDetectionError::InvalidLimits);
    }

    let mut languages = BTreeSet::new();
    let mut ecosystems = BTreeSet::new();

    for (index, path) in paths.into_iter().enumerate() {
        if index >= limits.max_paths {
            return Err(ProjectDetectionError::TooManyPaths {
                max: limits.max_paths,
            });
        }
        let normalized = NormalizedRepoPath::parse(path.as_ref(), limits.max_path_bytes)
            .map_err(|source| ProjectDetectionError::InvalidPath { index, source })?;
        classify_path(&normalized, &mut languages, &mut ecosystems);
    }

    Ok(LanguageEcosystemDetection {
        languages: languages.into_iter().map(str::to_owned).collect(),
        package_ecosystems: ecosystems.into_iter().map(str::to_owned).collect(),
    })
}

fn classify_path(
    path: &NormalizedRepoPath,
    languages: &mut BTreeSet<&'static str>,
    ecosystems: &mut BTreeSet<&'static str>,
) {
    let value = path.as_str();
    let basename = value.rsplit('/').next().unwrap_or(value);

    match basename {
        "Cargo.toml" | "Cargo.lock" => {
            languages.insert("rust");
            ecosystems.insert("cargo");
        }
        "package.json" | "package-lock.json" | "npm-shrinkwrap.json" | "yarn.lock"
        | "pnpm-lock.yaml" => {
            ecosystems.insert("npm");
        }
        "pyproject.toml" | "Pipfile" | "Pipfile.lock" | "poetry.lock" | "uv.lock" => {
            languages.insert("python");
            ecosystems.insert("pip");
        }
        "go.mod" | "go.sum" => {
            languages.insert("go");
            ecosystems.insert("go-modules");
        }
        _ if basename.starts_with("requirements") && basename.ends_with(".txt") => {
            languages.insert("python");
            ecosystems.insert("pip");
        }
        _ => {}
    }

    let extension = basename.rsplit_once('.').map(|(_, extension)| extension);
    match extension {
        Some("rs") => {
            languages.insert("rust");
        }
        Some("js" | "jsx" | "mjs" | "cjs") => {
            languages.insert("javascript");
        }
        Some("ts" | "tsx" | "mts" | "cts") => {
            languages.insert("typescript");
        }
        Some("py" | "pyi") => {
            languages.insert("python");
        }
        Some("go") => {
            languages.insert("go");
        }
        _ => {}
    }
}
