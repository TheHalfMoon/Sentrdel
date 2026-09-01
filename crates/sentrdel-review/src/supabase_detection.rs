//! Bounded Supabase presence detection and R2 static-posture handoff.
//!
//! This module recognizes only repository-relative Supabase project layout
//! signals. It does not parse configuration values, inspect credentials, run
//! Supabase tooling, connect to a project, or make any security-posture verdict.

use sentrdel_schema::coverage::CoverageState;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use crate::project_detection::DetectionLimits;
use crate::supabase::SUPABASE_R2_PACK_ID;
use crate::view::{NormalizedRepoPath, RepoViewError};

pub const SUPABASE_R2_ROADMAP: &str =
    "specs/000-sentrdel-roadmap/roadmap.md#roadmap (R2: Supabase P0 Static/Posture Pack)";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SupabaseSignalKind {
    Config,
    Migration,
    EdgeFunction,
    Seed,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SupabaseSignal {
    pub kind: SupabaseSignalKind,
    pub path: NormalizedRepoPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupabaseStaticPostureStatus {
    Available,
}

impl SupabaseStaticPostureStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "AVAILABLE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupabaseStaticPostureCoverage {
    pub status: SupabaseStaticPostureStatus,
    /// Detection can hand off to the native R2 pack, but producer Coverage is
    /// not fabricated here. Until orchestration actually runs, this remains
    /// UNAVAILABLE rather than being misreported as PARTIAL or COVERED.
    pub coverage_state: CoverageState,
    pub pack_id: &'static str,
    pub roadmap: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupabaseDetection {
    pub detected: bool,
    pub signals: Vec<SupabaseSignal>,
    /// Present only when Supabase is detected. This is the control-plane handoff
    /// to the compiled-in R2 pack, not security Evidence or a verdict.
    pub static_posture: Option<SupabaseStaticPostureCoverage>,
}

impl SupabaseDetection {
    #[must_use]
    pub fn has_security_verdict(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum SupabaseDetectionError {
    InvalidLimits,
    TooManyPaths { max: usize },
    InvalidPath { index: usize, source: RepoViewError },
}

impl fmt::Display for SupabaseDetectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                formatter.write_str("Supabase detection limits must be non-zero")
            }
            Self::TooManyPaths { max } => {
                write!(
                    formatter,
                    "repository path count exceeds Supabase detection cap {max}"
                )
            }
            Self::InvalidPath { index, source } => {
                write!(
                    formatter,
                    "repository path at index {index} is invalid: {source}"
                )
            }
        }
    }
}

impl Error for SupabaseDetectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPath { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub fn detect_supabase<I, S>(
    paths: I,
    limits: DetectionLimits,
) -> Result<SupabaseDetection, SupabaseDetectionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if limits.max_paths == 0 || limits.max_path_bytes == 0 {
        return Err(SupabaseDetectionError::InvalidLimits);
    }

    let mut signals = BTreeSet::new();
    for (index, raw_path) in paths.into_iter().enumerate() {
        if index >= limits.max_paths {
            return Err(SupabaseDetectionError::TooManyPaths {
                max: limits.max_paths,
            });
        }
        let path = NormalizedRepoPath::parse(raw_path.as_ref(), limits.max_path_bytes)
            .map_err(|source| SupabaseDetectionError::InvalidPath { index, source })?;
        if let Some(kind) = classify_supabase_path(&path) {
            signals.insert(SupabaseSignal { kind, path });
        }
    }

    let signals: Vec<_> = signals.into_iter().collect();
    let detected = !signals.is_empty();
    let static_posture = detected.then_some(SupabaseStaticPostureCoverage {
        status: SupabaseStaticPostureStatus::Available,
        coverage_state: CoverageState::Unavailable,
        pack_id: SUPABASE_R2_PACK_ID,
        roadmap: SUPABASE_R2_ROADMAP,
    });

    Ok(SupabaseDetection {
        detected,
        signals,
        static_posture,
    })
}

fn classify_supabase_path(path: &NormalizedRepoPath) -> Option<SupabaseSignalKind> {
    let value = path.as_str();
    if value == "supabase/config.toml" {
        return Some(SupabaseSignalKind::Config);
    }
    if value == "supabase/seed.sql" {
        return Some(SupabaseSignalKind::Seed);
    }
    if let Some(relative) = value.strip_prefix("supabase/migrations/")
        && !relative.is_empty()
        && !relative.contains('/')
        && relative.ends_with(".sql")
    {
        return Some(SupabaseSignalKind::Migration);
    }
    if let Some(relative) = value.strip_prefix("supabase/functions/") {
        let mut parts = relative.split('/');
        if matches!((parts.next(), parts.next()), (Some(name), Some(file)) if !name.is_empty() && !file.is_empty())
        {
            return Some(SupabaseSignalKind::EdgeFunction);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positive_layout_preserves_detection_and_hands_off_to_r2_without_verdict() {
        let detection = detect_supabase(
            [
                "supabase/config.toml",
                "supabase/migrations/20260829000000_init.sql",
                "supabase/functions/webhook/index.ts",
                "supabase/seed.sql",
            ],
            DetectionLimits::default(),
        )
        .unwrap();

        assert!(detection.detected);
        assert_eq!(detection.signals.len(), 4);
        assert!(!detection.has_security_verdict());
        let posture = detection.static_posture.unwrap();
        assert_eq!(posture.status.as_str(), "AVAILABLE");
        assert_eq!(posture.coverage_state, CoverageState::Unavailable);
        assert_eq!(posture.pack_id, SUPABASE_R2_PACK_ID);
        assert!(
            posture
                .roadmap
                .contains("R2: Supabase P0 Static/Posture Pack")
        );
    }

    #[test]
    fn misleading_names_outside_canonical_layout_do_not_detect_supabase() {
        let detection = detect_supabase(
            [
                "docs/supabase/config.toml",
                "supabase-config.toml",
                "src/supabase/config.toml",
                "supabase/migrations.txt",
                "supabase/functions.txt",
            ],
            DetectionLimits::default(),
        )
        .unwrap();

        assert!(!detection.detected);
        assert!(detection.signals.is_empty());
        assert!(detection.static_posture.is_none());
        assert!(!detection.has_security_verdict());
    }

    #[test]
    fn output_is_deterministic_and_bounded() {
        let first = detect_supabase(
            ["supabase/seed.sql", "supabase/config.toml"],
            DetectionLimits::default(),
        )
        .unwrap();
        let second = detect_supabase(
            ["supabase/config.toml", "supabase/seed.sql"],
            DetectionLimits::default(),
        )
        .unwrap();
        assert_eq!(first, second);

        assert!(matches!(
            detect_supabase(
                ["supabase/config.toml"],
                DetectionLimits {
                    max_paths: 0,
                    max_path_bytes: 1
                }
            ),
            Err(SupabaseDetectionError::InvalidLimits)
        ));
    }
}
