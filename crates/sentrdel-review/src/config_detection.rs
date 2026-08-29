//! Bounded CI and MCP configuration detection from repository paths only.
//!
//! Configuration presence is inventory, not authority or security posture. This
//! module never reads configuration values, secret values, opens MCP connections,
//! executes repository tooling, or performs network calls.

use std::collections::BTreeSet;

use crate::project_detection::{DetectionLimits, ProjectDetectionError};
use crate::view::NormalizedRepoPath;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CiMcpConfigDetection {
    pub ci_systems: Vec<String>,
    pub mcp_configurations: Vec<String>,
}

pub fn detect_ci_mcp_configurations<I, S>(
    paths: I,
    limits: DetectionLimits,
) -> Result<CiMcpConfigDetection, ProjectDetectionError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    if limits.max_paths == 0 || limits.max_path_bytes == 0 {
        return Err(ProjectDetectionError::InvalidLimits);
    }

    let mut ci_systems = BTreeSet::new();
    let mut mcp_configurations = BTreeSet::new();

    for (index, path) in paths.into_iter().enumerate() {
        if index >= limits.max_paths {
            return Err(ProjectDetectionError::TooManyPaths {
                max: limits.max_paths,
            });
        }
        let normalized = NormalizedRepoPath::parse(path.as_ref(), limits.max_path_bytes)
            .map_err(|source| ProjectDetectionError::InvalidPath { index, source })?;
        classify_ci_path(&normalized, &mut ci_systems);
        classify_mcp_path(&normalized, &mut mcp_configurations);
    }

    Ok(CiMcpConfigDetection {
        ci_systems: ci_systems.into_iter().map(str::to_owned).collect(),
        mcp_configurations: mcp_configurations.into_iter().map(str::to_owned).collect(),
    })
}

fn classify_ci_path(path: &NormalizedRepoPath, systems: &mut BTreeSet<&'static str>) {
    let value = path.as_str();
    let basename = value.rsplit('/').next().unwrap_or(value);

    if value.starts_with(".github/workflows/")
        && matches!(
            value.rsplit_once('.').map(|(_, extension)| extension),
            Some("yml" | "yaml")
        )
    {
        systems.insert("github-actions");
    }

    match basename {
        ".gitlab-ci.yml" | ".gitlab-ci.yaml" => {
            systems.insert("gitlab-ci");
        }
        "azure-pipelines.yml" | "azure-pipelines.yaml" => {
            systems.insert("azure-pipelines");
        }
        "Jenkinsfile" => {
            systems.insert("jenkins");
        }
        "CircleCI.yml" | "CircleCI.yaml" if value.starts_with(".circleci/") => {
            systems.insert("circleci");
        }
        "config.yml" | "config.yaml" if value.starts_with(".circleci/") => {
            systems.insert("circleci");
        }
        _ => {}
    }
}

fn classify_mcp_path(path: &NormalizedRepoPath, configurations: &mut BTreeSet<&'static str>) {
    let value = path.as_str();
    let basename = value.rsplit('/').next().unwrap_or(value);

    match value {
        ".mcp.json" | "mcp.json" => {
            configurations.insert("mcp-json");
        }
        ".cursor/mcp.json" => {
            configurations.insert("cursor-mcp");
        }
        ".vscode/mcp.json" => {
            configurations.insert("vscode-mcp");
        }
        _ if basename == "mcp.json" && value.starts_with(".claude/") => {
            configurations.insert("claude-mcp");
        }
        _ => {}
    }
}
