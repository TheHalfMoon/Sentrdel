use sentrdel_review::config_detection::detect_ci_mcp_configurations;
use sentrdel_review::project_detection::{DetectionLimits, ProjectDetectionError};

#[test]
fn detects_ci_and_mcp_configuration_presence_from_paths_only() {
    let detected = detect_ci_mcp_configurations(
        [
            ".github/workflows/ci.yml",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            "azure-pipelines.yaml",
            "Jenkinsfile",
            ".mcp.json",
            ".cursor/mcp.json",
            ".vscode/mcp.json",
            ".claude/mcp.json",
        ],
        DetectionLimits::default(),
    )
    .expect("bounded config detection");

    assert_eq!(
        detected.ci_systems,
        vec![
            "azure-pipelines",
            "circleci",
            "github-actions",
            "gitlab-ci",
            "jenkins",
        ]
    );
    assert_eq!(
        detected.mcp_configurations,
        vec!["claude-mcp", "cursor-mcp", "mcp-json", "vscode-mcp"]
    );
}

#[test]
fn similarly_named_files_outside_authorized_locations_do_not_match() {
    let detected = detect_ci_mcp_configurations(
        [
            "docs/workflows/ci.yml",
            "examples/.github-not/workflows/ci.yml",
            "config/mcp.json",
            "docs/cursor/mcp.json",
            "circleci/config.yml",
        ],
        DetectionLimits::default(),
    )
    .expect("bounded config detection");

    assert!(detected.ci_systems.is_empty());
    assert!(detected.mcp_configurations.is_empty());
}

#[test]
fn detection_is_deterministic_and_does_not_require_config_contents() {
    let first = detect_ci_mcp_configurations(
        [
            ".cursor/mcp.json",
            ".github/workflows/security.yaml",
            ".cursor/mcp.json",
        ],
        DetectionLimits::default(),
    )
    .expect("bounded config detection");
    let second = detect_ci_mcp_configurations(
        [".github/workflows/security.yaml", ".cursor/mcp.json"],
        DetectionLimits::default(),
    )
    .expect("bounded config detection");

    assert_eq!(first, second);
}

#[test]
fn invalid_paths_and_caps_fail_closed_before_detection() {
    assert!(matches!(
        detect_ci_mcp_configurations(
            [".github/workflows/ci.yml", "../outside/mcp.json"],
            DetectionLimits::default(),
        ),
        Err(ProjectDetectionError::InvalidPath { index: 1, .. })
    ));

    assert!(matches!(
        detect_ci_mcp_configurations(
            [".mcp.json", ".cursor/mcp.json"],
            DetectionLimits {
                max_paths: 1,
                max_path_bytes: 128,
            },
        ),
        Err(ProjectDetectionError::TooManyPaths { max: 1 })
    ));
}
