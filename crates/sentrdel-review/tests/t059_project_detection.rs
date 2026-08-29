use sentrdel_review::project_detection::{
    DetectionLimits, ProjectDetectionError, detect_language_ecosystems,
};

#[test]
fn detects_languages_and_ecosystems_from_paths_without_execution() {
    let detected = detect_language_ecosystems(
        [
            "Cargo.toml",
            "src/lib.rs",
            "web/package.json",
            "web/src/app.tsx",
            "scripts/check.py",
            "requirements-dev.txt",
            "cmd/server/main.go",
            "go.mod",
        ],
        DetectionLimits::default(),
    )
    .expect("bounded detection");

    assert_eq!(
        detected.languages,
        vec!["go", "python", "rust", "typescript"]
    );
    assert_eq!(
        detected.package_ecosystems,
        vec!["cargo", "go-modules", "npm", "pip"]
    );
}

#[test]
fn javascript_and_typescript_are_distinct_and_manifest_does_not_invent_language() {
    let detected = detect_language_ecosystems(
        [
            "frontend/package.json",
            "frontend/index.js",
            "frontend/types.d.ts",
        ],
        DetectionLimits::default(),
    )
    .expect("bounded detection");

    assert_eq!(detected.languages, vec!["javascript", "typescript"]);
    assert_eq!(detected.package_ecosystems, vec!["npm"]);
}

#[test]
fn unknown_files_do_not_create_posture_or_ecosystem_claims() {
    let detected = detect_language_ecosystems(
        ["README.md", "docs/security.txt", "assets/logo.svg"],
        DetectionLimits::default(),
    )
    .expect("bounded detection");

    assert!(detected.languages.is_empty());
    assert!(detected.package_ecosystems.is_empty());
}

#[test]
fn input_order_and_duplicate_paths_do_not_change_output() {
    let first = detect_language_ecosystems(
        [
            "src/main.rs",
            "Cargo.toml",
            "src/main.rs",
            "package-lock.json",
        ],
        DetectionLimits::default(),
    )
    .expect("bounded detection");
    let second = detect_language_ecosystems(
        ["package-lock.json", "Cargo.toml", "src/main.rs"],
        DetectionLimits::default(),
    )
    .expect("bounded detection");

    assert_eq!(first, second);
}

#[test]
fn invalid_paths_and_resource_caps_fail_closed() {
    assert!(matches!(
        detect_language_ecosystems(["src/main.rs", "../escape.py"], DetectionLimits::default()),
        Err(ProjectDetectionError::InvalidPath { index: 1, .. })
    ));

    assert!(matches!(
        detect_language_ecosystems(
            ["a.rs", "b.rs"],
            DetectionLimits {
                max_paths: 1,
                max_path_bytes: 128,
            }
        ),
        Err(ProjectDetectionError::TooManyPaths { max: 1 })
    ));

    assert!(matches!(
        detect_language_ecosystems(
            ["a.rs"],
            DetectionLimits {
                max_paths: 0,
                max_path_bytes: 128,
            }
        ),
        Err(ProjectDetectionError::InvalidLimits)
    ));
}
