#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sentrdel_cli::init::build_init_output;
use sentrdel_policy::Verdict;
use sentrdel_policy::narrowing::{RepositoryNarrowingError, validate_repository_narrowing};
use sentrdel_review::TARGET_BUILD_EXECUTION_ALLOWED;
use sentrdel_review::config_detection::CiMcpConfigDetection;
use sentrdel_review::pack_registry::SecurityPackRegistry;
use sentrdel_review::profile::build_project_profile_snapshot;
use sentrdel_review::project_detection::{DetectionLimits, LanguageEcosystemDetection};
use sentrdel_review::stack_detection::StackDetectorRegistry;
use sentrdel_review::supabase_detection::detect_supabase;
use sentrdel_review::view::{RepoFileView, RepoViewError, RepoViewLimits};
use sentrdel_schema::coverage::CoverageState;

struct TempRepo {
    root: PathBuf,
}

impl TempRepo {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sentrdel-t066-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create adversarial fixture root");
        Self { root }
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_target_build_execution_disabled() {
    assert!(!std::hint::black_box(TARGET_BUILD_EXECUTION_ALLOWED));
}

fn empty_stacks() -> sentrdel_review::stack_detection::StackDetectionResult {
    StackDetectorRegistry::new(&[])
        .expect("empty stack registry")
        .detect(std::iter::empty::<&str>(), DetectionLimits::default())
        .expect("empty stack detection")
}

fn init_for_paths(paths: &[&str]) -> sentrdel_cli::init::InitOutput {
    let supabase = detect_supabase(paths.iter().copied(), DetectionLimits::default())
        .expect("bounded supabase detection");
    let snapshot = build_project_profile_snapshot(
        "repo:adversarial-fixture",
        "sha256:t066-root",
        &LanguageEcosystemDetection {
            languages: vec!["rust".to_owned()],
            package_ecosystems: vec!["cargo".to_owned()],
        },
        &CiMcpConfigDetection {
            ci_systems: Vec::new(),
            mcp_configurations: Vec::new(),
        },
        &empty_stacks(),
        &supabase,
        &SecurityPackRegistry::new(),
        "2026-08-29T00:00:00Z",
        "2026-08-29T00:00:00Z",
    )
    .expect("project profile snapshot");
    build_init_output(&snapshot, ".", 0).expect("init output")
}

#[test]
fn oversized_repository_input_fails_closed_before_init_can_treat_it_as_inventory() {
    let repo = TempRepo::new("oversized");
    fs::write(repo.root.join("Cargo.toml"), vec![b'x'; 33]).expect("write oversized fixture");
    let view = RepoFileView::new(
        &repo.root,
        RepoViewLimits {
            max_path_bytes: 128,
            max_file_bytes: 32,
        },
    )
    .expect("bounded repository view");

    assert!(matches!(
        view.read("Cargo.toml"),
        Err(RepoViewError::FileTooLarge {
            bytes: 33,
            max: 32,
            ..
        })
    ));
    assert_target_build_execution_disabled();
}

#[cfg(unix)]
#[test]
fn symlinked_project_metadata_is_rejected_instead_of_followed() {
    use std::os::unix::fs::symlink;

    let repo = TempRepo::new("symlink");
    let outside = TempRepo::new("outside");
    fs::write(
        outside.root.join("Cargo.toml"),
        b"[package]\nname = 'attacker-controlled'\n",
    )
    .expect("write outside metadata");
    symlink(
        outside.root.join("Cargo.toml"),
        repo.root.join("Cargo.toml"),
    )
    .expect("create metadata symlink");

    let view = RepoFileView::new(&repo.root, RepoViewLimits::default()).expect("repo view");
    assert!(matches!(
        view.read("Cargo.toml"),
        Err(RepoViewError::SymlinkEncountered(_))
    ));
    assert_target_build_execution_disabled();
}

#[test]
fn repository_weakening_candidate_cannot_override_trusted_policy_floor() {
    let repo = TempRepo::new("weakening");
    fs::create_dir_all(repo.root.join(".sentrdel")).expect("create config directory");
    fs::write(
        repo.root.join(".sentrdel/config.toml"),
        b"evidence_logging = false\npolicy = 'allow'\nexecute_target_build = true\n",
    )
    .expect("write weakening fixture");

    let view = RepoFileView::new(&repo.root, RepoViewLimits::default()).expect("repo view");
    let bytes = view
        .read(".sentrdel/config.toml")
        .expect("repository config remains bounded data");
    assert!(
        bytes
            .windows(b"execute_target_build = true".len())
            .any(|window| { window == b"execute_target_build = true" })
    );

    assert_eq!(
        validate_repository_narrowing(Verdict::Deny, Verdict::Allow, true),
        Err(RepositoryNarrowingError::PermissionWidening {
            base: Verdict::Deny,
            repository: Verdict::Allow,
        })
    );
    assert_eq!(
        validate_repository_narrowing(Verdict::Allow, Verdict::Deny, false),
        Err(RepositoryNarrowingError::EvidenceLoggingDisabled)
    );
    assert_target_build_execution_disabled();
}

#[test]
fn hostile_cargo_config_is_read_only_data_and_cannot_activate_runner_or_wrapper() {
    let repo = TempRepo::new("hostile-cargo");
    fs::create_dir_all(repo.root.join(".cargo")).expect("create cargo config directory");
    let hostile = br#"[build]
rustc-wrapper = "./attacker-controlled-wrapper"
[target.'cfg(all())']
runner = "./attacker-controlled-runner"
[source.crates-io]
replace-with = "attacker"
[source.attacker]
registry = "https://attacker.invalid/index"
"#;
    fs::write(repo.root.join(".cargo/config.toml"), hostile).expect("write hostile cargo config");

    let view = RepoFileView::new(&repo.root, RepoViewLimits::default()).expect("repo view");
    assert_eq!(
        view.read(".cargo/config.toml")
            .expect("read hostile config as bytes"),
        hostile
    );
    assert_target_build_execution_disabled();

    let output = init_for_paths(&[".cargo/config.toml", "Cargo.toml"]);
    assert!(output.envelope.findings.is_empty());
    assert!(output.human.contains("Package ecosystems: cargo"));
    assert!(!output.human.contains("attacker-controlled-runner"));
    assert!(!output.human.contains("attacker-controlled-wrapper"));
    assert!(!output.human.contains("attacker.invalid"));
}

#[test]
fn supabase_detection_without_registered_r2_pack_reports_unsupported_without_verdict() {
    let output = init_for_paths(&[
        "supabase/config.toml",
        "supabase/migrations/20260829_init.sql",
    ]);

    assert!(output.envelope.findings.is_empty());
    let supabase_static = output
        .envelope
        .coverage
        .iter()
        .find(|record| record.capability == "provider.supabase.STATIC_POSTURE")
        .expect("supabase static coverage record");
    assert_eq!(supabase_static.state, CoverageState::Unsupported);
    assert_eq!(
        supabase_static.reason_code.as_deref(),
        Some("R1_POSTURE_NOT_IMPLEMENTED")
    );
    assert!(output.human.contains(
        "provider supabase / STATIC_POSTURE: Unsupported (R1_POSTURE_NOT_IMPLEMENTED)"
    ));
    for unsupported_claim in [
        "Supabase is secure",
        "Supabase is safe",
        "Supabase is vulnerable",
    ] {
        assert!(!output.human.contains(unsupported_claim));
    }
}
