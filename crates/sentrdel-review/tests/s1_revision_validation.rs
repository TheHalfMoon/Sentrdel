use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sentrdel_review::regression::model::{RegressionLimits, RevisionRole};
use sentrdel_review::regression::revision::{
    LocalRevisionInput, RevisionValidationError, validate_local_revision_pair,
};

struct FixtureRepo {
    root: PathBuf,
}

impl FixtureRepo {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sentrdel-s1-t007-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("fixture directory must be created");

        let repo = Self { root };
        repo.git(&["init", "-b", "main"]);
        repo.git(&["config", "user.name", "Sentrdel S1 T007 Fixture"]);
        repo.git(&["config", "user.email", "s1-t007@example.invalid"]);
        repo
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.root)
            .output()
            .expect("Git fixture setup must start");
        assert!(
            output.status.success(),
            "Git fixture setup failed for {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("Git fixture output must be UTF-8")
    }

    fn commit_all(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-m", message]);
    }

    fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"]).trim().to_owned()
    }

    fn tree(&self, commit_id: &str) -> String {
        let treeish = format!("{commit_id}^{{tree}}");
        self.git(&["rev-parse", &treeish]).trim().to_owned()
    }

    fn two_commits(&self) -> (String, String, String, String) {
        fs::write(self.root.join("tracked.txt"), "base\n").unwrap();
        self.commit_all("base");
        let base = self.head();
        let base_tree = self.tree(&base);

        fs::write(self.root.join("tracked.txt"), "candidate\n").unwrap();
        self.commit_all("candidate");
        let candidate = self.head();
        let candidate_tree = self.tree(&candidate);
        (base, base_tree, candidate, candidate_tree)
    }
}

impl Drop for FixtureRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn input(commit: &str, tree: &str, digest: &str) -> LocalRevisionInput {
    LocalRevisionInput::new(commit, Some(tree), digest)
}

#[test]
fn exact_local_pair_binds_commit_tree_roles_and_order_deterministically() {
    let repo = FixtureRepo::new("exact-pair");
    let (base, base_tree, candidate, candidate_tree) = repo.two_commits();
    let limits = RegressionLimits::default();

    let first = validate_local_revision_pair(
        &repo.root,
        input(&base, &base_tree, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        limits,
    )
    .expect("exact local pair must validate");
    let replay = validate_local_revision_pair(
        &repo.root,
        input(&base, &base_tree, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        limits,
    )
    .expect("same exact local pair must replay");

    assert_eq!(first.pair_id(), replay.pair_id());
    assert_eq!(first.trusted_base().role(), RevisionRole::TrustedBase);
    assert_eq!(first.candidate().role(), RevisionRole::Candidate);
    assert_eq!(first.trusted_base().commit_id(), base);
    assert_eq!(first.trusted_base().root_tree_id(), base_tree);
    assert_eq!(first.candidate().commit_id(), candidate);
    assert_eq!(first.candidate().root_tree_id(), candidate_tree);
    assert!(!first.trusted_base().is_fixture_only());
    assert!(!first.candidate().is_fixture_only());

    let reversed = validate_local_revision_pair(
        &repo.root,
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        input(&base, &base_tree, "snapshot:base"),
        limits,
    )
    .expect("reversed exact pair is valid but distinct");
    assert_ne!(first.pair_id(), reversed.pair_id());
}

#[test]
fn mutable_refs_abbreviations_and_malformed_ids_are_rejected_before_resolution() {
    let repo = FixtureRepo::new("bad-id");
    let (base, base_tree, candidate, candidate_tree) = repo.two_commits();
    let limits = RegressionLimits::default();

    for invalid in [
        "HEAD",
        &base[..12],
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        let result = validate_local_revision_pair(
            &repo.root,
            LocalRevisionInput::new(invalid, Some(base_tree.as_str()), "snapshot:base"),
            input(&candidate, &candidate_tree, "snapshot:candidate"),
            limits,
        );
        assert!(matches!(
            result,
            Err(RevisionValidationError::InvalidExactObjectId {
                field: "exact_commit_id"
            })
        ));
    }
}

#[test]
fn aggregate_pair_input_cap_applies_across_both_revisions_before_repository_resolution() {
    let repo = FixtureRepo::new("aggregate-pair-cap");
    let (base, base_tree, candidate, candidate_tree) = repo.two_commits();
    let limits = RegressionLimits {
        max_total_input_bytes: 100,
        ..RegressionLimits::default()
    };

    assert!(base.len() + base_tree.len() + "snapshot:base".len() <= limits.max_total_input_bytes);
    assert!(
        candidate.len() + candidate_tree.len() + "snapshot:candidate".len()
            <= limits.max_total_input_bytes
    );

    let result = validate_local_revision_pair(
        PathBuf::from("sentrdel-s1-t007-no-repository"),
        input(&base, &base_tree, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        limits,
    );
    assert!(matches!(
        result,
        Err(RevisionValidationError::TotalInputBytesExceeded { max: 100 })
    ));
}

#[test]
fn expected_root_tree_mismatch_fails_visible() {
    let repo = FixtureRepo::new("tree-mismatch");
    let (base, _base_tree, candidate, candidate_tree) = repo.two_commits();

    let result = validate_local_revision_pair(
        &repo.root,
        input(&base, &candidate_tree, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        RegressionLimits::default(),
    );
    assert!(matches!(
        result,
        Err(RevisionValidationError::RootTreeMismatch { .. })
    ));
}

#[test]
fn identical_base_and_candidate_commit_is_rejected_even_with_different_snapshot_digests() {
    let repo = FixtureRepo::new("same-commit");
    let (base, base_tree, _candidate, _candidate_tree) = repo.two_commits();

    let result = validate_local_revision_pair(
        &repo.root,
        input(&base, &base_tree, "snapshot:base"),
        input(&base, &base_tree, "snapshot:candidate"),
        RegressionLimits::default(),
    );
    assert!(matches!(
        result,
        Err(RevisionValidationError::SameRevisionIdentity)
    ));
}

#[test]
fn full_object_id_that_is_not_a_commit_is_rejected() {
    let repo = FixtureRepo::new("blob-not-commit");
    let (_base, _base_tree, candidate, candidate_tree) = repo.two_commits();
    fs::write(repo.root.join("blob.txt"), "blob-only\n").unwrap();
    let blob = repo.git(&["hash-object", "-w", "blob.txt"]);
    let blob = blob.trim();

    let result = validate_local_revision_pair(
        &repo.root,
        LocalRevisionInput::new(blob, None::<String>, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        RegressionLimits::default(),
    );
    assert!(matches!(
        result,
        Err(RevisionValidationError::CommitObject { .. })
    ));
}

#[test]
fn nested_start_path_discovers_only_the_local_repository() {
    let repo = FixtureRepo::new("nested-root");
    let (base, base_tree, candidate, candidate_tree) = repo.two_commits();
    let nested = repo.root.join("a/b/c");
    fs::create_dir_all(&nested).unwrap();

    let pair = validate_local_revision_pair(
        &nested,
        input(&base, &base_tree, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        RegressionLimits::default(),
    )
    .expect("nested path must resolve its containing local repository");
    assert_eq!(pair.trusted_base().commit_id(), base);
    assert_eq!(pair.candidate().commit_id(), candidate);
}

#[test]
fn hostile_git_config_and_remote_are_data_and_never_execute_helpers() {
    let repo = FixtureRepo::new("hostile-config");
    let (base, base_tree, candidate, candidate_tree) = repo.two_commits();
    let marker = repo.root.join("helper-executed");
    let helper = repo.root.join("hostile-helper.sh");
    fs::write(
        &helper,
        format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let helper_text = helper.to_string_lossy().into_owned();
    repo.git(&["config", "credential.helper", &helper_text]);
    repo.git(&["config", "diff.hostile.command", &helper_text]);
    repo.git(&["config", "filter.hostile.clean", &helper_text]);
    repo.git(&["config", "filter.hostile.smudge", &helper_text]);
    repo.git(&["config", "core.hooksPath", &helper_text]);
    repo.git(&[
        "remote",
        "add",
        "origin",
        "https://example.invalid/never-fetch.git",
    ]);

    let pair = validate_local_revision_pair(
        &repo.root,
        input(&base, &base_tree, "snapshot:base"),
        input(&candidate, &candidate_tree, "snapshot:candidate"),
        RegressionLimits::default(),
    )
    .expect("hostile config must remain inert during local object validation");

    assert_eq!(pair.trusted_base().commit_id(), base);
    assert_eq!(pair.candidate().commit_id(), candidate);
    assert!(!marker.exists(), "hostile helper must never execute");
}
