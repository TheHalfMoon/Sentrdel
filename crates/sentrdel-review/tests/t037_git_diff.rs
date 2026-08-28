use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sentrdel_review::git::{ChangeKind, DiffMode, read_diff};

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
            "sentrdel-t037-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("fixture directory must be created");

        let repo = Self { root };
        repo.git(&["init", "-b", "main"]);
        repo.git(&["config", "user.name", "Sentrdel T037 Fixture"]);
        repo.git(&["config", "user.email", "t037@example.invalid"]);
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
}

impl Drop for FixtureRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn find_change<'a>(
    changes: &'a [sentrdel_review::git::GitChange],
    path: &[u8],
) -> &'a sentrdel_review::git::GitChange {
    changes
        .iter()
        .find(|change| change.path.as_bytes() == path)
        .unwrap_or_else(|| panic!("missing change for {}", String::from_utf8_lossy(path)))
}

#[test]
fn hostile_git_config_is_data_and_never_executes_helpers() {
    let repo = FixtureRepo::new("hostile-config");
    fs::write(repo.root.join("tracked.txt"), "safe\n").unwrap();
    fs::write(
        repo.root.join(".gitattributes"),
        "tracked.txt diff=hostile filter=hostile\n",
    )
    .unwrap();
    repo.commit_all("initial");

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
    repo.git(&["config", "diff.hostile.command", &helper_text]);
    repo.git(&["config", "filter.hostile.clean", &helper_text]);
    repo.git(&["config", "filter.hostile.smudge", &helper_text]);
    repo.git(&["config", "credential.helper", &helper_text]);
    repo.git(&["config", "core.hooksPath", &helper_text]);

    fs::write(repo.root.join("tracked.txt"), "changed\n").unwrap();
    let diff = read_diff(&repo.root, DiffMode::WorkingTree).expect("safe read must succeed");

    let change = find_change(&diff.changes, b"tracked.txt");
    assert_eq!(change.kind, ChangeKind::Modified);
    assert!(!marker.exists(), "hostile helper must never execute");
}

#[test]
fn staged_diff_preserves_rename_delete_and_binary_semantics() {
    let repo = FixtureRepo::new("staged-semantics");
    fs::write(repo.root.join("old.txt"), "rename-me\n").unwrap();
    fs::write(repo.root.join("delete.txt"), "delete-me\n").unwrap();
    repo.commit_all("initial");

    fs::rename(repo.root.join("old.txt"), repo.root.join("new.txt")).unwrap();
    fs::remove_file(repo.root.join("delete.txt")).unwrap();
    fs::write(repo.root.join("binary.bin"), b"prefix\0payload").unwrap();
    repo.git(&["add", "-A"]);

    let diff = read_diff(&repo.root, DiffMode::Staged).expect("staged read must succeed");

    let renamed = find_change(&diff.changes, b"new.txt");
    assert_eq!(renamed.kind, ChangeKind::Renamed);
    assert_eq!(
        renamed.previous_path.as_ref().map(|path| path.as_bytes()),
        Some(b"old.txt".as_slice())
    );

    let deleted = find_change(&diff.changes, b"delete.txt");
    assert_eq!(deleted.kind, ChangeKind::Deleted);

    let binary = find_change(&diff.changes, b"binary.bin");
    assert_eq!(binary.kind, ChangeKind::Added);
    assert!(binary.binary);
}

#[test]
fn shallow_repository_reads_local_objects_without_fetching() {
    let repo = FixtureRepo::new("shallow");
    fs::write(repo.root.join("tracked.txt"), "one\n").unwrap();
    repo.commit_all("initial");

    let head = repo.git(&["rev-parse", "HEAD"]);
    fs::write(repo.root.join(".git/shallow"), head.trim().as_bytes()).unwrap();
    fs::write(repo.root.join("tracked.txt"), "two\n").unwrap();
    repo.git(&["add", "tracked.txt"]);

    let staged = read_diff(&repo.root, DiffMode::Staged).expect("shallow staged read must succeed");
    assert_eq!(
        find_change(&staged.changes, b"tracked.txt").kind,
        ChangeKind::Modified
    );

    let base = read_diff(
        &repo.root,
        DiffMode::Base {
            revision: "HEAD".to_owned(),
        },
    )
    .expect("local shallow base read must succeed");
    assert!(base.changes.is_empty());
}
