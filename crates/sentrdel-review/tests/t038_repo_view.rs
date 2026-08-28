use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sentrdel_review::view::{NormalizedRepoPath, RepoFileView, RepoViewError, RepoViewLimits};

struct TempRepo {
    root: PathBuf,
}

impl TempRepo {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sentrdel-t038-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("temporary repository must be created");
        Self { root }
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn reads_only_bounded_regular_repository_files() {
    let repo = TempRepo::new("regular");
    fs::create_dir_all(repo.root.join("src")).unwrap();
    fs::write(repo.root.join("src/lib.rs"), b"fn safe() {}\n").unwrap();

    let view = RepoFileView::new(&repo.root, RepoViewLimits::default()).unwrap();
    assert_eq!(view.read("src/lib.rs").unwrap(), b"fn safe() {}\n");
}

#[test]
fn path_normalization_rejects_traversal_noncanonical_and_confusable_forms() {
    let max = 128;
    assert!(matches!(
        NormalizedRepoPath::parse("../secret", max),
        Err(RepoViewError::ParentTraversal)
    ));
    assert!(matches!(
        NormalizedRepoPath::parse("src\\lib.rs", max),
        Err(RepoViewError::NonCanonicalSeparator)
    ));
    assert!(matches!(
        NormalizedRepoPath::parse("src//lib.rs", max),
        Err(RepoViewError::NonCanonicalPath | RepoViewError::EmptyComponent)
    ));
    assert!(matches!(
        NormalizedRepoPath::parse("src/\u{ff0e}\u{ff0e}/secret", max),
        Err(RepoViewError::ConfusableOrControlCharacter)
    ));
    assert!(matches!(
        NormalizedRepoPath::parse("src\u{2215}lib.rs", max),
        Err(RepoViewError::ConfusableOrControlCharacter)
    ));
    assert!(matches!(
        NormalizedRepoPath::parse("src/ab\u{202e}cd.rs", max),
        Err(RepoViewError::ConfusableOrControlCharacter)
    ));
}

#[test]
fn oversized_paths_and_files_fail_closed() {
    let repo = TempRepo::new("oversized");
    fs::write(repo.root.join("large.bin"), vec![b'x'; 17]).unwrap();
    let limits = RepoViewLimits {
        max_path_bytes: 8,
        max_file_bytes: 16,
    };
    let view = RepoFileView::new(&repo.root, limits).unwrap();

    assert!(matches!(
        view.normalize("123456789"),
        Err(RepoViewError::PathTooLarge { bytes: 9, max: 8 })
    ));
    assert!(matches!(
        view.read("large.bin"),
        Err(RepoViewError::FileTooLarge {
            bytes: 17,
            max: 16,
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn symlink_file_and_directory_components_are_rejected() {
    use std::os::unix::fs::symlink;

    let repo = TempRepo::new("symlink");
    let outside = TempRepo::new("outside");
    fs::write(outside.root.join("secret.txt"), b"do not read").unwrap();
    fs::create_dir_all(repo.root.join("real")).unwrap();
    fs::write(repo.root.join("real/safe.txt"), b"safe").unwrap();

    symlink(
        outside.root.join("secret.txt"),
        repo.root.join("linked.txt"),
    )
    .unwrap();
    symlink(&outside.root, repo.root.join("linked-dir")).unwrap();

    let view = RepoFileView::new(&repo.root, RepoViewLimits::default()).unwrap();
    assert!(matches!(
        view.read("linked.txt"),
        Err(RepoViewError::SymlinkEncountered(_))
    ));
    assert!(matches!(
        view.read("linked-dir/secret.txt"),
        Err(RepoViewError::SymlinkEncountered(_))
    ));
    assert_eq!(view.read("real/safe.txt").unwrap(), b"safe");
}

#[cfg(unix)]
#[test]
fn symlink_repository_root_is_rejected() {
    use std::os::unix::fs::symlink;

    let repo = TempRepo::new("root-target");
    let holder = TempRepo::new("root-holder");
    let linked_root = holder.root.join("linked-root");
    symlink(&repo.root, &linked_root).unwrap();

    assert!(RepoFileView::new(&linked_root, RepoViewLimits::default()).is_err());
}
