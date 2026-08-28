//! Read-only Git discovery and diff snapshots for untrusted target repositories.
//!
//! This module deliberately does not execute Git, hooks, filters, textconv,
//! credential helpers, submodule commands, package managers, or network remotes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

const BINARY_PREFIX_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiffMode {
    WorkingTree,
    Staged,
    Base { revision: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    Added,
    Modified,
    Deleted,
    Renamed,
    TypeChanged,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepoPath(Vec<u8>);

impl RepoPath {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitChange {
    pub path: RepoPath,
    pub previous_path: Option<RepoPath>,
    pub kind: ChangeKind,
    pub old_oid: Option<String>,
    pub new_oid: Option<String>,
    pub binary: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitDiff {
    pub root: PathBuf,
    pub mode: DiffMode,
    pub changes: Vec<GitChange>,
}

#[derive(Debug)]
pub enum GitReadError {
    RepositoryNotFound(PathBuf),
    BareRepository(PathBuf),
    Open(String),
    Head(String),
    Index(String),
    ConflictedIndex(RepoPath),
    InvalidRepositoryPath(RepoPath),
    Object(String),
    Revision {
        revision: String,
        source: String,
    },
    Filesystem {
        path: RepoPath,
        source: std::io::Error,
    },
}

impl fmt::Display for GitReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RepositoryNotFound(path) => {
                write!(f, "no Git repository found from {}", path.display())
            }
            Self::BareRepository(path) => {
                write!(f, "repository at {} has no working tree", path.display())
            }
            Self::Open(source) => write!(f, "cannot open repository safely: {source}"),
            Self::Head(source) => write!(f, "cannot read local HEAD: {source}"),
            Self::Index(source) => write!(f, "cannot read local index: {source}"),
            Self::ConflictedIndex(path) => write!(f, "index contains unresolved stages at {path}"),
            Self::InvalidRepositoryPath(path) => write!(
                f,
                "repository path cannot be represented safely on this platform: {path}"
            ),
            Self::Object(source) => write!(f, "cannot read required local Git object: {source}"),
            Self::Revision { revision, source } => {
                write!(f, "cannot resolve local revision {revision:?}: {source}")
            }
            Self::Filesystem { path, source } => {
                write!(f, "cannot read tracked path {path}: {source}")
            }
        }
    }
}

impl std::error::Error for GitReadError {}

#[derive(Clone)]
struct SnapshotEntry {
    oid: gix::ObjectId,
    mode: String,
    binary: bool,
}

type Snapshot = BTreeMap<RepoPath, SnapshotEntry>;

pub fn read_diff(start: impl AsRef<Path>, mode: DiffMode) -> Result<GitDiff, GitReadError> {
    let root = discover_root(start.as_ref())?;
    let repo = gix::open_opts(&root, gix::open::Options::isolated().strict_config(true))
        .map_err(|error| GitReadError::Open(error.to_string()))?;

    let workdir = repo
        .workdir()
        .ok_or_else(|| GitReadError::BareRepository(root.clone()))?;

    let changes = match &mode {
        DiffMode::Staged => {
            let before = head_snapshot(&repo)?;
            let after = index_snapshot(&repo)?;
            compare_snapshots(&before, &after)
        }
        DiffMode::Base { revision } => {
            let before = revision_snapshot(&repo, revision)?;
            let after = head_snapshot(&repo)?;
            compare_snapshots(&before, &after)
        }
        DiffMode::WorkingTree => working_tree_changes(&repo, workdir)?,
    };

    Ok(GitDiff {
        root,
        mode,
        changes,
    })
}

fn discover_root(start: &Path) -> Result<PathBuf, GitReadError> {
    let mut current = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(GitReadError::RepositoryNotFound(start.to_path_buf()));
        }
    }
}

fn head_snapshot(repo: &gix::Repository) -> Result<Snapshot, GitReadError> {
    let tree = repo
        .head_tree()
        .map_err(|error| GitReadError::Head(error.to_string()))?;
    tree_snapshot(repo, &tree)
}

fn revision_snapshot(repo: &gix::Repository, revision: &str) -> Result<Snapshot, GitReadError> {
    let id = repo
        .rev_parse_single(revision)
        .map_err(|error| GitReadError::Revision {
            revision: revision.to_owned(),
            source: error.to_string(),
        })?;
    let object = id.object().map_err(|error| GitReadError::Revision {
        revision: revision.to_owned(),
        source: error.to_string(),
    })?;
    let tree = object
        .peel_to_tree()
        .map_err(|error| GitReadError::Revision {
            revision: revision.to_owned(),
            source: error.to_string(),
        })?;
    tree_snapshot(repo, &tree)
}

fn tree_snapshot(repo: &gix::Repository, tree: &gix::Tree<'_>) -> Result<Snapshot, GitReadError> {
    let mut out = BTreeMap::new();
    visit_tree(repo, tree, &[], &mut out)?;
    Ok(out)
}

fn visit_tree(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    prefix: &[u8],
    out: &mut Snapshot,
) -> Result<(), GitReadError> {
    for entry in tree.iter() {
        let entry = entry.map_err(|error| GitReadError::Object(error.to_string()))?;
        let mut path = Vec::with_capacity(
            prefix.len() + entry.filename().len() + usize::from(!prefix.is_empty()),
        );
        if !prefix.is_empty() {
            path.extend_from_slice(prefix);
            path.push(b'/');
        }
        path.extend_from_slice(entry.filename());

        if entry.mode().is_tree() {
            let subtree = repo
                .find_tree(entry.object_id())
                .map_err(|error| GitReadError::Object(error.to_string()))?;
            visit_tree(repo, &subtree, &path, out)?;
            continue;
        }

        let oid = entry.object_id();
        out.insert(
            RepoPath::from_bytes(path),
            SnapshotEntry {
                oid,
                mode: format!("{:o}", entry.mode()),
                binary: object_is_binary(repo, oid)?,
            },
        );
    }
    Ok(())
}

fn index_snapshot(repo: &gix::Repository) -> Result<Snapshot, GitReadError> {
    let index = repo
        .open_index()
        .map_err(|error| GitReadError::Index(error.to_string()))?;
    let mut out = BTreeMap::new();

    for entry in index.entries() {
        let path = RepoPath::from_bytes(entry.path_in(index.path_backing()).to_vec());
        if entry.stage_raw() != 0 {
            return Err(GitReadError::ConflictedIndex(path));
        }
        let oid = entry.id;
        out.insert(
            path,
            SnapshotEntry {
                oid,
                mode: format!("{:o}", entry.mode),
                binary: object_is_binary(repo, oid)?,
            },
        );
    }

    Ok(out)
}

fn object_is_binary(repo: &gix::Repository, oid: gix::ObjectId) -> Result<bool, GitReadError> {
    let object = repo
        .find_object(oid)
        .map_err(|error| GitReadError::Object(error.to_string()))?;
    if !object.kind.is_blob() {
        return Ok(false);
    }
    Ok(has_nul_prefix(&object.data))
}

fn has_nul_prefix(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .take(BINARY_PREFIX_BYTES)
        .any(|byte| *byte == 0)
}

fn working_tree_changes(
    repo: &gix::Repository,
    workdir: &Path,
) -> Result<Vec<GitChange>, GitReadError> {
    let index = index_snapshot(repo)?;
    let mut changes = Vec::new();

    for (path, staged) in index {
        let native = gix::path::try_from_byte_slice(path.as_bytes())
            .map_err(|_| GitReadError::InvalidRepositoryPath(path.clone()))?;
        let native_path: &Path = native;
        let absolute = workdir.join(native_path);
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                changes.push(GitChange {
                    path,
                    previous_path: None,
                    kind: ChangeKind::Deleted,
                    old_oid: Some(staged.oid.to_string()),
                    new_oid: None,
                    binary: staged.binary,
                });
                continue;
            }
            Err(error) => {
                return Err(GitReadError::Filesystem {
                    path,
                    source: error,
                });
            }
        };

        if metadata.file_type().is_symlink() || !metadata.is_file() {
            changes.push(GitChange {
                path,
                previous_path: None,
                kind: ChangeKind::TypeChanged,
                old_oid: Some(staged.oid.to_string()),
                new_oid: None,
                binary: staged.binary,
            });
            continue;
        }

        let bytes = fs::read(&absolute).map_err(|source| GitReadError::Filesystem {
            path: path.clone(),
            source,
        })?;
        let blob = repo
            .find_blob(staged.oid)
            .map_err(|error| GitReadError::Object(error.to_string()))?;
        let mode = filesystem_mode(&metadata);
        let kind = if mode != staged.mode {
            Some(ChangeKind::TypeChanged)
        } else if bytes != blob.data {
            Some(ChangeKind::Modified)
        } else {
            None
        };

        if let Some(kind) = kind {
            changes.push(GitChange {
                path,
                previous_path: None,
                kind,
                old_oid: Some(staged.oid.to_string()),
                new_oid: None,
                binary: has_nul_prefix(&bytes) || staged.binary,
            });
        }
    }

    changes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(changes)
}

fn filesystem_mode(metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 != 0 {
            return "100755".to_owned();
        }
    }
    "100644".to_owned()
}

fn compare_snapshots(before: &Snapshot, after: &Snapshot) -> Vec<GitChange> {
    let all_paths: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    let mut added = Vec::new();
    let mut deleted = Vec::new();
    let mut stable = Vec::new();

    for path in all_paths {
        match (before.get(&path), after.get(&path)) {
            (None, Some(new)) => added.push((path, new)),
            (Some(old), None) => deleted.push((path, old)),
            (Some(old), Some(new)) if old.oid != new.oid || old.mode != new.mode => {
                stable.push(GitChange {
                    path,
                    previous_path: None,
                    kind: if old.mode == new.mode {
                        ChangeKind::Modified
                    } else {
                        ChangeKind::TypeChanged
                    },
                    old_oid: Some(old.oid.to_string()),
                    new_oid: Some(new.oid.to_string()),
                    binary: old.binary || new.binary,
                });
            }
            _ => {}
        }
    }

    let mut consumed_adds = BTreeSet::new();
    let mut consumed_deletes = BTreeSet::new();
    let mut renamed = Vec::new();

    for (delete_index, (old_path, old)) in deleted.iter().enumerate() {
        if let Some((add_index, (new_path, new))) =
            added.iter().enumerate().find(|(index, (_, candidate))| {
                !consumed_adds.contains(index)
                    && candidate.oid == old.oid
                    && candidate.mode == old.mode
            })
        {
            consumed_adds.insert(add_index);
            consumed_deletes.insert(delete_index);
            renamed.push(GitChange {
                path: new_path.clone(),
                previous_path: Some(old_path.clone()),
                kind: ChangeKind::Renamed,
                old_oid: Some(old.oid.to_string()),
                new_oid: Some(new.oid.to_string()),
                binary: old.binary || new.binary,
            });
        }
    }

    for (index, (path, old)) in deleted.into_iter().enumerate() {
        if !consumed_deletes.contains(&index) {
            stable.push(GitChange {
                path,
                previous_path: None,
                kind: ChangeKind::Deleted,
                old_oid: Some(old.oid.to_string()),
                new_oid: None,
                binary: old.binary,
            });
        }
    }
    for (index, (path, new)) in added.into_iter().enumerate() {
        if !consumed_adds.contains(&index) {
            stable.push(GitChange {
                path,
                previous_path: None,
                kind: ChangeKind::Added,
                old_oid: None,
                new_oid: Some(new.oid.to_string()),
                binary: new.binary,
            });
        }
    }

    stable.extend(renamed);
    stable.sort_by(|left, right| left.path.cmp(&right.path));
    stable
}
