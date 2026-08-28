//! Bounded, non-executing repository file access for untrusted target trees.
//!
//! Target paths and bytes are data. This module never invokes package managers,
//! build tools, hooks, interpreters, repository helpers, or network services.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

pub const DEFAULT_MAX_REPO_PATH_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepoViewLimits {
    pub max_path_bytes: usize,
    pub max_file_bytes: u64,
}

impl Default for RepoViewLimits {
    fn default() -> Self {
        Self {
            max_path_bytes: DEFAULT_MAX_REPO_PATH_BYTES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NormalizedRepoPath(String);

impl NormalizedRepoPath {
    pub fn parse(value: &str, max_bytes: usize) -> Result<Self, RepoViewError> {
        if value.is_empty() {
            return Err(RepoViewError::EmptyPath);
        }
        if value.len() > max_bytes {
            return Err(RepoViewError::PathTooLarge {
                bytes: value.len(),
                max: max_bytes,
            });
        }
        if value.trim() != value {
            return Err(RepoViewError::PaddedPath);
        }
        if value.starts_with('/') || value.starts_with('\\') || has_drive_prefix(value) {
            return Err(RepoViewError::AbsolutePath);
        }
        if value.contains('\\') {
            return Err(RepoViewError::NonCanonicalSeparator);
        }
        if value.chars().any(is_forbidden_path_character) {
            return Err(RepoViewError::ConfusableOrControlCharacter);
        }

        let path = Path::new(value);
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::Normal(part) => {
                    let text = part.to_str().ok_or(RepoViewError::NonUtf8Path)?;
                    if text.is_empty() {
                        return Err(RepoViewError::EmptyComponent);
                    }
                    components.push(text);
                }
                Component::CurDir => return Err(RepoViewError::CurrentDirectoryComponent),
                Component::ParentDir => return Err(RepoViewError::ParentTraversal),
                Component::RootDir | Component::Prefix(_) => {
                    return Err(RepoViewError::AbsolutePath);
                }
            }
        }
        if components.is_empty() {
            return Err(RepoViewError::EmptyPath);
        }

        let normalized = components.join("/");
        if normalized != value {
            return Err(RepoViewError::NonCanonicalPath);
        }
        Ok(Self(normalized))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for NormalizedRepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug)]
pub enum RepoViewError {
    EmptyPath,
    PathTooLarge {
        bytes: usize,
        max: usize,
    },
    PaddedPath,
    AbsolutePath,
    NonCanonicalSeparator,
    ConfusableOrControlCharacter,
    NonUtf8Path,
    EmptyComponent,
    CurrentDirectoryComponent,
    ParentTraversal,
    NonCanonicalPath,
    InvalidRoot(PathBuf),
    SymlinkEncountered(NormalizedRepoPath),
    NotRegularFile(NormalizedRepoPath),
    FileTooLarge {
        path: NormalizedRepoPath,
        bytes: u64,
        max: u64,
    },
    FileChangedWhileReading {
        path: NormalizedRepoPath,
        max: u64,
    },
    Filesystem {
        path: NormalizedRepoPath,
        source: io::Error,
    },
}

impl fmt::Display for RepoViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => formatter.write_str("repository path is empty"),
            Self::PathTooLarge { bytes, max } => {
                write!(
                    formatter,
                    "repository path length {bytes} exceeds cap {max}"
                )
            }
            Self::PaddedPath => formatter.write_str("repository path must not be padded"),
            Self::AbsolutePath => formatter.write_str("repository path must be relative"),
            Self::NonCanonicalSeparator => {
                formatter.write_str("repository path must use canonical '/' separators")
            }
            Self::ConfusableOrControlCharacter => formatter.write_str(
                "repository path contains a control, bidi, or separator/dot confusable character",
            ),
            Self::NonUtf8Path => formatter.write_str("repository path must be valid UTF-8"),
            Self::EmptyComponent => {
                formatter.write_str("repository path contains an empty component")
            }
            Self::CurrentDirectoryComponent => {
                formatter.write_str("repository path may not contain '.' components")
            }
            Self::ParentTraversal => {
                formatter.write_str("repository path may not contain '..' traversal")
            }
            Self::NonCanonicalPath => {
                formatter.write_str("repository path is not in canonical repository-relative form")
            }
            Self::InvalidRoot(root) => {
                write!(
                    formatter,
                    "repository root is not a readable non-symlink directory: {}",
                    root.display()
                )
            }
            Self::SymlinkEncountered(path) => {
                write!(formatter, "repository path crosses a symlink at {path}")
            }
            Self::NotRegularFile(path) => {
                write!(formatter, "repository path is not a file: {path}")
            }
            Self::FileTooLarge { path, bytes, max } => {
                write!(
                    formatter,
                    "repository file {path} size {bytes} exceeds cap {max}"
                )
            }
            Self::FileChangedWhileReading { path, max } => write!(
                formatter,
                "repository file {path} exceeded cap {max} while being read"
            ),
            Self::Filesystem { path, source } => {
                write!(formatter, "cannot read repository path {path}: {source}")
            }
        }
    }
}

impl std::error::Error for RepoViewError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Filesystem { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub struct RepoFileView {
    root: PathBuf,
    limits: RepoViewLimits,
}

impl RepoFileView {
    pub fn new(root: impl AsRef<Path>, limits: RepoViewLimits) -> Result<Self, RepoViewError> {
        let root = root.as_ref().to_path_buf();
        let metadata =
            fs::symlink_metadata(&root).map_err(|_| RepoViewError::InvalidRoot(root.clone()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RepoViewError::InvalidRoot(root));
        }
        Ok(Self { root, limits })
    }

    pub fn normalize(&self, path: &str) -> Result<NormalizedRepoPath, RepoViewError> {
        NormalizedRepoPath::parse(path, self.limits.max_path_bytes)
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>, RepoViewError> {
        let normalized = self.normalize(path)?;
        self.read_normalized(&normalized)
    }

    pub fn read_normalized(&self, path: &NormalizedRepoPath) -> Result<Vec<u8>, RepoViewError> {
        self.reject_symlink_components(path)?;
        let absolute = self.root.join(path.as_path());
        let metadata =
            fs::symlink_metadata(&absolute).map_err(|source| RepoViewError::Filesystem {
                path: path.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            return Err(RepoViewError::SymlinkEncountered(path.clone()));
        }
        if !metadata.is_file() {
            return Err(RepoViewError::NotRegularFile(path.clone()));
        }
        if metadata.len() > self.limits.max_file_bytes {
            return Err(RepoViewError::FileTooLarge {
                path: path.clone(),
                bytes: metadata.len(),
                max: self.limits.max_file_bytes,
            });
        }

        let file = File::open(&absolute).map_err(|source| RepoViewError::Filesystem {
            path: path.clone(),
            source,
        })?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len().min(self.limits.max_file_bytes)).unwrap_or(0),
        );
        file.take(self.limits.max_file_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|source| RepoViewError::Filesystem {
                path: path.clone(),
                source,
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > self.limits.max_file_bytes {
            return Err(RepoViewError::FileChangedWhileReading {
                path: path.clone(),
                max: self.limits.max_file_bytes,
            });
        }
        Ok(bytes)
    }

    fn reject_symlink_components(&self, path: &NormalizedRepoPath) -> Result<(), RepoViewError> {
        let mut current = self.root.clone();
        let component_count = path.as_path().components().count();
        for (index, component) in path.as_path().components().enumerate() {
            let Component::Normal(part) = component else {
                return Err(RepoViewError::NonCanonicalPath);
            };
            current.push(part);
            if index + 1 == component_count {
                break;
            }
            let metadata =
                fs::symlink_metadata(&current).map_err(|source| RepoViewError::Filesystem {
                    path: path.clone(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                return Err(RepoViewError::SymlinkEncountered(path.clone()));
            }
            if !metadata.is_dir() {
                return Err(RepoViewError::NotRegularFile(path.clone()));
            }
        }
        Ok(())
    }
}

fn has_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_forbidden_path_character(value: char) -> bool {
    value == '\0'
        || value.is_control()
        || matches!(
            value,
            '\u{202a}'
                ..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{2044}'
                    | '\u{2215}'
                    | '\u{29f8}'
                    | '\u{ff0f}'
                    | '\u{ff3c}'
                    | '\u{2024}'
                    | '\u{fe52}'
                    | '\u{ff0e}'
        )
}
