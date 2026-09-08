//! Bounded local Git revision identity validation for S1.
//!
//! Production comparison accepts exact full object identities only. This module
//! opens the local repository through isolated strict-config `gix` reads and
//! never invokes Git, hooks, filters, credential helpers, forge APIs, network
//! remotes, target code, package managers, models, or external engines.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use sentrdel_schema::canonical::{CanonicalError, content_id};

use crate::regression::S1_REGRESSION_CONTRACT_VERSION;
use crate::regression::model::{RegressionLimits, RegressionModelError, RevisionRole};

const SHA1_HEX_BYTES: usize = 40;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalRevisionInput {
    exact_commit_id: String,
    expected_root_tree_id: Option<String>,
    snapshot_input_digest: String,
}

impl LocalRevisionInput {
    #[must_use]
    pub fn new(
        exact_commit_id: impl Into<String>,
        expected_root_tree_id: Option<impl Into<String>>,
        snapshot_input_digest: impl Into<String>,
    ) -> Self {
        Self {
            exact_commit_id: exact_commit_id.into(),
            expected_root_tree_id: expected_root_tree_id.map(Into::into),
            snapshot_input_digest: snapshot_input_digest.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLocalRevision {
    role: RevisionRole,
    exact_identity: String,
    commit_id: String,
    root_tree_id: String,
    snapshot_input_digest: String,
}

impl ValidatedLocalRevision {
    #[must_use]
    pub const fn role(&self) -> RevisionRole {
        self.role
    }

    #[must_use]
    pub fn exact_identity(&self) -> &str {
        &self.exact_identity
    }

    #[must_use]
    pub fn commit_id(&self) -> &str {
        &self.commit_id
    }

    #[must_use]
    pub fn root_tree_id(&self) -> &str {
        &self.root_tree_id
    }

    #[must_use]
    pub fn snapshot_input_digest(&self) -> &str {
        &self.snapshot_input_digest
    }

    #[must_use]
    pub const fn is_fixture_only(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedRevisionPair {
    pair_id: String,
    trusted_base: ValidatedLocalRevision,
    candidate: ValidatedLocalRevision,
}

impl ValidatedRevisionPair {
    #[must_use]
    pub fn pair_id(&self) -> &str {
        &self.pair_id
    }

    #[must_use]
    pub fn trusted_base(&self) -> &ValidatedLocalRevision {
        &self.trusted_base
    }

    #[must_use]
    pub fn candidate(&self) -> &ValidatedLocalRevision {
        &self.candidate
    }
}

#[derive(Debug)]
pub enum RevisionValidationError {
    Limits(RegressionModelError),
    RepositoryNotFound(PathBuf),
    RepositoryOpen(String),
    EmptyField(&'static str),
    FieldTooLarge {
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    TotalInputBytesExceeded {
        max: usize,
    },
    InvalidExactObjectId {
        field: &'static str,
    },
    CommitResolution {
        commit_id: String,
        source: String,
    },
    CommitObject {
        commit_id: String,
        source: String,
    },
    RootTree {
        commit_id: String,
        source: String,
    },
    RootTreeMismatch {
        expected: String,
        actual: String,
    },
    SameRevisionIdentity,
    Canonical(CanonicalError),
}

impl fmt::Display for RevisionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(error) => write!(formatter, "invalid S1 revision limits: {error}"),
            Self::RepositoryNotFound(path) => {
                write!(
                    formatter,
                    "no local Git repository found from {}",
                    path.display()
                )
            }
            Self::RepositoryOpen(source) => {
                write!(
                    formatter,
                    "cannot open local Git repository safely: {source}"
                )
            }
            Self::EmptyField(field) => write!(formatter, "S1 revision field {field} is empty"),
            Self::FieldTooLarge { field, bytes, max } => write!(
                formatter,
                "S1 revision field {field} size {bytes} exceeds cap {max}"
            ),
            Self::TotalInputBytesExceeded { max } => {
                write!(
                    formatter,
                    "S1 revision identity input exceeds byte cap {max}"
                )
            }
            Self::InvalidExactObjectId { field } => write!(
                formatter,
                "S1 revision field {field} must be an exact 40-hex SHA-1 object id"
            ),
            Self::CommitResolution { commit_id, source } => write!(
                formatter,
                "cannot resolve exact local commit {commit_id}: {source}"
            ),
            Self::CommitObject { commit_id, source } => write!(
                formatter,
                "local object {commit_id} is unavailable or is not a commit: {source}"
            ),
            Self::RootTree { commit_id, source } => write!(
                formatter,
                "cannot read root tree for local commit {commit_id}: {source}"
            ),
            Self::RootTreeMismatch { expected, actual } => write!(
                formatter,
                "local root tree mismatch: expected {expected}, resolved {actual}"
            ),
            Self::SameRevisionIdentity => formatter
                .write_str("trusted-base and candidate must bind distinct exact local commits"),
            Self::Canonical(error) => write!(formatter, "S1 revision identity failed: {error}"),
        }
    }
}

impl Error for RevisionValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Limits(error) => Some(error),
            Self::Canonical(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalError> for RevisionValidationError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

/// Validate and bind an ordered trusted-base/candidate pair to exact local Git
/// commit and root-tree identities.
///
/// Inputs must be full SHA-1 object ids. Mutable refs, abbreviated ids, display
/// labels, PR numbers, and forge-derived identities are rejected before local
/// object resolution.
pub fn validate_local_revision_pair(
    start: impl AsRef<Path>,
    trusted_base: LocalRevisionInput,
    candidate: LocalRevisionInput,
    limits: RegressionLimits,
) -> Result<ValidatedRevisionPair, RevisionValidationError> {
    let limits = limits.validate().map_err(RevisionValidationError::Limits)?;
    enforce_pair_input_bytes(&trusted_base, &candidate, limits)?;
    let root = discover_root(start.as_ref())?;
    let repo = gix::open_opts(&root, gix::open::Options::isolated().strict_config(true))
        .map_err(|error| RevisionValidationError::RepositoryOpen(error.to_string()))?;

    let trusted_base = validate_revision(&repo, RevisionRole::TrustedBase, trusted_base, limits)?;
    let candidate = validate_revision(&repo, RevisionRole::Candidate, candidate, limits)?;

    if trusted_base.commit_id == candidate.commit_id {
        return Err(RevisionValidationError::SameRevisionIdentity);
    }

    let pair_id = content_id(
        "s1-revision-pair",
        &(
            S1_REGRESSION_CONTRACT_VERSION,
            trusted_base.exact_identity.as_str(),
            candidate.exact_identity.as_str(),
        ),
    )?;

    Ok(ValidatedRevisionPair {
        pair_id,
        trusted_base,
        candidate,
    })
}

fn enforce_pair_input_bytes(
    trusted_base: &LocalRevisionInput,
    candidate: &LocalRevisionInput,
    limits: RegressionLimits,
) -> Result<(), RevisionValidationError> {
    let mut total = 0usize;
    for input in [trusted_base, candidate] {
        for bytes in [
            input.exact_commit_id.len(),
            input.snapshot_input_digest.len(),
            input
                .expected_root_tree_id
                .as_ref()
                .map_or(0, String::len),
        ] {
            total = total.checked_add(bytes).ok_or(
                RevisionValidationError::TotalInputBytesExceeded {
                    max: limits.max_total_input_bytes,
                },
            )?;
            if total > limits.max_total_input_bytes {
                return Err(RevisionValidationError::TotalInputBytesExceeded {
                    max: limits.max_total_input_bytes,
                });
            }
        }
    }
    Ok(())
}

fn validate_revision(
    repo: &gix::Repository,
    role: RevisionRole,
    input: LocalRevisionInput,
    limits: RegressionLimits,
) -> Result<ValidatedLocalRevision, RevisionValidationError> {
    let commit_id = normalize_exact_object_id(input.exact_commit_id, "exact_commit_id", limits)?;
    let expected_root_tree_id = input
        .expected_root_tree_id
        .map(|value| normalize_exact_object_id(value, "expected_root_tree_id", limits))
        .transpose()?;
    let snapshot_input_digest =
        validate_text(input.snapshot_input_digest, "snapshot_input_digest", limits)?;

    let resolved = repo.rev_parse_single(commit_id.as_str()).map_err(|error| {
        RevisionValidationError::CommitResolution {
            commit_id: commit_id.clone(),
            source: error.to_string(),
        }
    })?;
    let resolved_id = resolved.to_string().to_ascii_lowercase();
    if resolved_id != commit_id {
        return Err(RevisionValidationError::CommitResolution {
            commit_id,
            source: format!("resolved unexpected object {resolved_id}"),
        });
    }

    let commit = repo.find_commit(resolved.detach()).map_err(|error| {
        RevisionValidationError::CommitObject {
            commit_id: resolved_id.clone(),
            source: error.to_string(),
        }
    })?;
    let root_tree_id = commit
        .tree_id()
        .map_err(|error| RevisionValidationError::RootTree {
            commit_id: resolved_id.clone(),
            source: error.to_string(),
        })?
        .to_string()
        .to_ascii_lowercase();

    if let Some(expected) = expected_root_tree_id
        && expected != root_tree_id
    {
        return Err(RevisionValidationError::RootTreeMismatch {
            expected,
            actual: root_tree_id,
        });
    }

    let exact_identity = content_id(
        "s1-local-git-revision-identity",
        &(
            resolved_id.as_str(),
            root_tree_id.as_str(),
            snapshot_input_digest.as_str(),
        ),
    )?;

    Ok(ValidatedLocalRevision {
        role,
        exact_identity,
        commit_id: resolved_id,
        root_tree_id,
        snapshot_input_digest,
    })
}

fn discover_root(start: &Path) -> Result<PathBuf, RevisionValidationError> {
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
            return Err(RevisionValidationError::RepositoryNotFound(
                start.to_path_buf(),
            ));
        }
    }
}

fn normalize_exact_object_id(
    value: String,
    field: &'static str,
    limits: RegressionLimits,
) -> Result<String, RevisionValidationError> {
    let value = validate_text(value, field, limits)?;
    if value.len() != SHA1_HEX_BYTES || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RevisionValidationError::InvalidExactObjectId { field });
    }
    Ok(value.to_ascii_lowercase())
}

fn validate_text(
    value: String,
    field: &'static str,
    limits: RegressionLimits,
) -> Result<String, RevisionValidationError> {
    if value.is_empty() {
        return Err(RevisionValidationError::EmptyField(field));
    }
    if value.len() > limits.max_text_bytes {
        return Err(RevisionValidationError::FieldTooLarge {
            field,
            bytes: value.len(),
            max: limits.max_text_bytes,
        });
    }
    Ok(value)
}
