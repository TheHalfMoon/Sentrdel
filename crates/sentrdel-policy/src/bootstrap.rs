use std::{
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};

use sentrdel_schema::policy::TrustedPolicyAuthority;

const MAX_POLICY_AUTHORITY_ID_BYTES: usize = 4_096;

/// Trusted policy bootstrap state created from process-owned configuration.
///
/// Repository/model/engine content cannot manufacture this value by
/// deserialization. The approved workspace is canonicalized before the runtime
/// opens mutable state, and policy authority metadata is validated before being
/// bound through `TrustedPolicyAuthority`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyBootstrap {
    workspace_root: PathBuf,
    authority: TrustedPolicyAuthority,
}

impl PolicyBootstrap {
    pub fn new(
        workspace_root: impl AsRef<Path>,
        authority_id: impl Into<String>,
        configuration_digest: impl Into<String>,
    ) -> Result<Self, PolicyBootstrapError> {
        let workspace_root = workspace_root.as_ref();
        if !workspace_root.is_absolute() {
            return Err(PolicyBootstrapError::WorkspaceRootNotAbsolute(
                workspace_root.to_path_buf(),
            ));
        }
        if contains_parent_component(workspace_root) {
            return Err(PolicyBootstrapError::WorkspaceParentTraversal(
                workspace_root.to_path_buf(),
            ));
        }
        let canonical_workspace = fs::canonicalize(workspace_root).map_err(|_| {
            PolicyBootstrapError::WorkspaceRootUnavailable(workspace_root.to_path_buf())
        })?;
        if !canonical_workspace.is_dir() {
            return Err(PolicyBootstrapError::WorkspaceRootUnavailable(
                workspace_root.to_path_buf(),
            ));
        }

        let authority_id = authority_id.into();
        if authority_id.trim().is_empty()
            || authority_id.len() > MAX_POLICY_AUTHORITY_ID_BYTES
            || authority_id.chars().any(char::is_control)
        {
            return Err(PolicyBootstrapError::InvalidAuthorityId);
        }

        let configuration_digest = configuration_digest.into();
        if !is_canonical_sha256_id(&configuration_digest) {
            return Err(PolicyBootstrapError::InvalidConfigurationDigest);
        }

        Ok(Self {
            workspace_root: canonical_workspace,
            authority: TrustedPolicyAuthority::from_runtime(authority_id, configuration_digest),
        })
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn authority(&self) -> &TrustedPolicyAuthority {
        &self.authority
    }

    /// Validate one existing path against the canonical approved workspace.
    ///
    /// Canonicalization resolves symlinks before containment is checked. This is
    /// a T036 bootstrap primitive, not a complete write-target validator; T052
    /// owns action-specific handling for paths that may not exist yet.
    pub fn validate_workspace_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<ValidatedWorkspacePath, PolicyBootstrapError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(PolicyBootstrapError::CandidatePathNotAbsolute(
                path.to_path_buf(),
            ));
        }
        if contains_parent_component(path) {
            return Err(PolicyBootstrapError::CandidateParentTraversal(
                path.to_path_buf(),
            ));
        }
        let canonical = fs::canonicalize(path)
            .map_err(|_| PolicyBootstrapError::CandidatePathUnavailable(path.to_path_buf()))?;
        if !canonical.starts_with(&self.workspace_root) {
            return Err(PolicyBootstrapError::CandidateOutsideWorkspace(canonical));
        }
        Ok(ValidatedWorkspacePath { path: canonical })
    }
}

/// Opaque evidence that one existing path resolved inside the approved
/// workspace. This is intentionally not serializable or directly constructible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedWorkspacePath {
    path: PathBuf,
}

impl ValidatedWorkspacePath {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyBootstrapError {
    WorkspaceRootNotAbsolute(PathBuf),
    WorkspaceParentTraversal(PathBuf),
    WorkspaceRootUnavailable(PathBuf),
    InvalidAuthorityId,
    InvalidConfigurationDigest,
    CandidatePathNotAbsolute(PathBuf),
    CandidateParentTraversal(PathBuf),
    CandidatePathUnavailable(PathBuf),
    CandidateOutsideWorkspace(PathBuf),
}

impl fmt::Display for PolicyBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceRootNotAbsolute(path) => {
                write!(
                    formatter,
                    "policy workspace root must be absolute: {path:?}"
                )
            }
            Self::WorkspaceParentTraversal(path) => write!(
                formatter,
                "policy workspace root must not contain parent traversal: {path:?}"
            ),
            Self::WorkspaceRootUnavailable(path) => write!(
                formatter,
                "policy workspace root must exist as a canonical directory: {path:?}"
            ),
            Self::InvalidAuthorityId => formatter.write_str(
                "policy authority id must be bounded, non-blank text without control characters",
            ),
            Self::InvalidConfigurationDigest => formatter
                .write_str("policy configuration digest must use sha256:<64 lowercase hex> form"),
            Self::CandidatePathNotAbsolute(path) => {
                write!(
                    formatter,
                    "policy candidate path must be absolute: {path:?}"
                )
            }
            Self::CandidateParentTraversal(path) => write!(
                formatter,
                "policy candidate path must not contain parent traversal: {path:?}"
            ),
            Self::CandidatePathUnavailable(path) => write!(
                formatter,
                "policy candidate path must exist for bootstrap validation: {path:?}"
            ),
            Self::CandidateOutsideWorkspace(path) => write!(
                formatter,
                "policy candidate path resolves outside the approved workspace: {path:?}"
            ),
        }
    }
}

impl Error for PolicyBootstrapError {}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn is_canonical_sha256_id(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_WORKSPACE_ID: AtomicU64 = AtomicU64::new(0);

    struct TestWorkspace {
        root: PathBuf,
    }

    impl TestWorkspace {
        fn new(label: &str) -> Self {
            let id = NEXT_WORKSPACE_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "sentrdel-policy-bootstrap-{label}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("inside")).expect("create policy test workspace");
            Self { root }
        }

        fn bootstrap(&self) -> PolicyBootstrap {
            PolicyBootstrap::new(
                &self.root,
                "sentrdel-test-authority",
                format!("sha256:{}", "a".repeat(64)),
            )
            .expect("policy bootstrap")
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn bootstrap_binds_canonical_workspace_and_policy_authority() {
        let workspace = TestWorkspace::new("canonical");
        let bootstrap = workspace.bootstrap();

        assert_eq!(
            bootstrap.workspace_root(),
            workspace.root.canonicalize().unwrap()
        );
        assert_eq!(bootstrap.authority().id(), "sentrdel-test-authority");
        assert_eq!(
            bootstrap.authority().configuration_digest(),
            format!("sha256:{}", "a".repeat(64))
        );
        let inside = bootstrap
            .validate_workspace_path(workspace.root.join("inside"))
            .expect("inside path");
        assert!(inside.path().starts_with(bootstrap.workspace_root()));
    }

    #[test]
    fn bootstrap_rejects_untrusted_authority_and_digest_shapes() {
        let workspace = TestWorkspace::new("authority");
        assert!(matches!(
            PolicyBootstrap::new(&workspace.root, "   ", format!("sha256:{}", "a".repeat(64))),
            Err(PolicyBootstrapError::InvalidAuthorityId)
        ));
        assert!(matches!(
            PolicyBootstrap::new(&workspace.root, "authority", "sha256:not-valid"),
            Err(PolicyBootstrapError::InvalidConfigurationDigest)
        ));
    }

    #[test]
    fn bootstrap_workspace_validation_fails_closed_outside_root() {
        let workspace = TestWorkspace::new("outside");
        let outside = TestWorkspace::new("other");
        let bootstrap = workspace.bootstrap();

        assert!(matches!(
            bootstrap.validate_workspace_path(outside.root.join("inside")),
            Err(PolicyBootstrapError::CandidateOutsideWorkspace(_))
        ));
        assert!(matches!(
            bootstrap.validate_workspace_path("relative/path"),
            Err(PolicyBootstrapError::CandidatePathNotAbsolute(_))
        ));
    }
}
