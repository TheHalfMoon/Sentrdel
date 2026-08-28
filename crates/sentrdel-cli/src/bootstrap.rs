use std::{
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};

use sentrdel_engine::EngineRegistry;
use sentrdel_graph::{GraphProjection, GraphProjectionError};
use sentrdel_policy::kernel::{PolicyBootstrap, PolicyBootstrapError};
use sentrdel_schema::SCHEMA_V1;
use sentrdel_store::{Store, StoreError};

/// Trusted startup inputs for the R1 composition root.
///
/// These values are supplied by the process/bootstrap layer. Repository feature
/// behavior does not populate this type in T036, and no engine, review, guard,
/// package-manager, target build, or network operation is performed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BootstrapConfig {
    workspace_root: PathBuf,
    store_path: PathBuf,
    policy_authority_id: String,
    policy_configuration_digest: String,
}

impl BootstrapConfig {
    pub(crate) fn new(
        workspace_root: impl Into<PathBuf>,
        store_path: impl Into<PathBuf>,
        policy_authority_id: impl Into<String>,
        policy_configuration_digest: impl Into<String>,
    ) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            store_path: store_path.into(),
            policy_authority_id: policy_authority_id.into(),
            policy_configuration_digest: policy_configuration_digest.into(),
        }
    }
}

/// R1 trusted composition root established before user-story behavior exists.
///
/// The runtime owns one Sentrdel store, one empty graph projection, one engine
/// registry, and the policy bootstrap boundary. It deliberately exposes no
/// review, init, explain, guard, engine-execution, or network orchestration.
pub(crate) struct BootstrapRuntime {
    wire_schema_version: &'static str,
    store_path: PathBuf,
    store: Store,
    graph: GraphProjection,
    engines: EngineRegistry,
    policy: PolicyBootstrap,
}

impl BootstrapRuntime {
    pub(crate) fn open(config: BootstrapConfig) -> Result<Self, BootstrapError> {
        // Validate all non-mutating authority/path inputs before Store::open can
        // create or migrate a database.
        let policy = PolicyBootstrap::new(
            &config.workspace_root,
            config.policy_authority_id,
            config.policy_configuration_digest,
        )?;
        let store_path = normalize_store_path(&config.store_path)?;

        let store = Store::open(&store_path)?;
        // Force the store to prove its migration ledger is readable at bootstrap
        // rather than deferring a broken database until feature execution.
        let _store_schema_version = store.schema_version()?;

        // The graph crate is wired as an explicitly empty, validated projection.
        // Loading graph records from the store belongs to later feature work.
        let graph = GraphProjection::from_records(
            std::iter::empty::<sentrdel_schema::graph::GraphNode>(),
            std::iter::empty::<sentrdel_schema::graph::GraphEdge>(),
        )?;

        Ok(Self {
            wire_schema_version: SCHEMA_V1,
            store_path,
            store,
            graph,
            engines: EngineRegistry::new(),
            policy,
        })
    }

    pub(crate) const fn wire_schema_version(&self) -> &'static str {
        self.wire_schema_version
    }

    pub(crate) fn store_path(&self) -> &Path {
        &self.store_path
    }

    pub(crate) fn store(&self) -> &Store {
        &self.store
    }

    pub(crate) fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    pub(crate) fn graph(&self) -> &GraphProjection {
        &self.graph
    }

    pub(crate) fn engines(&self) -> &EngineRegistry {
        &self.engines
    }

    pub(crate) fn engines_mut(&mut self) -> &mut EngineRegistry {
        &mut self.engines
    }

    pub(crate) fn policy(&self) -> &PolicyBootstrap {
        &self.policy
    }
}

#[derive(Debug)]
pub(crate) enum BootstrapError {
    StorePathNotAbsolute(PathBuf),
    StorePathParentTraversal(PathBuf),
    StoreParentUnavailable(PathBuf),
    StorePathIsDirectory(PathBuf),
    Policy(PolicyBootstrapError),
    Store(StoreError),
    Graph(GraphProjectionError),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorePathNotAbsolute(path) => {
                write!(formatter, "bootstrap store path must be absolute: {path:?}")
            }
            Self::StorePathParentTraversal(path) => write!(
                formatter,
                "bootstrap store path must not contain parent traversal: {path:?}"
            ),
            Self::StoreParentUnavailable(path) => write!(
                formatter,
                "bootstrap store parent must exist as a canonical directory: {path:?}"
            ),
            Self::StorePathIsDirectory(path) => {
                write!(formatter, "bootstrap store path must not be a directory: {path:?}")
            }
            Self::Policy(error) => write!(formatter, "policy bootstrap failed: {error}"),
            Self::Store(error) => write!(formatter, "store bootstrap failed: {error}"),
            Self::Graph(error) => write!(formatter, "graph bootstrap failed: {error}"),
        }
    }
}

impl Error for BootstrapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::StorePathNotAbsolute(_)
            | Self::StorePathParentTraversal(_)
            | Self::StoreParentUnavailable(_)
            | Self::StorePathIsDirectory(_) => None,
        }
    }
}

impl From<PolicyBootstrapError> for BootstrapError {
    fn from(value: PolicyBootstrapError) -> Self {
        Self::Policy(value)
    }
}

impl From<StoreError> for BootstrapError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<GraphProjectionError> for BootstrapError {
    fn from(value: GraphProjectionError) -> Self {
        Self::Graph(value)
    }
}

fn normalize_store_path(path: &Path) -> Result<PathBuf, BootstrapError> {
    if !path.is_absolute() {
        return Err(BootstrapError::StorePathNotAbsolute(path.to_path_buf()));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(BootstrapError::StorePathParentTraversal(path.to_path_buf()));
    }

    let file_name = path
        .file_name()
        .ok_or_else(|| BootstrapError::StorePathIsDirectory(path.to_path_buf()))?;
    let parent = path
        .parent()
        .ok_or_else(|| BootstrapError::StoreParentUnavailable(path.to_path_buf()))?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| BootstrapError::StoreParentUnavailable(parent.to_path_buf()))?;
    if !canonical_parent.is_dir() {
        return Err(BootstrapError::StoreParentUnavailable(parent.to_path_buf()));
    }

    if path.exists() {
        let canonical = fs::canonicalize(path)
            .map_err(|_| BootstrapError::StoreParentUnavailable(path.to_path_buf()))?;
        if canonical.is_dir() {
            return Err(BootstrapError::StorePathIsDirectory(canonical));
        }
        Ok(canonical)
    } else {
        Ok(canonical_parent.join(file_name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TestWorkspace {
        root: PathBuf,
    }

    impl TestWorkspace {
        fn new(label: &str) -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "sentrdel-bootstrap-{label}-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join(".sentrdel")).expect("create test workspace");
            Self { root }
        }

        fn config(&self) -> BootstrapConfig {
            BootstrapConfig::new(
                &self.root,
                self.root.join(".sentrdel/state.sqlite3"),
                "sentrdel-r1-kernel",
                format!("sha256:{}", "a".repeat(64)),
            )
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn bootstrap_wires_all_foundational_substrates_without_feature_execution() {
        let workspace = TestWorkspace::new("composition");
        let mut runtime = BootstrapRuntime::open(workspace.config()).expect("bootstrap runtime");

        assert_eq!(runtime.wire_schema_version(), SCHEMA_V1);
        assert!(runtime.store_path().is_absolute());
        assert!(runtime.store().schema_version().expect("store schema") > 0);
        assert_eq!(runtime.graph().node_count(), 0);
        assert_eq!(runtime.graph().edge_count(), 0);
        assert!(runtime.engines().is_empty());
        assert_eq!(runtime.engines_mut().len(), 0);
        assert!(runtime.store_mut().schema_version().expect("store schema") > 0);
        assert_eq!(runtime.policy().workspace_root(), workspace.root.canonicalize().unwrap());

        let validated = runtime
            .policy()
            .validate_workspace_path(workspace.root.join(".sentrdel"))
            .expect("workspace child should validate");
        assert!(validated.path().starts_with(runtime.policy().workspace_root()));
    }

    #[test]
    fn bootstrap_rejects_relative_store_path_before_creating_state() {
        let workspace = TestWorkspace::new("relative-store");
        let config = BootstrapConfig::new(
            &workspace.root,
            "relative.sqlite3",
            "sentrdel-r1-kernel",
            format!("sha256:{}", "b".repeat(64)),
        );

        assert!(matches!(
            BootstrapRuntime::open(config),
            Err(BootstrapError::StorePathNotAbsolute(_))
        ));
        assert!(!workspace.root.join("relative.sqlite3").exists());
    }

    #[test]
    fn invalid_policy_authority_fails_before_store_creation() {
        let workspace = TestWorkspace::new("policy-first");
        let store_path = workspace.root.join(".sentrdel/state.sqlite3");
        let config = BootstrapConfig::new(
            &workspace.root,
            &store_path,
            "   ",
            format!("sha256:{}", "c".repeat(64)),
        );

        assert!(matches!(
            BootstrapRuntime::open(config),
            Err(BootstrapError::Policy(_))
        ));
        assert!(!store_path.exists());
    }

    #[test]
    fn existing_directory_cannot_be_used_as_store_file() {
        let workspace = TestWorkspace::new("store-directory");
        let config = BootstrapConfig::new(
            &workspace.root,
            workspace.root.join(".sentrdel"),
            "sentrdel-r1-kernel",
            format!("sha256:{}", "d".repeat(64)),
        );

        assert!(matches!(
            BootstrapRuntime::open(config),
            Err(BootstrapError::StorePathIsDirectory(_))
        ));
    }
}
