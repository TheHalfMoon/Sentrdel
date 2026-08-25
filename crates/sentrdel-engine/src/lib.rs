#![forbid(unsafe_code)]
//! Trusted boundary types for optional external evidence engines.
//!
//! T026 defines the object-safe adapter contract, bounded request/limit types,
//! validated result envelope, and registry only. Process spawning remains
//! intentionally unimplemented until T027.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    error::Error,
    fmt, fs,
    future::Future,
    path::{Component, Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use sentrdel_schema::{
    coverage::CoverageRecord,
    engine::{EngineManifest, EngineRun, NetworkRequirement},
    evidence::Evidence,
};

pub const EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED: bool = false;

/// A normalized analysis scope understood by a qualified engine adapter.
///
/// Scope values are data only. They never select executables, become shell
/// syntax, or widen child-process environment authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineScope {
    kind: String,
    value: String,
}

impl EngineScope {
    pub fn new(
        kind: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, EngineRequestError> {
        let kind = kind.into();
        let value = value.into();
        let kind = kind.trim().to_owned();
        let value = value.trim().to_owned();

        if kind.is_empty() {
            return Err(EngineRequestError::BlankScopeKind);
        }
        if value.is_empty() {
            return Err(EngineRequestError::BlankScopeValue);
        }

        Ok(Self { kind, value })
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

/// A normalized reference to input already admitted by the trusted caller.
///
/// The reference is never executable authority. T027/T028 own executable
/// resolution and raw-output adaptation respectively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineInputRef {
    kind: String,
    reference: String,
    digest: Option<String>,
}

impl EngineInputRef {
    pub fn new(
        kind: impl Into<String>,
        reference: impl Into<String>,
        digest: Option<String>,
    ) -> Result<Self, EngineRequestError> {
        let kind = kind.into();
        let reference = reference.into();
        let kind = kind.trim().to_owned();
        let reference = reference.trim().to_owned();
        let digest = digest.map(|value| value.trim().to_owned());

        if kind.is_empty() {
            return Err(EngineRequestError::BlankInputKind);
        }
        if reference.is_empty() {
            return Err(EngineRequestError::BlankInputReference);
        }
        if digest.as_deref().is_some_and(|value| value.is_empty()) {
            return Err(EngineRequestError::BlankInputDigest);
        }

        Ok(Self {
            kind,
            reference,
            digest,
        })
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

/// Normalized request presented to an engine adapter.
///
/// A request must make its intended scope/input explicit rather than relying
/// on an implicit unbounded "scan everything" default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineRequest {
    request_id: String,
    scopes: Vec<EngineScope>,
    input_refs: Vec<EngineInputRef>,
}

impl EngineRequest {
    pub fn new(
        request_id: impl Into<String>,
        scopes: Vec<EngineScope>,
        input_refs: Vec<EngineInputRef>,
    ) -> Result<Self, EngineRequestError> {
        let request_id = request_id.into();
        let request_id = request_id.trim().to_owned();
        if request_id.is_empty() {
            return Err(EngineRequestError::BlankRequestId);
        }
        if scopes.is_empty() && input_refs.is_empty() {
            return Err(EngineRequestError::UnboundedRequest);
        }

        Ok(Self {
            request_id,
            scopes,
            input_refs,
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn scopes(&self) -> &[EngineScope] {
        &self.scopes
    }

    pub fn input_refs(&self) -> &[EngineInputRef] {
        &self.input_refs
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineRequestError {
    BlankRequestId,
    BlankScopeKind,
    BlankScopeValue,
    BlankInputKind,
    BlankInputReference,
    BlankInputDigest,
    UnboundedRequest,
}

impl fmt::Display for EngineRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BlankRequestId => "engine request id must not be blank",
            Self::BlankScopeKind => "engine scope kind must not be blank",
            Self::BlankScopeValue => "engine scope value must not be blank",
            Self::BlankInputKind => "engine input kind must not be blank",
            Self::BlankInputReference => "engine input reference must not be blank",
            Self::BlankInputDigest => "engine input digest must not be blank when present",
            Self::UnboundedRequest => {
                "engine request must contain an explicit scope or input reference"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for EngineRequestError {}

/// Command-level network policy imposed by the trusted caller.
///
/// `PermitDeclared` does not itself create network authority. T027 must still
/// compare it with the trusted manifest declaration and enforcement policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkAccessPolicy {
    Deny,
    PermitDeclared,
}

/// Trusted execution bounds derived from an `EngineManifest` plus an approved
/// workspace/cwd and command-level network policy.
///
/// Workspace and cwd must already exist and are stored in canonical form so a
/// symlinked cwd cannot escape the approved canonical workspace. This type
/// intentionally contains no executable or argv fields; those belong to T027
/// trusted executable resolution and process invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineLimits {
    wall_clock_timeout: Duration,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    workspace_root: PathBuf,
    working_directory: PathBuf,
    allowed_environment_names: BTreeSet<String>,
    network_requirement: NetworkRequirement,
    network_access_policy: NetworkAccessPolicy,
}

impl EngineLimits {
    pub fn from_manifest(
        manifest: &EngineManifest,
        workspace_root: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        network_access_policy: NetworkAccessPolicy,
    ) -> Result<Self, EngineLimitsError> {
        if manifest.timeout_ms == 0 {
            return Err(EngineLimitsError::ZeroTimeout);
        }
        if manifest.max_stdout_bytes == 0 {
            return Err(EngineLimitsError::ZeroStdoutCap);
        }
        if manifest.max_stderr_bytes == 0 {
            return Err(EngineLimitsError::ZeroStderrCap);
        }

        let workspace_root = workspace_root.into();
        let working_directory = working_directory.into();

        if !workspace_root.is_absolute() {
            return Err(EngineLimitsError::WorkspaceRootNotAbsolute(workspace_root));
        }
        if !working_directory.is_absolute() {
            return Err(EngineLimitsError::WorkingDirectoryNotAbsolute(
                working_directory,
            ));
        }
        if contains_parent_component(&workspace_root)
            || contains_parent_component(&working_directory)
        {
            return Err(EngineLimitsError::ParentTraversal);
        }

        let canonical_workspace_root = fs::canonicalize(&workspace_root).map_err(|_| {
            EngineLimitsError::WorkspaceRootNotCanonicalizable(workspace_root.clone())
        })?;
        if !canonical_workspace_root.is_dir() {
            return Err(EngineLimitsError::WorkspaceRootNotCanonicalizable(
                workspace_root,
            ));
        }

        let canonical_working_directory = fs::canonicalize(&working_directory).map_err(|_| {
            EngineLimitsError::WorkingDirectoryNotCanonicalizable(working_directory.clone())
        })?;
        if !canonical_working_directory.is_dir() {
            return Err(EngineLimitsError::WorkingDirectoryNotCanonicalizable(
                working_directory,
            ));
        }
        if !canonical_working_directory.starts_with(&canonical_workspace_root) {
            return Err(EngineLimitsError::WorkingDirectoryOutsideWorkspace);
        }

        let mut allowed_environment_names = BTreeSet::new();
        for name in &manifest.allowed_environment_names {
            if name.is_empty()
                || name.trim() != name
                || name.contains('=')
                || name.chars().any(char::is_control)
            {
                return Err(EngineLimitsError::InvalidEnvironmentName(name.clone()));
            }
            if !allowed_environment_names.insert(name.clone()) {
                return Err(EngineLimitsError::DuplicateEnvironmentName(name.clone()));
            }
        }

        Ok(Self {
            wall_clock_timeout: Duration::from_millis(manifest.timeout_ms),
            max_stdout_bytes: manifest.max_stdout_bytes,
            max_stderr_bytes: manifest.max_stderr_bytes,
            workspace_root: canonical_workspace_root,
            working_directory: canonical_working_directory,
            allowed_environment_names,
            network_requirement: manifest.network_requirement.clone(),
            network_access_policy,
        })
    }

    pub fn wall_clock_timeout(&self) -> Duration {
        self.wall_clock_timeout
    }

    pub fn max_stdout_bytes(&self) -> u64 {
        self.max_stdout_bytes
    }

    pub fn max_stderr_bytes(&self) -> u64 {
        self.max_stderr_bytes
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    pub fn allowed_environment_names(&self) -> &BTreeSet<String> {
        &self.allowed_environment_names
    }

    pub fn network_requirement(&self) -> &NetworkRequirement {
        &self.network_requirement
    }

    pub fn network_access_policy(&self) -> NetworkAccessPolicy {
        self.network_access_policy
    }
}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineLimitsError {
    ZeroTimeout,
    ZeroStdoutCap,
    ZeroStderrCap,
    WorkspaceRootNotAbsolute(PathBuf),
    WorkingDirectoryNotAbsolute(PathBuf),
    WorkspaceRootNotCanonicalizable(PathBuf),
    WorkingDirectoryNotCanonicalizable(PathBuf),
    ParentTraversal,
    WorkingDirectoryOutsideWorkspace,
    InvalidEnvironmentName(String),
    DuplicateEnvironmentName(String),
}

impl fmt::Display for EngineLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTimeout => formatter.write_str("engine timeout must be greater than zero"),
            Self::ZeroStdoutCap => {
                formatter.write_str("engine stdout cap must be greater than zero")
            }
            Self::ZeroStderrCap => {
                formatter.write_str("engine stderr cap must be greater than zero")
            }
            Self::WorkspaceRootNotAbsolute(path) => {
                write!(
                    formatter,
                    "engine workspace root must be absolute: {path:?}"
                )
            }
            Self::WorkingDirectoryNotAbsolute(path) => {
                write!(
                    formatter,
                    "engine working directory must be absolute: {path:?}"
                )
            }
            Self::WorkspaceRootNotCanonicalizable(path) => write!(
                formatter,
                "engine workspace root must exist as a canonical directory: {path:?}"
            ),
            Self::WorkingDirectoryNotCanonicalizable(path) => write!(
                formatter,
                "engine working directory must exist as a canonical directory: {path:?}"
            ),
            Self::ParentTraversal => {
                formatter.write_str("engine workspace/cwd may not contain parent traversal")
            }
            Self::WorkingDirectoryOutsideWorkspace => formatter
                .write_str("engine working directory must remain inside the approved workspace"),
            Self::InvalidEnvironmentName(name) => {
                write!(
                    formatter,
                    "invalid engine environment allowlist name: {name:?}"
                )
            }
            Self::DuplicateEnvironmentName(name) => {
                write!(
                    formatter,
                    "duplicate engine environment allowlist name: {name:?}"
                )
            }
        }
    }
}

impl Error for EngineLimitsError {}

/// Sanitized adapter diagnostic. Raw stdout/stderr is intentionally not part
/// of the T026 result contract and must remain behind later bounded adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineDiagnostic {
    code: String,
    message: String,
}

impl EngineDiagnostic {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Validated engine output admitted to the trusted Rust boundary.
///
/// Raw engine bytes are not represented here. T028 must validate/map raw
/// output before constructing this envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct EngineRunResult {
    run: EngineRun,
    evidence: Vec<Evidence>,
    coverage: Vec<CoverageRecord>,
    diagnostics: Vec<EngineDiagnostic>,
}

impl EngineRunResult {
    pub fn new(
        run: EngineRun,
        evidence: Vec<Evidence>,
        coverage: Vec<CoverageRecord>,
        diagnostics: Vec<EngineDiagnostic>,
    ) -> Self {
        Self {
            run,
            evidence,
            coverage,
            diagnostics,
        }
    }

    pub fn run(&self) -> &EngineRun {
        &self.run
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    pub fn coverage(&self) -> &[CoverageRecord] {
        &self.coverage
    }

    pub fn diagnostics(&self) -> &[EngineDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineRunErrorKind {
    InvalidRequest,
    PolicyBlocked,
    AdapterFailure,
}

/// Pre-result engine boundary failure.
///
/// Runtime termination paths introduced by T027 and adapted by T028 must be
/// represented as explicit run/coverage state by T030 rather than silently
/// collapsing into this error channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineRunError {
    kind: EngineRunErrorKind,
    code: String,
    message: String,
}

impl EngineRunError {
    pub fn new(
        kind: EngineRunErrorKind,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn kind(&self) -> EngineRunErrorKind {
        self.kind
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EngineRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for EngineRunError {}

pub type EngineRunFuture<'a> =
    Pin<Box<dyn Future<Output = Result<EngineRunResult, EngineRunError>> + Send + 'a>>;

/// Object-safe external engine adapter boundary.
pub trait Engine: Send + Sync {
    fn manifest(&self) -> &EngineManifest;

    fn run<'a>(&'a self, request: EngineRequest, limits: EngineLimits) -> EngineRunFuture<'a>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineRegistryError {
    InvalidEngineId,
    DuplicateEngineId(String),
}

impl fmt::Display for EngineRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEngineId => formatter.write_str(
                "engine manifest id must be non-empty, normalized, and free of control characters",
            ),
            Self::DuplicateEngineId(engine_id) => {
                write!(formatter, "engine id already registered: {engine_id:?}")
            }
        }
    }
}

impl Error for EngineRegistryError {}

/// Registry of qualified adapters keyed only by trusted manifest engine id.
#[derive(Default)]
pub struct EngineRegistry {
    engines: BTreeMap<String, Arc<dyn Engine>>,
}

impl EngineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, engine: Arc<dyn Engine>) -> Result<(), EngineRegistryError> {
        let engine_id = engine.manifest().engine_id.clone();
        if engine_id.is_empty()
            || engine_id.trim() != engine_id
            || engine_id.chars().any(char::is_control)
        {
            return Err(EngineRegistryError::InvalidEngineId);
        }

        match self.engines.entry(engine_id) {
            Entry::Vacant(slot) => {
                slot.insert(engine);
                Ok(())
            }
            Entry::Occupied(slot) => {
                Err(EngineRegistryError::DuplicateEngineId(slot.key().clone()))
            }
        }
    }

    pub fn get(&self, engine_id: &str) -> Option<Arc<dyn Engine>> {
        self.engines.get(engine_id).cloned()
    }

    pub fn contains(&self, engine_id: &str) -> bool {
        self.engines.contains_key(engine_id)
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.engines.keys().map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.engines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.engines.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    struct FixtureEngine {
        manifest: EngineManifest,
    }

    impl Engine for FixtureEngine {
        fn manifest(&self) -> &EngineManifest {
            &self.manifest
        }

        fn run<'a>(
            &'a self,
            _request: EngineRequest,
            _limits: EngineLimits,
        ) -> EngineRunFuture<'a> {
            Box::pin(async {
                Err(EngineRunError::new(
                    EngineRunErrorKind::AdapterFailure,
                    "fixture-not-executed",
                    "T026 fixture proves the object-safe boundary only",
                ))
            })
        }
    }

    fn manifest(engine_id: &str) -> EngineManifest {
        EngineManifest {
            schema_version: "1".to_owned(),
            engine_id: engine_id.to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-installation".to_owned(),
            executable_digest: None,
            expected_version_constraint: Some("1.x".to_owned()),
            input_dialects: vec!["normalized-ref".to_owned()],
            output_dialects: vec!["sentrdel-json".to_owned()],
            capabilities: vec!["fixture".to_owned()],
            timeout_ms: 2_500,
            max_stdout_bytes: 8_192,
            max_stderr_bytes: 4_096,
            allowed_environment_names: vec!["LANG".to_owned(), "PATH".to_owned()],
            network_requirement: NetworkRequirement::None,
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        let fixture_id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sentrdel-t026-{label}-{}-{fixture_id}",
            std::process::id()
        ))
    }

    fn existing_workspace(label: &str) -> (PathBuf, PathBuf) {
        let workspace = unique_temp_path(label);
        let working_directory = workspace.join("subdir");
        fs::create_dir_all(&working_directory).expect("create T026 workspace fixture");
        (workspace, working_directory)
    }

    fn explicit_request() -> EngineRequest {
        EngineRequest::new(
            "request-1",
            vec![EngineScope::new("repository", ".").expect("valid explicit scope")],
            vec![
                EngineInputRef::new("tree", "sha256:fixture", Some("sha256:fixture".to_owned()))
                    .expect("valid input reference"),
            ],
        )
        .expect("explicit request")
    }

    fn limits(manifest: &EngineManifest) -> EngineLimits {
        let (workspace, working_directory) = existing_workspace("limits");
        EngineLimits::from_manifest(
            manifest,
            &workspace,
            &working_directory,
            NetworkAccessPolicy::Deny,
        )
        .expect("trusted fixture limits")
    }

    #[test]
    fn request_requires_explicit_normalized_scope_or_input() {
        assert_eq!(
            EngineRequest::new("request-1", Vec::new(), Vec::new()),
            Err(EngineRequestError::UnboundedRequest)
        );
        assert_eq!(
            EngineScope::new(" ", "."),
            Err(EngineRequestError::BlankScopeKind)
        );
        assert_eq!(
            EngineInputRef::new("tree", " ", None),
            Err(EngineRequestError::BlankInputReference)
        );

        let scope = EngineScope::new(" repository ", " . ").expect("normalized scope");
        assert_eq!(scope.kind(), "repository");
        assert_eq!(scope.value(), ".");

        let input = EngineInputRef::new(
            " tree ",
            " sha256:fixture ",
            Some(" sha256:digest ".to_owned()),
        )
        .expect("normalized input reference");
        assert_eq!(input.kind(), "tree");
        assert_eq!(input.reference(), "sha256:fixture");
        assert_eq!(input.digest(), Some("sha256:digest"));

        let request = EngineRequest::new(" request-1 ", vec![scope], vec![input])
            .expect("normalized request");
        assert_eq!(request.request_id(), "request-1");
    }

    #[test]
    fn limits_preserve_manifest_caps_environment_and_network_declaration() {
        let manifest = manifest("fixture");
        let limits = limits(&manifest);

        assert_eq!(limits.wall_clock_timeout(), Duration::from_millis(2_500));
        assert_eq!(limits.max_stdout_bytes(), 8_192);
        assert_eq!(limits.max_stderr_bytes(), 4_096);
        assert!(limits.workspace_root().is_absolute());
        assert!(
            limits
                .working_directory()
                .starts_with(limits.workspace_root())
        );
        assert_eq!(limits.network_requirement(), &NetworkRequirement::None);
        assert_eq!(limits.network_access_policy(), NetworkAccessPolicy::Deny);
        assert_eq!(
            limits
                .allowed_environment_names()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["LANG", "PATH"]
        );
    }

    #[test]
    fn limits_reject_parent_traversal_outside_cwd_and_bad_environment_names() {
        let fixture_manifest = manifest("fixture");
        let (workspace, working_directory) = existing_workspace("reject");

        assert_eq!(
            EngineLimits::from_manifest(
                &fixture_manifest,
                &workspace,
                workspace.join("..").join("escape"),
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::ParentTraversal)
        );

        let outside = unique_temp_path("outside");
        fs::create_dir_all(&outside).expect("create outside fixture");
        assert_eq!(
            EngineLimits::from_manifest(
                &fixture_manifest,
                &workspace,
                &outside,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::WorkingDirectoryOutsideWorkspace)
        );

        let mut duplicate_environment = manifest("fixture");
        duplicate_environment.allowed_environment_names =
            vec!["PATH".to_owned(), "PATH".to_owned()];
        assert_eq!(
            EngineLimits::from_manifest(
                &duplicate_environment,
                &workspace,
                &working_directory,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::DuplicateEnvironmentName(
                "PATH".to_owned()
            ))
        );

        for invalid_name in ["PATH=/attacker/bin", "PATH\n", " PATH"] {
            let mut invalid_environment = manifest("fixture");
            invalid_environment.allowed_environment_names = vec![invalid_name.to_owned()];
            assert_eq!(
                EngineLimits::from_manifest(
                    &invalid_environment,
                    &workspace,
                    &working_directory,
                    NetworkAccessPolicy::Deny,
                ),
                Err(EngineLimitsError::InvalidEnvironmentName(
                    invalid_name.to_owned()
                ))
            );
        }
    }

    #[test]
    fn limits_reject_invalid_paths_and_zero_resource_caps() {
        let fixture_manifest = manifest("fixture");
        let (workspace, working_directory) = existing_workspace("path-errors");

        let relative_workspace = PathBuf::from("relative/workspace");
        assert_eq!(
            EngineLimits::from_manifest(
                &fixture_manifest,
                &relative_workspace,
                &working_directory,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::WorkspaceRootNotAbsolute(
                relative_workspace
            ))
        );

        let relative_cwd = PathBuf::from("relative/cwd");
        assert_eq!(
            EngineLimits::from_manifest(
                &fixture_manifest,
                &workspace,
                &relative_cwd,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::WorkingDirectoryNotAbsolute(relative_cwd))
        );

        let missing_workspace = unique_temp_path("missing-workspace");
        assert_eq!(
            EngineLimits::from_manifest(
                &fixture_manifest,
                &missing_workspace,
                &working_directory,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::WorkspaceRootNotCanonicalizable(
                missing_workspace
            ))
        );

        let missing_cwd = workspace.join("missing-cwd");
        assert_eq!(
            EngineLimits::from_manifest(
                &fixture_manifest,
                &workspace,
                &missing_cwd,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::WorkingDirectoryNotCanonicalizable(
                missing_cwd
            ))
        );

        let mut zero_timeout = manifest("fixture");
        zero_timeout.timeout_ms = 0;
        assert_eq!(
            EngineLimits::from_manifest(
                &zero_timeout,
                &workspace,
                &working_directory,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::ZeroTimeout)
        );

        let mut zero_stdout = manifest("fixture");
        zero_stdout.max_stdout_bytes = 0;
        assert_eq!(
            EngineLimits::from_manifest(
                &zero_stdout,
                &workspace,
                &working_directory,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::ZeroStdoutCap)
        );

        let mut zero_stderr = manifest("fixture");
        zero_stderr.max_stderr_bytes = 0;
        assert_eq!(
            EngineLimits::from_manifest(
                &zero_stderr,
                &workspace,
                &working_directory,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::ZeroStderrCap)
        );
    }

    #[cfg(unix)]
    #[test]
    fn limits_reject_symlink_workspace_escape() {
        use std::os::unix::fs::symlink;

        let workspace = unique_temp_path("symlink-workspace");
        let outside = unique_temp_path("symlink-outside");
        fs::create_dir_all(&workspace).expect("create symlink workspace");
        fs::create_dir_all(&outside).expect("create symlink outside directory");
        let escaped_cwd = workspace.join("escaped-cwd");
        symlink(&outside, &escaped_cwd).expect("create escape symlink");

        assert_eq!(
            EngineLimits::from_manifest(
                &manifest("fixture"),
                &workspace,
                &escaped_cwd,
                NetworkAccessPolicy::Deny,
            ),
            Err(EngineLimitsError::WorkingDirectoryOutsideWorkspace)
        );
    }

    #[test]
    fn registry_is_manifest_keyed_duplicate_safe_and_object_safe() {
        let fixture_manifest = manifest("fixture");
        let fixture_limits = limits(&fixture_manifest);
        let mut registry = EngineRegistry::new();

        registry
            .register(Arc::new(FixtureEngine {
                manifest: fixture_manifest,
            }))
            .expect("first qualified adapter should register");

        assert!(registry.contains("fixture"));
        assert_eq!(registry.ids().collect::<Vec<_>>(), vec!["fixture"]);
        assert_eq!(registry.len(), 1);

        let engine = registry.get("fixture").expect("registered adapter");
        let _future: EngineRunFuture<'_> = engine.run(explicit_request(), fixture_limits);

        assert_eq!(
            registry.register(Arc::new(FixtureEngine {
                manifest: manifest("fixture"),
            })),
            Err(EngineRegistryError::DuplicateEngineId("fixture".to_owned()))
        );
        assert_eq!(registry.len(), 1);

        for invalid_id in ["", " padded ", "bad\nid"] {
            let mut invalid_registry = EngineRegistry::new();
            assert_eq!(
                invalid_registry.register(Arc::new(FixtureEngine {
                    manifest: manifest(invalid_id),
                })),
                Err(EngineRegistryError::InvalidEngineId)
            );
        }
    }

    #[test]
    fn t026_does_not_enable_external_execution() {
        const { assert!(!EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED) };
    }
}
