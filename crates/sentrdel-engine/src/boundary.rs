#![forbid(unsafe_code)]
//! Trusted boundary types for optional external evidence engines.
//!
//! T026 defines the object-safe adapter contract, bounded request/limit types,
//! validated result envelope, and registry. T027 consumes these limits for the
//! sole external-engine process runner.

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

pub(crate) const EXTERNAL_ENGINE_EXECUTION_IMPLEMENTED: bool = false;

/// Hard R1 ceilings for manifest-controlled process resources.
pub const MAX_ENGINE_TIMEOUT_MS: u64 = 15 * 60 * 1_000;
pub const MAX_ENGINE_STDOUT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ENGINE_STDERR_BYTES: u64 = 64 * 1024 * 1024;

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
        let kind = kind.into().trim().to_owned();
        let value = value.into().trim().to_owned();
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
        let kind = kind.into().trim().to_owned();
        let reference = reference.into().trim().to_owned();
        let digest = digest.map(|value| value.trim().to_owned());
        if kind.is_empty() {
            return Err(EngineRequestError::BlankInputKind);
        }
        if reference.is_empty() {
            return Err(EngineRequestError::BlankInputReference);
        }
        if digest.as_deref().is_some_and(str::is_empty) {
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
        let request_id = request_id.into().trim().to_owned();
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
        formatter.write_str(match self {
            Self::BlankRequestId => "engine request id must not be blank",
            Self::BlankScopeKind => "engine scope kind must not be blank",
            Self::BlankScopeValue => "engine scope value must not be blank",
            Self::BlankInputKind => "engine input kind must not be blank",
            Self::BlankInputReference => "engine input reference must not be blank",
            Self::BlankInputDigest => "engine input digest must not be blank when present",
            Self::UnboundedRequest => {
                "engine request must contain an explicit scope or input reference"
            }
        })
    }
}

impl Error for EngineRequestError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkAccessPolicy {
    Deny,
    PermitDeclared,
}

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
        validate_manifest_resource_limits(manifest)?;

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

fn validate_manifest_resource_limits(manifest: &EngineManifest) -> Result<(), EngineLimitsError> {
    if manifest.timeout_ms == 0 {
        return Err(EngineLimitsError::ZeroTimeout);
    }
    if manifest.timeout_ms > MAX_ENGINE_TIMEOUT_MS {
        return Err(EngineLimitsError::TimeoutAboveMaximum {
            value: manifest.timeout_ms,
            max: MAX_ENGINE_TIMEOUT_MS,
        });
    }
    if manifest.max_stdout_bytes == 0 {
        return Err(EngineLimitsError::ZeroStdoutCap);
    }
    if manifest.max_stdout_bytes > MAX_ENGINE_STDOUT_BYTES
        || usize::try_from(manifest.max_stdout_bytes).is_err()
    {
        return Err(EngineLimitsError::StdoutCapAboveMaximum {
            value: manifest.max_stdout_bytes,
            max: MAX_ENGINE_STDOUT_BYTES,
        });
    }
    if manifest.max_stderr_bytes == 0 {
        return Err(EngineLimitsError::ZeroStderrCap);
    }
    if manifest.max_stderr_bytes > MAX_ENGINE_STDERR_BYTES
        || usize::try_from(manifest.max_stderr_bytes).is_err()
    {
        return Err(EngineLimitsError::StderrCapAboveMaximum {
            value: manifest.max_stderr_bytes,
            max: MAX_ENGINE_STDERR_BYTES,
        });
    }
    Ok(())
}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineLimitsError {
    ZeroTimeout,
    TimeoutAboveMaximum { value: u64, max: u64 },
    ZeroStdoutCap,
    StdoutCapAboveMaximum { value: u64, max: u64 },
    ZeroStderrCap,
    StderrCapAboveMaximum { value: u64, max: u64 },
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
            Self::TimeoutAboveMaximum { value, max } => {
                write!(formatter, "engine timeout {value}ms exceeds hard maximum {max}ms")
            }
            Self::ZeroStdoutCap => {
                formatter.write_str("engine stdout cap must be greater than zero")
            }
            Self::StdoutCapAboveMaximum { value, max } => {
                write!(formatter, "engine stdout cap {value} exceeds hard maximum {max}")
            }
            Self::ZeroStderrCap => {
                formatter.write_str("engine stderr cap must be greater than zero")
            }
            Self::StderrCapAboveMaximum { value, max } => {
                write!(formatter, "engine stderr cap {value} exceeds hard maximum {max}")
            }
            Self::WorkspaceRootNotAbsolute(path) => {
                write!(formatter, "engine workspace root must be absolute: {path:?}")
            }
            Self::WorkingDirectoryNotAbsolute(path) => {
                write!(formatter, "engine working directory must be absolute: {path:?}")
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
                write!(formatter, "invalid engine environment allowlist name: {name:?}")
            }
            Self::DuplicateEnvironmentName(name) => {
                write!(formatter, "duplicate engine environment allowlist name: {name:?}")
            }
        }
    }
}

impl Error for EngineLimitsError {}

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
                    "fixture proves the object-safe boundary only",
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
            expected_version_constraint: None,
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
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sentrdel-engine-boundary-{label}-{}-{id}",
            std::process::id()
        ))
    }

    fn workspace(label: &str) -> (PathBuf, PathBuf) {
        let root = unique_temp_path(label);
        let cwd = root.join("cwd");
        fs::create_dir_all(&cwd).expect("create fixture workspace");
        (root, cwd)
    }

    fn limits(manifest: &EngineManifest) -> EngineLimits {
        let (root, cwd) = workspace("limits");
        EngineLimits::from_manifest(manifest, root, cwd, NetworkAccessPolicy::Deny)
            .expect("valid fixture limits")
    }

    #[test]
    fn request_values_are_normalized_and_unbounded_request_is_rejected() {
        assert_eq!(
            EngineRequest::new("request", Vec::new(), Vec::new()),
            Err(EngineRequestError::UnboundedRequest)
        );
        let scope = EngineScope::new(" repository ", " . ").expect("scope");
        let input = EngineInputRef::new(
            " tree ",
            " sha256:fixture ",
            Some(" sha256:digest ".to_owned()),
        )
        .expect("input");
        let request = EngineRequest::new(" request ", vec![scope], vec![input]).expect("request");
        assert_eq!(request.request_id(), "request");
        assert_eq!(request.scopes()[0].kind(), "repository");
        assert_eq!(request.input_refs()[0].digest(), Some("sha256:digest"));
    }

    #[test]
    fn manifest_resource_limits_have_hard_upper_bounds() {
        let (root, cwd) = workspace("hard-caps");
        let mut fixture = manifest("fixture");

        fixture.timeout_ms = u64::MAX;
        assert_eq!(
            EngineLimits::from_manifest(&fixture, &root, &cwd, NetworkAccessPolicy::Deny),
            Err(EngineLimitsError::TimeoutAboveMaximum {
                value: u64::MAX,
                max: MAX_ENGINE_TIMEOUT_MS,
            })
        );

        fixture = manifest("fixture");
        fixture.max_stdout_bytes = u64::MAX;
        assert_eq!(
            EngineLimits::from_manifest(&fixture, &root, &cwd, NetworkAccessPolicy::Deny),
            Err(EngineLimitsError::StdoutCapAboveMaximum {
                value: u64::MAX,
                max: MAX_ENGINE_STDOUT_BYTES,
            })
        );

        fixture = manifest("fixture");
        fixture.max_stderr_bytes = u64::MAX;
        assert_eq!(
            EngineLimits::from_manifest(&fixture, &root, &cwd, NetworkAccessPolicy::Deny),
            Err(EngineLimitsError::StderrCapAboveMaximum {
                value: u64::MAX,
                max: MAX_ENGINE_STDERR_BYTES,
            })
        );
    }

    #[test]
    fn limits_canonicalize_workspace_and_reject_bad_environment() {
        let fixture = manifest("fixture");
        let limits = limits(&fixture);
        assert!(limits.workspace_root().is_absolute());
        assert!(limits.working_directory().starts_with(limits.workspace_root()));
        assert_eq!(limits.wall_clock_timeout(), Duration::from_millis(2_500));

        let (root, cwd) = workspace("environment");
        for invalid in [" PATH", "PATH=/tmp", "PATH\n"] {
            let mut bad = manifest("fixture");
            bad.allowed_environment_names = vec![invalid.to_owned()];
            assert_eq!(
                EngineLimits::from_manifest(&bad, &root, &cwd, NetworkAccessPolicy::Deny),
                Err(EngineLimitsError::InvalidEnvironmentName(invalid.to_owned()))
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn limits_reject_symlink_workspace_escape() {
        use std::os::unix::fs::symlink;

        let root = unique_temp_path("symlink-root");
        let outside = unique_temp_path("symlink-outside");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&outside).expect("outside");
        let escaped = root.join("escaped");
        symlink(&outside, &escaped).expect("symlink");
        assert_eq!(
            EngineLimits::from_manifest(
                &manifest("fixture"),
                &root,
                &escaped,
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
            .expect("register");
        let engine = registry.get("fixture").expect("registered adapter");
        let request = EngineRequest::new(
            "request",
            vec![EngineScope::new("repository", ".").expect("scope")],
            Vec::new(),
        )
        .expect("request");
        let _future: EngineRunFuture<'_> = engine.run(request, fixture_limits);
        assert_eq!(
            registry.register(Arc::new(FixtureEngine {
                manifest: manifest("fixture"),
            })),
            Err(EngineRegistryError::DuplicateEngineId("fixture".to_owned()))
        );
    }
}
