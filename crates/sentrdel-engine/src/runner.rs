//! T027 bounded external-engine process runner.
//!
//! This module is the only process-spawning implementation in the R1 trusted
//! core. It accepts only a canonical executable selected by trusted
//! user/system configuration, uses argv values without shell evaluation,
//! clears the inherited environment before adding explicitly allowlisted
//! entries, and bounds cwd, wall-clock time, stdout, and stderr.
//!
//! `NetworkAccessPolicy` is a declaration gate, not an OS network sandbox.
//! When network is denied, engines declaring OPTIONAL or REQUIRED network are
//! not started. T027 also does not claim process-tree isolation: a qualified
//! external engine remains a trust-boundary process. Reader collection is
//! nevertheless deadline-bounded so descendants cannot keep inherited pipes
//! open and make the Sentrdel runner wait past its wall-clock limit.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Sender, TryRecvError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use sentrdel_schema::engine::{EngineManifest, NetworkRequirement, TerminationReason};

use crate::{EngineLimits, NetworkAccessPolicy};

pub const MAX_ENGINE_ARGUMENTS: usize = 1_024;
pub const MAX_ENGINE_ARGUMENT_BYTES: usize = 1_048_576;
pub const MAX_ENGINE_ENVIRONMENT_ENTRIES: usize = 256;
pub const MAX_ENGINE_ENVIRONMENT_BYTES: usize = 262_144;

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const READER_CHUNK_BYTES: usize = 8_192;

/// Canonical executable identity admitted from trusted user/system
/// configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedExecutable {
    source_id: String,
    path: PathBuf,
}

impl TrustedExecutable {
    pub fn resolve(
        source_id: impl Into<String>,
        path: impl Into<PathBuf>,
    ) -> Result<Self, TrustedExecutableError> {
        let source_id = source_id.into();
        let path = path.into();

        if source_id.is_empty() {
            return Err(TrustedExecutableError::BlankSourceId);
        }
        if source_id.trim() != source_id || source_id.chars().any(char::is_control) {
            return Err(TrustedExecutableError::InvalidSourceId);
        }
        if !path.is_absolute() {
            return Err(TrustedExecutableError::PathNotAbsolute(path));
        }
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(TrustedExecutableError::ParentTraversal);
        }

        let canonical_path = fs::canonicalize(&path)
            .map_err(|error| TrustedExecutableError::NotCanonicalizable(path, error.kind()))?;
        if !canonical_path.is_file() {
            return Err(TrustedExecutableError::NotAFile(canonical_path));
        }

        Ok(Self {
            source_id,
            path: canonical_path,
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustedExecutableError {
    BlankSourceId,
    InvalidSourceId,
    PathNotAbsolute(PathBuf),
    ParentTraversal,
    NotCanonicalizable(PathBuf, io::ErrorKind),
    NotAFile(PathBuf),
}

impl fmt::Display for TrustedExecutableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankSourceId => formatter.write_str("trusted executable source id is blank"),
            Self::InvalidSourceId => formatter.write_str(
                "trusted executable source id must be normalized and free of control characters",
            ),
            Self::PathNotAbsolute(path) => {
                write!(
                    formatter,
                    "trusted executable path must be absolute: {path:?}"
                )
            }
            Self::ParentTraversal => {
                formatter.write_str("trusted executable path may not contain parent traversal")
            }
            Self::NotCanonicalizable(path, kind) => write!(
                formatter,
                "trusted executable path could not be canonicalized ({kind:?}): {path:?}"
            ),
            Self::NotAFile(path) => {
                write!(formatter, "trusted executable path is not a file: {path:?}")
            }
        }
    }
}

impl Error for TrustedExecutableError {}

/// Explicit argv/environment data for one process invocation.
///
/// Debug output intentionally omits argv values and environment values because
/// either may contain untrusted project text or credentials explicitly passed
/// by the trusted caller.
#[derive(Clone, PartialEq, Eq)]
pub struct EngineProcessSpec {
    executable: TrustedExecutable,
    arguments: Vec<OsString>,
    environment: BTreeMap<String, OsString>,
}

impl EngineProcessSpec {
    pub fn new(
        executable: TrustedExecutable,
        arguments: Vec<OsString>,
        environment: BTreeMap<String, OsString>,
    ) -> Result<Self, EngineProcessSpecError> {
        validate_argument_bounds(&arguments)?;
        validate_environment_bounds(&environment)?;
        Ok(Self {
            executable,
            arguments,
            environment,
        })
    }

    pub fn executable(&self) -> &TrustedExecutable {
        &self.executable
    }

    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub fn environment_names(&self) -> impl Iterator<Item = &str> {
        self.environment.keys().map(String::as_str)
    }
}

impl fmt::Debug for EngineProcessSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineProcessSpec")
            .field("executable_source_id", &self.executable.source_id())
            .field("argument_count", &self.arguments.len())
            .field(
                "environment_names",
                &self.environment.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineProcessSpecError {
    TooManyArguments { count: usize, max: usize },
    ArgumentsTooLarge { size: usize, max: usize },
    TooManyEnvironmentEntries { count: usize, max: usize },
    EnvironmentTooLarge { size: usize, max: usize },
    InvalidArgumentNul,
    InvalidEnvironmentName(String),
    InvalidEnvironmentValueNul(String),
}

impl fmt::Display for EngineProcessSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyArguments { count, max } => {
                write!(formatter, "engine argv count {count} exceeds cap {max}")
            }
            Self::ArgumentsTooLarge { size, max } => {
                write!(formatter, "engine argv size {size} exceeds cap {max}")
            }
            Self::TooManyEnvironmentEntries { count, max } => write!(
                formatter,
                "engine explicit environment count {count} exceeds cap {max}"
            ),
            Self::EnvironmentTooLarge { size, max } => write!(
                formatter,
                "engine explicit environment size {size} exceeds cap {max}"
            ),
            Self::InvalidArgumentNul => formatter.write_str("engine argv contains a NUL code unit"),
            Self::InvalidEnvironmentName(name) => {
                write!(
                    formatter,
                    "invalid explicit engine environment name: {name:?}"
                )
            }
            Self::InvalidEnvironmentValueNul(name) => write!(
                formatter,
                "explicit engine environment value contains a NUL code unit for name {name:?}"
            ),
        }
    }
}

impl Error for EngineProcessSpecError {}

/// Bounded raw process outcome. T028 owns parsing/adaptation of these bytes.
///
/// Debug intentionally reports only lengths, never captured raw bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct EngineProcessOutcome {
    termination_reason: TerminationReason,
    exit_status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    io_error_kind: Option<io::ErrorKind>,
}

impl EngineProcessOutcome {
    fn without_process(reason: TerminationReason, io_error_kind: Option<io::ErrorKind>) -> Self {
        Self {
            termination_reason: reason,
            exit_status: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            io_error_kind,
        }
    }

    fn without_capture(reason: TerminationReason, exit_status: Option<i32>) -> Self {
        Self {
            termination_reason: reason,
            exit_status,
            stdout: Vec::new(),
            stderr: Vec::new(),
            io_error_kind: None,
        }
    }

    pub fn termination_reason(&self) -> &TerminationReason {
        &self.termination_reason
    }

    pub fn exit_status(&self) -> Option<i32> {
        self.exit_status
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn io_error_kind(&self) -> Option<io::ErrorKind> {
        self.io_error_kind
    }
}

impl fmt::Debug for EngineProcessOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EngineProcessOutcome")
            .field("termination_reason", &self.termination_reason)
            .field("exit_status", &self.exit_status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("io_error_kind", &self.io_error_kind)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineOutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineProcessError {
    ManifestExecutableSourceMismatch,
    ManifestLimitsMismatch,
    ExecutableInsideWorkspace,
    EnvironmentNotAllowed(String),
    TimeoutOverflow,
    MissingPipe(EngineOutputStream),
    PipeReadFailed(EngineOutputStream, io::ErrorKind),
    TryWaitFailed(io::ErrorKind),
    KillFailed(io::ErrorKind),
    WaitFailed(io::ErrorKind),
    ReaderThreadPanicked(EngineOutputStream),
}

impl fmt::Display for EngineProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestExecutableSourceMismatch => {
                formatter.write_str("trusted executable source does not match the engine manifest")
            }
            Self::ManifestLimitsMismatch => {
                formatter.write_str("engine limits do not match the trusted engine manifest")
            }
            Self::ExecutableInsideWorkspace => formatter
                .write_str("trusted external engine executable may not resolve inside workspace"),
            Self::EnvironmentNotAllowed(name) => {
                write!(
                    formatter,
                    "engine environment name is not allowlisted: {name:?}"
                )
            }
            Self::TimeoutOverflow => {
                formatter.write_str("engine wall-clock timeout cannot be represented")
            }
            Self::MissingPipe(stream) => {
                write!(
                    formatter,
                    "engine {stream:?} pipe was not available after spawn"
                )
            }
            Self::PipeReadFailed(stream, kind) => {
                write!(formatter, "engine {stream:?} pipe read failed: {kind:?}")
            }
            Self::TryWaitFailed(kind) => {
                write!(formatter, "engine process status poll failed: {kind:?}")
            }
            Self::KillFailed(kind) => {
                write!(formatter, "engine process termination failed: {kind:?}")
            }
            Self::WaitFailed(kind) => {
                write!(formatter, "engine process wait failed: {kind:?}")
            }
            Self::ReaderThreadPanicked(stream) => {
                write!(formatter, "engine {stream:?} reader thread panicked")
            }
        }
    }
}

impl Error for EngineProcessError {}

/// Run one qualified external engine process with the T027 bounds.
pub fn run_engine_process(
    manifest: &EngineManifest,
    spec: &EngineProcessSpec,
    limits: &EngineLimits,
) -> Result<EngineProcessOutcome, EngineProcessError> {
    validate_manifest_binding(manifest, spec, limits)?;

    if limits.network_access_policy() == NetworkAccessPolicy::Deny
        && !matches!(limits.network_requirement(), NetworkRequirement::None)
    {
        return Ok(EngineProcessOutcome::without_process(
            TerminationReason::PolicyBlocked,
            None,
        ));
    }

    let deadline = Instant::now()
        .checked_add(limits.wall_clock_timeout())
        .ok_or(EngineProcessError::TimeoutOverflow)?;

    let mut command = Command::new(spec.executable.path());
    command
        .args(spec.arguments())
        .current_dir(limits.working_directory())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (name, value) in &spec.environment {
        command.env(name, value);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Ok(EngineProcessOutcome::without_process(
                TerminationReason::SpawnFailed,
                Some(error.kind()),
            ));
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = terminate_and_wait(&mut child);
            return Err(EngineProcessError::MissingPipe(EngineOutputStream::Stdout));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let _ = terminate_and_wait(&mut child);
            return Err(EngineProcessError::MissingPipe(EngineOutputStream::Stderr));
        }
    };

    let (event_tx, event_rx) = mpsc::channel();
    let stdout_reader = spawn_bounded_reader(
        stdout,
        limits.max_stdout_bytes(),
        EngineOutputStream::Stdout,
        event_tx.clone(),
    );
    let stderr_reader = spawn_bounded_reader(
        stderr,
        limits.max_stderr_bytes(),
        EngineOutputStream::Stderr,
        event_tx,
    );

    let (status, forced_reason) = monitor_child(&mut child, deadline, &event_rx)?;
    let captures = collect_readers_before_deadline(stdout_reader, stderr_reader, deadline)?;
    let Some((stdout_capture, stderr_capture)) = captures else {
        return Ok(EngineProcessOutcome::without_capture(
            forced_reason.unwrap_or(TerminationReason::Timeout),
            status.code(),
        ));
    };

    let output_capped = stdout_capture.capped || stderr_capture.capped;
    let termination_reason = match forced_reason {
        Some(reason) => reason,
        None if output_capped => TerminationReason::OutputCap,
        None if status.success() => TerminationReason::Completed,
        None => TerminationReason::NonZero,
    };

    Ok(EngineProcessOutcome {
        termination_reason,
        exit_status: status.code(),
        stdout: stdout_capture.bytes,
        stderr: stderr_capture.bytes,
        io_error_kind: None,
    })
}

fn validate_manifest_binding(
    manifest: &EngineManifest,
    spec: &EngineProcessSpec,
    limits: &EngineLimits,
) -> Result<(), EngineProcessError> {
    if manifest.executable_source != spec.executable.source_id() {
        return Err(EngineProcessError::ManifestExecutableSourceMismatch);
    }

    let manifest_environment = manifest
        .allowed_environment_names
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if limits.wall_clock_timeout() != Duration::from_millis(manifest.timeout_ms)
        || limits.max_stdout_bytes() != manifest.max_stdout_bytes
        || limits.max_stderr_bytes() != manifest.max_stderr_bytes
        || limits.allowed_environment_names() != &manifest_environment
        || limits.network_requirement() != &manifest.network_requirement
    {
        return Err(EngineProcessError::ManifestLimitsMismatch);
    }
    if spec.executable.path().starts_with(limits.workspace_root()) {
        return Err(EngineProcessError::ExecutableInsideWorkspace);
    }
    for name in spec.environment.keys() {
        if !limits.allowed_environment_names().contains(name) {
            return Err(EngineProcessError::EnvironmentNotAllowed(name.clone()));
        }
    }
    Ok(())
}

fn validate_argument_bounds(arguments: &[OsString]) -> Result<(), EngineProcessSpecError> {
    if arguments.len() > MAX_ENGINE_ARGUMENTS {
        return Err(EngineProcessSpecError::TooManyArguments {
            count: arguments.len(),
            max: MAX_ENGINE_ARGUMENTS,
        });
    }
    if arguments.iter().any(|value| os_str_contains_nul(value)) {
        return Err(EngineProcessSpecError::InvalidArgumentNul);
    }
    let size = arguments.iter().try_fold(0usize, |total, value| {
        total
            .checked_add(os_str_size(value))
            .ok_or(EngineProcessSpecError::ArgumentsTooLarge {
                size: usize::MAX,
                max: MAX_ENGINE_ARGUMENT_BYTES,
            })
    })?;
    if size > MAX_ENGINE_ARGUMENT_BYTES {
        return Err(EngineProcessSpecError::ArgumentsTooLarge {
            size,
            max: MAX_ENGINE_ARGUMENT_BYTES,
        });
    }
    Ok(())
}

fn validate_environment_bounds(
    environment: &BTreeMap<String, OsString>,
) -> Result<(), EngineProcessSpecError> {
    if environment.len() > MAX_ENGINE_ENVIRONMENT_ENTRIES {
        return Err(EngineProcessSpecError::TooManyEnvironmentEntries {
            count: environment.len(),
            max: MAX_ENGINE_ENVIRONMENT_ENTRIES,
        });
    }
    let mut size = 0usize;
    for (name, value) in environment {
        if name.is_empty()
            || name.trim() != name
            || name.contains('=')
            || name.chars().any(char::is_control)
        {
            return Err(EngineProcessSpecError::InvalidEnvironmentName(name.clone()));
        }
        if os_str_contains_nul(value) {
            return Err(EngineProcessSpecError::InvalidEnvironmentValueNul(
                name.clone(),
            ));
        }
        size = size
            .checked_add(name.len())
            .and_then(|total| total.checked_add(os_str_size(value)))
            .ok_or(EngineProcessSpecError::EnvironmentTooLarge {
                size: usize::MAX,
                max: MAX_ENGINE_ENVIRONMENT_BYTES,
            })?;
    }
    if size > MAX_ENGINE_ENVIRONMENT_BYTES {
        return Err(EngineProcessSpecError::EnvironmentTooLarge {
            size,
            max: MAX_ENGINE_ENVIRONMENT_BYTES,
        });
    }
    Ok(())
}

fn os_str_size(value: &OsStr) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().len()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().count().saturating_mul(2)
    }
    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().len()
    }
}

fn os_str_contains_nul(value: &OsStr) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().contains(&0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().any(|unit| unit == 0)
    }
    #[cfg(not(any(unix, windows)))]
    {
        value.to_string_lossy().contains('\0')
    }
}

#[derive(Debug)]
struct BoundedCapture {
    bytes: Vec<u8>,
    capped: bool,
}

#[derive(Clone, Copy, Debug)]
enum ReaderEvent {
    Capped,
    Failed(EngineOutputStream, io::ErrorKind),
}

fn spawn_bounded_reader<R>(
    mut reader: R,
    cap: u64,
    stream: EngineOutputStream,
    event_tx: Sender<ReaderEvent>,
) -> JoinHandle<Result<BoundedCapture, EngineProcessError>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0u8; READER_CHUNK_BYTES];
        loop {
            let read = match reader.read(&mut buffer) {
                Ok(read) => read,
                Err(error) => {
                    let _ = event_tx.send(ReaderEvent::Failed(stream, error.kind()));
                    return Err(EngineProcessError::PipeReadFailed(stream, error.kind()));
                }
            };
            if read == 0 {
                return Ok(BoundedCapture {
                    bytes,
                    capped: false,
                });
            }
            let remaining = cap.saturating_sub(bytes.len() as u64);
            if read as u64 > remaining {
                let keep = usize::try_from(remaining).unwrap_or(usize::MAX).min(read);
                bytes.extend_from_slice(&buffer[..keep]);
                let _ = event_tx.send(ReaderEvent::Capped);
                return Ok(BoundedCapture {
                    bytes,
                    capped: true,
                });
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
    })
}

fn monitor_child(
    child: &mut Child,
    deadline: Instant,
    event_rx: &mpsc::Receiver<ReaderEvent>,
) -> Result<(ExitStatus, Option<TerminationReason>), EngineProcessError> {
    loop {
        match event_rx.try_recv() {
            Ok(ReaderEvent::Capped) => {
                let status = terminate_and_wait(child)?;
                return Ok((status, Some(TerminationReason::OutputCap)));
            }
            Ok(ReaderEvent::Failed(stream, kind)) => {
                terminate_and_wait(child)?;
                return Err(EngineProcessError::PipeReadFailed(stream, kind));
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => {}
        }

        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, None)),
            Ok(None) => {}
            Err(error) => {
                let poll_error = error.kind();
                force_kill_and_wait(child)?;
                return Err(EngineProcessError::TryWaitFailed(poll_error));
            }
        }

        let now = Instant::now();
        if now >= deadline {
            let status = terminate_and_wait(child)?;
            return Ok((status, Some(TerminationReason::Timeout)));
        }
        thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn collect_readers_before_deadline(
    stdout: JoinHandle<Result<BoundedCapture, EngineProcessError>>,
    stderr: JoinHandle<Result<BoundedCapture, EngineProcessError>>,
    deadline: Instant,
) -> Result<Option<(BoundedCapture, BoundedCapture)>, EngineProcessError> {
    loop {
        if stdout.is_finished() && stderr.is_finished() {
            return Ok(Some((
                join_reader(stdout, EngineOutputStream::Stdout)?,
                join_reader(stderr, EngineOutputStream::Stderr)?,
            )));
        }

        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        thread::sleep(PROCESS_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn terminate_and_wait(child: &mut Child) -> Result<ExitStatus, EngineProcessError> {
    match child.try_wait() {
        Ok(Some(status)) => Ok(status),
        Ok(None) => force_kill_and_wait(child),
        Err(error) => {
            let poll_error = error.kind();
            force_kill_and_wait(child)?;
            Err(EngineProcessError::TryWaitFailed(poll_error))
        }
    }
}

fn force_kill_and_wait(child: &mut Child) -> Result<ExitStatus, EngineProcessError> {
    if let Err(error) = child.kill() {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => return Err(EngineProcessError::KillFailed(error.kind())),
            Err(wait_error) => {
                return Err(EngineProcessError::TryWaitFailed(wait_error.kind()));
            }
        }
    }
    child
        .wait()
        .map_err(|error| EngineProcessError::WaitFailed(error.kind()))
}

fn join_reader(
    handle: JoinHandle<Result<BoundedCapture, EngineProcessError>>,
    stream: EngineOutputStream,
) -> Result<BoundedCapture, EngineProcessError> {
    handle
        .join()
        .map_err(|_| EngineProcessError::ReaderThreadPanicked(stream))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, process,
        sync::atomic::{AtomicU64, Ordering},
    };

    const FIXTURE_MODE: &str = "SENTRDEL_T027_FIXTURE_MODE";
    const FORBIDDEN_ENV_NAME: &str = "SENTRDEL_T027_FORBIDDEN_ENV_NAME";
    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

    fn manifest(
        timeout_ms: u64,
        max_stdout_bytes: u64,
        max_stderr_bytes: u64,
        allowed_environment_names: Vec<String>,
    ) -> EngineManifest {
        EngineManifest {
            schema_version: "1".to_owned(),
            engine_id: "fixture-runner".to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-test-binary".to_owned(),
            executable_digest: None,
            expected_version_constraint: None,
            input_dialects: vec!["fixture".to_owned()],
            output_dialects: vec!["raw".to_owned()],
            capabilities: vec!["fixture".to_owned()],
            timeout_ms,
            max_stdout_bytes,
            max_stderr_bytes,
            allowed_environment_names,
            network_requirement: NetworkRequirement::None,
        }
    }

    fn workspace(label: &str) -> (PathBuf, PathBuf) {
        let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!("sentrdel-t027-{label}-{}-{id}", process::id()));
        let cwd = root.join("cwd");
        fs::create_dir_all(&cwd).expect("create T027 fixture workspace");
        (root, cwd)
    }

    fn fixture_executable() -> TrustedExecutable {
        TrustedExecutable::resolve(
            "trusted-test-binary",
            env::current_exe().expect("resolve current test executable"),
        )
        .expect("current test executable is trusted fixture")
    }

    fn fixture_arguments() -> Vec<OsString> {
        [
            "--ignored",
            "--exact",
            "runner::tests::fixture_child_process",
            "--nocapture",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    fn process_spec(mode: &str, extra: BTreeMap<String, OsString>) -> EngineProcessSpec {
        let mut environment = BTreeMap::new();
        environment.insert(FIXTURE_MODE.to_owned(), OsString::from(mode));
        environment.extend(extra);
        EngineProcessSpec::new(fixture_executable(), fixture_arguments(), environment)
            .expect("valid T027 fixture process spec")
    }

    fn limits_for(
        manifest: &EngineManifest,
        label: &str,
        network_access_policy: NetworkAccessPolicy,
    ) -> EngineLimits {
        let (root, cwd) = workspace(label);
        EngineLimits::from_manifest(manifest, root, cwd, network_access_policy)
            .expect("valid T027 fixture limits")
    }

    #[test]
    fn trusted_executable_requires_absolute_canonical_file_and_normalized_source() {
        assert_eq!(
            TrustedExecutable::resolve(" ", PathBuf::from("relative")),
            Err(TrustedExecutableError::InvalidSourceId)
        );
        let relative = PathBuf::from("relative");
        assert_eq!(
            TrustedExecutable::resolve("trusted", &relative),
            Err(TrustedExecutableError::PathNotAbsolute(relative))
        );
        let missing = env::temp_dir().join(format!(
            "sentrdel-t027-missing-executable-{}",
            process::id()
        ));
        assert!(matches!(
            TrustedExecutable::resolve("trusted", missing),
            Err(TrustedExecutableError::NotCanonicalizable(
                _,
                io::ErrorKind::NotFound
            ))
        ));
    }

    #[test]
    fn process_spec_is_bounded_and_debug_never_exposes_environment_values() {
        let executable = fixture_executable();
        let environment = BTreeMap::from([(
            "VISIBLE_NAME".to_owned(),
            OsString::from("super-secret-environment-value"),
        )]);
        let spec = EngineProcessSpec::new(
            executable.clone(),
            vec![OsString::from("argument-secret-value")],
            environment,
        )
        .expect("bounded process spec");
        let debug = format!("{spec:?}");
        assert!(debug.contains("VISIBLE_NAME"));
        assert!(!debug.contains("super-secret-environment-value"));
        assert!(!debug.contains("argument-secret-value"));

        let invalid_environment =
            BTreeMap::from([("BAD\nNAME".to_owned(), OsString::from("value"))]);
        assert_eq!(
            EngineProcessSpec::new(executable, Vec::new(), invalid_environment),
            Err(EngineProcessSpecError::InvalidEnvironmentName(
                "BAD\nNAME".to_owned()
            ))
        );
    }

    #[test]
    fn runner_rejects_source_unallowlisted_environment_and_workspace_executable() {
        let manifest = manifest(1_000, 8_192, 8_192, vec![FIXTURE_MODE.to_owned()]);
        let limits = limits_for(&manifest, "preflight", NetworkAccessPolicy::Deny);
        let spec = process_spec("ok", BTreeMap::new());

        let mut mismatched = manifest.clone();
        mismatched.executable_source = "other-trusted-source".to_owned();
        assert_eq!(
            run_engine_process(&mismatched, &spec, &limits),
            Err(EngineProcessError::ManifestExecutableSourceMismatch)
        );

        let disallowed_spec = process_spec(
            "ok",
            BTreeMap::from([("NOT_ALLOWED".to_owned(), OsString::from("value"))]),
        );
        assert_eq!(
            run_engine_process(&manifest, &disallowed_spec, &limits),
            Err(EngineProcessError::EnvironmentNotAllowed(
                "NOT_ALLOWED".to_owned()
            ))
        );

        let executable_copy = limits.workspace_root().join("engine-fixture");
        fs::copy(spec.executable.path(), &executable_copy).expect("copy engine fixture");
        let workspace_executable =
            TrustedExecutable::resolve("trusted-test-binary", &executable_copy)
                .expect("resolve copied fixture");
        let workspace_spec =
            EngineProcessSpec::new(workspace_executable, fixture_arguments(), BTreeMap::new())
                .expect("workspace executable spec");
        assert_eq!(
            run_engine_process(&manifest, &workspace_spec, &limits),
            Err(EngineProcessError::ExecutableInsideWorkspace)
        );
    }

    #[test]
    fn denied_declared_network_fails_closed_without_spawn() {
        let mut manifest = manifest(1_000, 8_192, 8_192, vec![FIXTURE_MODE.to_owned()]);
        manifest.network_requirement = NetworkRequirement::Optional;
        let limits = limits_for(&manifest, "network", NetworkAccessPolicy::Deny);
        let outcome = run_engine_process(&manifest, &process_spec("ok", BTreeMap::new()), &limits)
            .expect("policy block is an explicit process outcome");
        assert_eq!(
            outcome.termination_reason(),
            &TerminationReason::PolicyBlocked
        );
        assert_eq!(outcome.exit_status(), None);
    }

    #[test]
    fn runner_scrubs_environment_and_reports_completed_and_nonzero() {
        let inherited_name = env::vars_os()
            .map(|(name, _)| name)
            .find(|name| name != OsStr::new(FIXTURE_MODE) && name != OsStr::new(FORBIDDEN_ENV_NAME))
            .expect("test process should expose an inherited environment name");
        let manifest = manifest(
            2_000,
            16_384,
            16_384,
            vec![FIXTURE_MODE.to_owned(), FORBIDDEN_ENV_NAME.to_owned()],
        );
        let limits = limits_for(&manifest, "environment", NetworkAccessPolicy::Deny);
        let environment = BTreeMap::from([(FORBIDDEN_ENV_NAME.to_owned(), inherited_name.clone())]);
        let outcome = run_engine_process(&manifest, &process_spec("env", environment), &limits)
            .expect("environment fixture should run");
        assert_eq!(outcome.termination_reason(), &TerminationReason::Completed);
        assert_eq!(outcome.exit_status(), Some(0));

        let nonzero = run_engine_process(
            &manifest,
            &process_spec(
                "nonzero",
                BTreeMap::from([(FORBIDDEN_ENV_NAME.to_owned(), inherited_name)]),
            ),
            &limits,
        )
        .expect("non-zero is an explicit outcome");
        assert_eq!(nonzero.termination_reason(), &TerminationReason::NonZero);
        assert_eq!(nonzero.exit_status(), Some(23));
    }

    #[test]
    fn runner_enforces_wall_clock_output_caps_and_pipe_drain_deadline() {
        let timeout_manifest = manifest(25, 16_384, 16_384, vec![FIXTURE_MODE.to_owned()]);
        let timeout_limits = limits_for(&timeout_manifest, "timeout", NetworkAccessPolicy::Deny);
        let timeout = run_engine_process(
            &timeout_manifest,
            &process_spec("timeout", BTreeMap::new()),
            &timeout_limits,
        )
        .expect("timeout should be an explicit outcome");
        assert_eq!(timeout.termination_reason(), &TerminationReason::Timeout);

        let flood_manifest = manifest(2_000, 128, 16_384, vec![FIXTURE_MODE.to_owned()]);
        let flood_limits = limits_for(&flood_manifest, "flood", NetworkAccessPolicy::Deny);
        let flood = run_engine_process(
            &flood_manifest,
            &process_spec("flood", BTreeMap::new()),
            &flood_limits,
        )
        .expect("output cap should be an explicit outcome");
        assert_eq!(flood.termination_reason(), &TerminationReason::OutputCap);
        assert!(flood.stdout().len() <= 128);

        let descendant_manifest = manifest(75, 16_384, 16_384, vec![FIXTURE_MODE.to_owned()]);
        let descendant_limits = limits_for(
            &descendant_manifest,
            "descendant",
            NetworkAccessPolicy::Deny,
        );
        let started = Instant::now();
        let descendant = run_engine_process(
            &descendant_manifest,
            &process_spec("spawn-pipe-holder", BTreeMap::new()),
            &descendant_limits,
        )
        .expect("descendant-held pipes should remain deadline bounded");
        assert_eq!(descendant.termination_reason(), &TerminationReason::Timeout);
        assert!(started.elapsed() < Duration::from_millis(300));
    }

    #[test]
    #[ignore = "invoked only as a subprocess fixture by T027 runner tests"]
    fn fixture_child_process() {
        let mode = env::var(FIXTURE_MODE).expect("fixture mode must be explicitly allowlisted");
        match mode.as_str() {
            "ok" => println!("fixture-ok"),
            "env" => {
                let forbidden_name =
                    env::var_os(FORBIDDEN_ENV_NAME).expect("forbidden env name must be supplied");
                assert!(
                    env::var_os(&forbidden_name).is_none(),
                    "runner inherited an environment variable that was not explicitly allowlisted"
                );
                println!("environment-scrubbed");
            }
            "nonzero" => process::exit(23),
            "timeout" => thread::sleep(Duration::from_millis(500)),
            "flood" => {
                use std::io::Write;
                let payload = vec![b'x'; 16_384];
                let mut stdout = io::stdout();
                stdout.write_all(&payload).expect("write flood fixture");
                stdout.flush().expect("flush flood fixture");
            }
            "spawn-pipe-holder" => {
                let mut descendant = Command::new(env::current_exe().expect("current test executable"))
                    .args(fixture_arguments())
                    .env(FIXTURE_MODE, "hold-pipes")
                    .spawn()
                    .expect("spawn descendant pipe-holder fixture");
                thread::spawn(move || {
                    let _ = descendant.wait();
                });
            }
            "hold-pipes" => thread::sleep(Duration::from_millis(500)),
            other => panic!("unknown T027 fixture mode: {other}"),
        }
    }
}
