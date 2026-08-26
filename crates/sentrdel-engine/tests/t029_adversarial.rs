use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs, io,
    io::Write,
    path::PathBuf,
    process::{self, Command},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

use sentrdel_engine::{
    EngineAdapterError, EngineLimits, EngineOutputDialect, EngineProcessOutcome, EngineProcessSpec,
    NetworkAccessPolicy, RepoLocationError, TrustedExecutable, TrustedExecutableError,
    adapt_engine_output, run_engine_process,
};
use sentrdel_schema::{
    engine::{EngineManifest, NetworkRequirement, TerminationReason},
    evidence::{EvidenceAuthority, ProducerKind},
};

const FIXTURE_MODE: &str = "SENTRDEL_T029_FIXTURE_MODE";
const FIXTURE_CHILD_ARG: &str = "--sentrdel-t029-fixture-child";
const CANARY_LAUNCHER_ARG: &str = "--sentrdel-t029-canary-launcher";
const SYNTHETIC_CANARY_VALUE: &str = "sentrdel-t029-synthetic-canary-not-a-secret";
const VALID_MINIMAL: &[u8] = include_bytes!("../../../fixtures/engines/native-valid-minimal.json");
const VALID_MULTIPLE: &[u8] =
    include_bytes!("../../../fixtures/engines/native-valid-multiple.json");
const VALID_EMPTY: &[u8] = include_bytes!("../../../fixtures/engines/native-empty.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/engines/native-malformed.json");
const OUT_OF_ROOT: &[u8] = include_bytes!("../../../fixtures/engines/native-out-of-root.json");
const UNSUPPORTED_SCHEMA: &[u8] =
    include_bytes!("../../../fixtures/engines/native-unsupported-schema.json");
const SENSITIVE_ENVIRONMENT_NAMES: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "HF_TOKEN",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "GPG_TTY",
    "GPG_PRIVATE_KEY",
    "CSC_LINK",
    "CSC_KEY_PASSWORD",
];

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

fn main() {
    if has_argument(FIXTURE_CHILD_ARG) {
        let mode = env::var(FIXTURE_MODE).expect("fixture mode must be explicitly supplied");
        fixture_engine_child(&mode);
        return;
    }

    if has_argument(CANARY_LAUNCHER_ARG) {
        synthetic_canary_launcher();
        return;
    }

    valid_native_fixture_corpus_uses_canonical_adapter();
    malformed_unsupported_and_out_of_root_use_canonical_adapter();
    flood_timeout_and_nonzero_are_explicit_process_outcomes();
    missing_executable_is_rejected_before_spawn();
    cloud_model_signing_and_ssh_credentials_are_absent_by_default();
}

fn has_argument(expected: &str) -> bool {
    env::args_os()
        .skip(1)
        .any(|argument| argument == OsStr::new(expected))
}

fn manifest(timeout_ms: u64, max_stdout_bytes: u64, max_stderr_bytes: u64) -> EngineManifest {
    EngineManifest {
        schema_version: "1".to_owned(),
        engine_id: "t029-fixture-engine".to_owned(),
        adapter_version: "1".to_owned(),
        executable_source: "trusted-t029-test-binary".to_owned(),
        executable_digest: None,
        expected_version_constraint: None,
        input_dialects: vec!["fixture".to_owned()],
        output_dialects: vec!["sentrdel-json-v1".to_owned()],
        capabilities: vec!["t029-adversarial-fixture".to_owned()],
        timeout_ms,
        max_stdout_bytes,
        max_stderr_bytes,
        allowed_environment_names: vec![FIXTURE_MODE.to_owned()],
        network_requirement: NetworkRequirement::None,
    }
}

fn authority() -> EvidenceAuthority {
    EvidenceAuthority::from_runtime(
        "t029-fixture-engine",
        "1",
        ProducerKind::ExternalEngine,
    )
    .expect("external engine authority")
}

fn workspace(label: &str) -> (PathBuf, PathBuf) {
    let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = env::temp_dir().join(format!("sentrdel-t029-{label}-{}-{id}", process::id()));
    let cwd = root.join("cwd");
    fs::create_dir_all(&cwd).expect("create T029 fixture workspace");
    (root, cwd)
}

fn limits_for(manifest: &EngineManifest, label: &str) -> EngineLimits {
    let (root, cwd) = workspace(label);
    EngineLimits::from_manifest(manifest, root, cwd, NetworkAccessPolicy::Deny)
        .expect("valid T029 fixture limits")
}

fn fixture_executable() -> TrustedExecutable {
    TrustedExecutable::resolve(
        "trusted-t029-test-binary",
        env::current_exe().expect("resolve current T029 harness executable"),
    )
    .expect("current T029 harness executable is a trusted fixture")
}

fn fixture_arguments() -> Vec<OsString> {
    vec![OsString::from(FIXTURE_CHILD_ARG)]
}

fn process_spec(mode: &str) -> EngineProcessSpec {
    EngineProcessSpec::new(
        fixture_executable(),
        fixture_arguments(),
        BTreeMap::from([(FIXTURE_MODE.to_owned(), OsString::from(mode))]),
    )
    .expect("valid T029 fixture process spec")
}

fn run_fixture(
    label: &str,
    mode: &str,
    timeout_ms: u64,
    max_stdout_bytes: u64,
) -> (EngineManifest, EngineLimits, EngineProcessOutcome) {
    let manifest = manifest(timeout_ms, max_stdout_bytes, 16_384);
    let limits = limits_for(&manifest, label);
    let outcome = run_engine_process(&manifest, &process_spec(mode), &limits)
        .expect("T029 fixture invocation should return an explicit outcome");
    (manifest, limits, outcome)
}

fn adapt_fixture(mode: &str, label: &str) -> Result<usize, EngineAdapterError> {
    let (manifest, limits, outcome) = run_fixture(label, mode, 2_000, 1024 * 1024);
    adapt_engine_output(
        &manifest,
        EngineOutputDialect::SentrdelJsonV1,
        &outcome,
        &authority(),
        &limits,
        &[],
        "2026-08-26T00:00:00Z",
    )
    .map(|evidence| evidence.len())
}

fn valid_native_fixture_corpus_uses_canonical_adapter() {
    assert_eq!(adapt_fixture("valid-minimal", "valid-minimal"), Ok(1));
    assert_eq!(adapt_fixture("valid-multiple", "valid-multiple"), Ok(2));
    assert_eq!(adapt_fixture("valid-empty", "valid-empty"), Ok(0));
}

fn malformed_unsupported_and_out_of_root_use_canonical_adapter() {
    assert_eq!(
        adapt_fixture("malformed", "malformed"),
        Err(EngineAdapterError::MalformedJson)
    );
    assert_eq!(
        adapt_fixture("unsupported-schema", "unsupported-schema"),
        Err(EngineAdapterError::UnsupportedNativeSchemaVersion(
            "2".to_owned()
        ))
    );
    assert_eq!(
        adapt_fixture("out-of-root", "out-of-root"),
        Err(EngineAdapterError::Location(
            RepoLocationError::ParentTraversal
        ))
    );
}

fn flood_timeout_and_nonzero_are_explicit_process_outcomes() {
    let (_, _, flood) = run_fixture("flood", "flood", 2_000, 128);
    assert_eq!(flood.termination_reason(), &TerminationReason::OutputCap);
    assert!(flood.stdout().len() <= 128);

    let (_, _, timeout) = run_fixture("timeout", "timeout", 80, 16_384);
    assert_eq!(timeout.termination_reason(), &TerminationReason::Timeout);

    let (_, _, nonzero) = run_fixture("nonzero", "nonzero", 2_000, 16_384);
    assert_eq!(nonzero.termination_reason(), &TerminationReason::NonZero);
    assert_eq!(nonzero.exit_status(), Some(23));
}

fn missing_executable_is_rejected_before_spawn() {
    let missing = env::temp_dir().join(format!(
        "sentrdel-t029-missing-executable-{}-{}",
        process::id(),
        NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    assert!(matches!(
        TrustedExecutable::resolve("trusted-t029-test-binary", missing),
        Err(TrustedExecutableError::NotCanonicalizable(
            _,
            io::ErrorKind::NotFound
        ))
    ));
}

fn cloud_model_signing_and_ssh_credentials_are_absent_by_default() {
    let mut launcher = Command::new(env::current_exe().expect("current T029 harness executable"));
    launcher.env_clear();
    launcher.arg(CANARY_LAUNCHER_ARG);
    launcher.env(FIXTURE_MODE, "launcher-env-probe");
    for name in SENSITIVE_ENVIRONMENT_NAMES {
        launcher.env(name, SYNTHETIC_CANARY_VALUE);
    }

    let output = launcher.output().expect("spawn synthetic-canary launcher");
    assert!(
        output.status.success(),
        "environment-scrub launcher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("launcher-proved-environment-scrub"),
        "launcher did not prove the engine environment boundary"
    );
}

fn synthetic_canary_launcher() {
    assert_eq!(
        env::var_os(FIXTURE_MODE).as_deref(),
        Some(OsStr::new("launcher-env-probe")),
        "launcher fixture mode was not explicitly supplied"
    );
    for name in SENSITIVE_ENVIRONMENT_NAMES {
        assert_eq!(
            env::var_os(name).as_deref(),
            Some(OsStr::new(SYNTHETIC_CANARY_VALUE)),
            "launcher is missing synthetic canary {name}"
        );
    }

    let manifest = manifest(2_000, 16_384, 16_384);
    let limits = limits_for(&manifest, "env-probe-child");
    let outcome = run_engine_process(&manifest, &process_spec("env-probe"), &limits)
        .expect("engine env probe should return an explicit outcome");
    assert_eq!(outcome.termination_reason(), &TerminationReason::Completed);
    assert!(
        String::from_utf8_lossy(outcome.stdout()).contains("sensitive-environment-absent"),
        "engine child did not confirm scrubbed environment"
    );
    println!("launcher-proved-environment-scrub");
}

fn fixture_engine_child(mode: &str) {
    match mode {
        "valid-minimal" => write_fixture(VALID_MINIMAL),
        "valid-multiple" => write_fixture(VALID_MULTIPLE),
        "valid-empty" => write_fixture(VALID_EMPTY),
        "malformed" => write_fixture(MALFORMED),
        "unsupported-schema" => write_fixture(UNSUPPORTED_SCHEMA),
        "out-of-root" => write_fixture(OUT_OF_ROOT),
        "flood" => write_fixture(&vec![b'x'; 16_384]),
        "timeout" => thread::sleep(Duration::from_millis(500)),
        "nonzero" => process::exit(23),
        "env-probe" => {
            for name in SENSITIVE_ENVIRONMENT_NAMES {
                assert!(
                    env::var_os(name).is_none(),
                    "engine inherited sensitive environment variable {name}"
                );
            }
            println!("sensitive-environment-absent");
        }
        other => panic!("unknown T029 fixture mode: {other}"),
    }
}

fn write_fixture(bytes: &[u8]) {
    let mut stdout = io::stdout();
    stdout.write_all(bytes).expect("write T029 fixture output");
    stdout.flush().expect("flush T029 fixture output");
}
