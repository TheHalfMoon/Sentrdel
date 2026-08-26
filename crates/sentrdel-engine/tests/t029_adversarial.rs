use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs, io,
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
const SYNTHETIC_CANARY_VALUE: &str = "sentrdel-t029-synthetic-canary-not-a-secret";
const CAPTURED_AT: &str = "2026-08-26T00:00:00Z";
const INPUT_DIGEST: &str = "sha256:t029-fixture-input";
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
        env::current_exe().expect("resolve current integration-test executable"),
    )
    .expect("current integration-test executable is a trusted fixture")
}

fn fixture_arguments() -> Vec<OsString> {
    [
        "--ignored",
        "--exact",
        "fixture_engine_child",
        "--nocapture",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
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

fn authority() -> EvidenceAuthority {
    EvidenceAuthority::from_runtime("t029-fixture-engine", "1", ProducerKind::ExternalEngine)
        .expect("fixture authority")
}

fn adapt(
    manifest: &EngineManifest,
    limits: &EngineLimits,
    outcome: &EngineProcessOutcome,
) -> Result<Vec<sentrdel_schema::evidence::Evidence>, EngineAdapterError> {
    adapt_engine_output(
        manifest,
        EngineOutputDialect::SentrdelJsonV1,
        outcome,
        &authority(),
        limits,
        &[INPUT_DIGEST.to_owned()],
        CAPTURED_AT,
    )
}

#[test]
fn valid_minimal_multiple_and_empty_fixtures_are_deterministic() {
    let (manifest, limits, minimal) = run_fixture("minimal", "valid-minimal", 2_000, 16_384);
    assert_eq!(minimal.termination_reason(), &TerminationReason::Completed);
    assert_eq!(
        adapt(&manifest, &limits, &minimal)
            .expect("minimal fixture")
            .len(),
        1
    );

    let (manifest, limits, multiple) = run_fixture("multiple", "valid-multiple", 2_000, 16_384);
    assert_eq!(multiple.termination_reason(), &TerminationReason::Completed);
    assert_eq!(
        adapt(&manifest, &limits, &multiple)
            .expect("multiple fixture")
            .len(),
        2
    );

    let (manifest, limits, empty) = run_fixture("empty", "valid-empty", 2_000, 16_384);
    assert_eq!(empty.termination_reason(), &TerminationReason::Completed);
    assert!(
        adapt(&manifest, &limits, &empty)
            .expect("empty fixture")
            .is_empty()
    );
}

#[test]
fn malformed_and_unsupported_native_results_never_become_evidence() {
    let (manifest, limits, malformed) = run_fixture("malformed", "malformed", 2_000, 16_384);
    assert_eq!(
        malformed.termination_reason(),
        &TerminationReason::Completed
    );
    assert_eq!(
        adapt(&manifest, &limits, &malformed),
        Err(EngineAdapterError::MalformedJson)
    );

    let (manifest, limits, unsupported) =
        run_fixture("unsupported-schema", "unsupported-schema", 2_000, 16_384);
    assert_eq!(
        unsupported.termination_reason(),
        &TerminationReason::Completed
    );
    assert_eq!(
        adapt(&manifest, &limits, &unsupported),
        Err(EngineAdapterError::UnsupportedNativeSchemaVersion(
            "2".to_owned()
        ))
    );
}

#[test]
fn out_of_root_engine_location_fails_closed() {
    let (manifest, limits, outcome) = run_fixture("out-of-root", "out-of-root", 2_000, 16_384);
    assert_eq!(outcome.termination_reason(), &TerminationReason::Completed);
    assert_eq!(
        adapt(&manifest, &limits, &outcome),
        Err(EngineAdapterError::Location(
            RepoLocationError::ParentTraversal
        ))
    );
}

#[test]
fn flood_timeout_and_nonzero_are_explicit_and_not_adapted() {
    let (manifest, limits, flood) = run_fixture("flood", "flood", 2_000, 128);
    assert_eq!(flood.termination_reason(), &TerminationReason::OutputCap);
    assert!(flood.stdout().len() <= 128);
    assert_eq!(
        adapt(&manifest, &limits, &flood),
        Err(EngineAdapterError::ProcessNotCompleted(
            TerminationReason::OutputCap
        ))
    );

    let (manifest, limits, timeout) = run_fixture("timeout", "timeout", 80, 16_384);
    assert_eq!(timeout.termination_reason(), &TerminationReason::Timeout);
    assert_eq!(
        adapt(&manifest, &limits, &timeout),
        Err(EngineAdapterError::ProcessNotCompleted(
            TerminationReason::Timeout
        ))
    );

    let (manifest, limits, nonzero) = run_fixture("nonzero", "nonzero", 2_000, 16_384);
    assert_eq!(nonzero.termination_reason(), &TerminationReason::NonZero);
    assert_eq!(nonzero.exit_status(), Some(23));
    assert_eq!(
        adapt(&manifest, &limits, &nonzero),
        Err(EngineAdapterError::ProcessNotCompleted(
            TerminationReason::NonZero
        ))
    );
}

#[test]
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

#[test]
fn cloud_model_signing_and_ssh_credentials_are_absent_by_default() {
    let mut launcher = Command::new(env::current_exe().expect("current test executable"));
    launcher.args(fixture_arguments());
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

#[test]
#[ignore = "invoked only as a subprocess fixture by T029 adversarial tests"]
fn fixture_engine_child() {
    let mode = env::var(FIXTURE_MODE).expect("fixture mode must be explicitly supplied");
    match mode.as_str() {
        "valid-minimal" => print!(
            "{}",
            include_str!("../../../fixtures/engines/native-valid-minimal.json")
        ),
        "valid-multiple" => print!(
            "{}",
            include_str!("../../../fixtures/engines/native-valid-multiple.json")
        ),
        "valid-empty" => print!(
            "{}",
            include_str!("../../../fixtures/engines/native-empty.json")
        ),
        "malformed" => print!(
            "{}",
            include_str!("../../../fixtures/engines/native-malformed.json")
        ),
        "out-of-root" => print!(
            "{}",
            include_str!("../../../fixtures/engines/native-out-of-root.json")
        ),
        "unsupported-schema" => print!(
            "{}",
            include_str!("../../../fixtures/engines/native-unsupported-schema.json")
        ),
        "flood" => {
            use std::io::Write;
            let payload = vec![b'x'; 16_384];
            let mut stdout = io::stdout();
            stdout.write_all(&payload).expect("write flood fixture");
            stdout.flush().expect("flush flood fixture");
        }
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
        "launcher-env-probe" => {
            for name in SENSITIVE_ENVIRONMENT_NAMES {
                assert_eq!(
                    env::var_os(name).as_deref(),
                    Some(std::ffi::OsStr::new(SYNTHETIC_CANARY_VALUE)),
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
        other => panic!("unknown T029 fixture mode: {other}"),
    }
}
