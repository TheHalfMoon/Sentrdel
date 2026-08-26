use std::{
    collections::BTreeMap,
    env,
    ffi::{OsStr, OsString},
    fs, io,
    io::Write,
    path::PathBuf,
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use sentrdel_engine::{
    ENGINE_MALFORMED_OUTPUT_REASON, ENGINE_NON_ZERO_REASON, EngineAdapterError,
    EngineCoverageContext, EngineCoverageError, EngineCoverageOutcome, EngineLimits,
    EngineOutputDialect, EngineProcessOutcome, EngineProcessSpec, NetworkAccessPolicy,
    TrustedExecutable, finalize_engine_coverage, run_engine_process,
};
use sentrdel_schema::{
    coverage::CoverageState,
    engine::{EngineManifest, NetworkRequirement, TerminationReason},
    evidence::{EvidenceAuthority, ProducerKind},
};

const FIXTURE_MODE: &str = "SENTRDEL_T030_FIXTURE_MODE";
const FIXTURE_CHILD_ARG: &str = "--sentrdel-t030-fixture-child";
const VALID_MINIMAL: &[u8] = include_bytes!("../../../fixtures/engines/native-valid-minimal.json");
const MALFORMED: &[u8] = include_bytes!("../../../fixtures/engines/native-malformed.json");

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

fn main() {
    if has_argument(FIXTURE_CHILD_ARG) {
        let mode = env::var(FIXTURE_MODE).expect("fixture mode must be explicitly supplied");
        fixture_engine_child(&mode);
        return;
    }

    accepted_completed_output_is_covered_only_after_t028_accepts();
    rejected_completed_output_is_explicit_failed_gap();
    non_completed_outcome_preserves_explicit_gap();
    undeclared_capability_fails_before_record_creation();
}

fn has_argument(expected: &str) -> bool {
    env::args_os()
        .skip(1)
        .any(|argument| argument == OsStr::new(expected))
}

fn manifest() -> EngineManifest {
    EngineManifest {
        schema_version: "1".to_owned(),
        engine_id: "t030-fixture-engine".to_owned(),
        adapter_version: "1".to_owned(),
        executable_source: "trusted-t030-test-binary".to_owned(),
        executable_digest: None,
        expected_version_constraint: None,
        input_dialects: vec!["fixture".to_owned()],
        output_dialects: vec!["sentrdel-json-v1".to_owned()],
        capabilities: vec!["t030-finalizer-fixture".to_owned()],
        timeout_ms: 2_000,
        max_stdout_bytes: 1024 * 1024,
        max_stderr_bytes: 16_384,
        allowed_environment_names: vec![FIXTURE_MODE.to_owned()],
        network_requirement: NetworkRequirement::None,
    }
}

fn authority() -> EvidenceAuthority {
    EvidenceAuthority::from_runtime("t030-fixture-engine", "1", ProducerKind::ExternalEngine)
        .expect("external engine authority")
}

fn canonical_digest() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn coverage_context(capability: &str) -> EngineCoverageContext {
    EngineCoverageContext::new(
        "coverage:t030-finalizer",
        capability,
        ".",
        vec![canonical_digest()],
        "2026-08-26T00:00:00Z",
    )
    .expect("valid T030 coverage context")
}

fn workspace(label: &str) -> (PathBuf, PathBuf) {
    let id = NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
    let root = env::temp_dir().join(format!("sentrdel-t030-{label}-{}-{id}", process::id()));
    let cwd = root.join("cwd");
    fs::create_dir_all(&cwd).expect("create T030 fixture workspace");
    (root, cwd)
}

fn limits_for(manifest: &EngineManifest, label: &str) -> EngineLimits {
    let (root, cwd) = workspace(label);
    EngineLimits::from_manifest(manifest, root, cwd, NetworkAccessPolicy::Deny)
        .expect("valid T030 fixture limits")
}

fn fixture_executable() -> TrustedExecutable {
    TrustedExecutable::resolve(
        "trusted-t030-test-binary",
        env::current_exe().expect("resolve current T030 harness executable"),
    )
    .expect("current T030 harness executable is a trusted fixture")
}

fn process_spec(mode: &str) -> EngineProcessSpec {
    EngineProcessSpec::new(
        fixture_executable(),
        vec![OsString::from(FIXTURE_CHILD_ARG)],
        BTreeMap::from([(FIXTURE_MODE.to_owned(), OsString::from(mode))]),
    )
    .expect("valid T030 fixture process spec")
}

fn run_fixture(label: &str, mode: &str) -> (EngineManifest, EngineLimits, EngineProcessOutcome) {
    let manifest = manifest();
    let limits = limits_for(&manifest, label);
    let outcome = run_engine_process(&manifest, &process_spec(mode), &limits)
        .expect("T030 fixture invocation should return an explicit outcome");
    (manifest, limits, outcome)
}

fn accepted_completed_output_is_covered_only_after_t028_accepts() {
    let (manifest, limits, outcome) = run_fixture("accepted", "valid-minimal");
    assert_eq!(outcome.termination_reason(), &TerminationReason::Completed);

    let finalized = finalize_engine_coverage(
        &manifest,
        EngineOutputDialect::SentrdelJsonV1,
        &outcome,
        &authority(),
        &limits,
        &coverage_context("t030-finalizer-fixture"),
    )
    .expect("accepted T028 output should finalize");

    match finalized {
        EngineCoverageOutcome::Covered { evidence, coverage } => {
            assert_eq!(evidence.len(), 1);
            assert_eq!(coverage.state, CoverageState::Covered);
            assert_eq!(coverage.reason_code, None);
            assert!(!coverage.is_gap());
        }
        other => panic!("accepted T028 output must be Covered, got {other:?}"),
    }
}

fn rejected_completed_output_is_explicit_failed_gap() {
    let (manifest, limits, outcome) = run_fixture("rejected", "malformed");
    assert_eq!(outcome.termination_reason(), &TerminationReason::Completed);

    let finalized = finalize_engine_coverage(
        &manifest,
        EngineOutputDialect::SentrdelJsonV1,
        &outcome,
        &authority(),
        &limits,
        &coverage_context("t030-finalizer-fixture"),
    )
    .expect("adapter rejection must still finalize explicit coverage");

    match finalized {
        EngineCoverageOutcome::RejectedOutput {
            coverage,
            adapter_error,
        } => {
            assert_eq!(coverage.state, CoverageState::Failed);
            assert_eq!(
                coverage.reason_code.as_deref(),
                Some(ENGINE_MALFORMED_OUTPUT_REASON)
            );
            assert!(coverage.is_gap());
            assert_eq!(adapter_error, EngineAdapterError::MalformedJson);
        }
        other => panic!("rejected T028 output must be an explicit failed gap, got {other:?}"),
    }
}

fn non_completed_outcome_preserves_explicit_gap() {
    let (manifest, limits, outcome) = run_fixture("nonzero", "nonzero");
    assert_eq!(outcome.termination_reason(), &TerminationReason::NonZero);

    let finalized = finalize_engine_coverage(
        &manifest,
        EngineOutputDialect::SentrdelJsonV1,
        &outcome,
        &authority(),
        &limits,
        &coverage_context("t030-finalizer-fixture"),
    )
    .expect("non-completed outcome must finalize explicit coverage");

    match finalized {
        EngineCoverageOutcome::TerminationGap { coverage } => {
            assert_eq!(coverage.state, CoverageState::Failed);
            assert_eq!(
                coverage.reason_code.as_deref(),
                Some(ENGINE_NON_ZERO_REASON)
            );
            assert!(coverage.is_gap());
        }
        other => panic!("non-completed outcome must remain a termination gap, got {other:?}"),
    }
}

fn undeclared_capability_fails_before_record_creation() {
    let (manifest, limits, outcome) = run_fixture("undeclared", "valid-minimal");

    let result = finalize_engine_coverage(
        &manifest,
        EngineOutputDialect::SentrdelJsonV1,
        &outcome,
        &authority(),
        &limits,
        &coverage_context("not-declared"),
    );

    assert!(matches!(
        result,
        Err(EngineCoverageError::UndeclaredCapability(capability))
            if capability == "not-declared"
    ));
}

fn fixture_engine_child(mode: &str) {
    match mode {
        "valid-minimal" => write_fixture(VALID_MINIMAL),
        "malformed" => write_fixture(MALFORMED),
        "nonzero" => process::exit(23),
        other => panic!("unknown T030 fixture mode: {other}"),
    }
}

fn write_fixture(bytes: &[u8]) {
    let mut stdout = io::stdout();
    stdout.write_all(bytes).expect("write T030 fixture output");
    stdout.flush().expect("flush T030 fixture output");
}
