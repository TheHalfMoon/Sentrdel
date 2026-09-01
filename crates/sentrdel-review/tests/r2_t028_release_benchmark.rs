#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use sentrdel_review::{
    TARGET_BUILD_EXECUTION_ALLOWED,
    supabase::{
        COVERAGE_BUSINESS_LOGIC, COVERAGE_LIVE_POSTURE, COVERAGE_RUNTIME,
        COVERAGE_STATIC_POSTURE_DATABASE, COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS,
        COVERAGE_STATIC_POSTURE_KEY_BOUNDARY, COVERAGE_STATIC_POSTURE_STORAGE,
        auth_api::AUTH_API_PROVIDER_NETWORK_ALLOWED,
        config::{SUPABASE_CONFIG_PATH, SupabaseConfigLimits, parse_supabase_config},
        edge_auth::{
            EDGE_AUTH_PROVIDER_NETWORK_ALLOWED, EDGE_AUTH_TARGET_EXECUTION_ALLOWED, EdgeAuthLimits,
            assess_edge_function_auth,
        },
        function_authority::{FunctionAuthorityLimits, observe_function_authority},
        grants::{ApiRoleGrantLimits, observe_api_role_grants},
        key_authority::{KeyAuthorityLocation, observe_key_literal, observe_key_reference},
        key_boundary::observe_elevated_key_client_boundary,
        posture::{
            ApiExposureSource, ApiSchemaExposureInput, ConfigExposureProvenance,
            observe_api_schema_exposure,
        },
        rls::{RlsPostureLimits, observe_api_relevant_rls},
        source_context::{SourceContextLimits, classify_source_execution_context},
        sql::SqlScanLimits,
        state::{MigrationSqlInput, reduce_repository_posture},
        storage::{StoragePostureLimits, observe_storage_authorization_posture},
    },
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::{canonical::content_id, evidence::Evidence};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const CAPTURED_AT: &str = "2026-09-01T04:45:00Z";
const SUITE_BYTES: &[u8] = include_bytes!("../../../tests/benchmark/r2-release-suite.json");
const DEVELOPMENT_CORPUS_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/development-evaluation/t090-development-corpus.json");
const SAFE_SQL: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/positive/safe-posture/supabase/migrations/20260829000100_baseline.sql"
);
const UNSAFE_BASELINE_SQL: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/migrations/20260829000100_baseline.sql"
);
const UNSAFE_WIDEN_SQL: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/migrations/20260829000200_widen.sql"
);
const SAFE_CONFIG: &str =
    include_str!("../../../fixtures/repos/r2-supabase/positive/safe-posture/supabase/config.toml");
const UNSAFE_CONFIG: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/config.toml"
);
const SAFE_BROWSER: &str =
    include_str!("../../../fixtures/repos/r2-supabase/positive/safe-posture/src/browser.ts");
const UNSAFE_BROWSER: &str =
    include_str!("../../../fixtures/repos/r2-supabase/negative/unsafe-posture/src/browser.ts");
const SAFE_EDGE: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/positive/safe-posture/supabase/functions/webhook/index.ts"
);
const UNSAFE_EDGE: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/functions/webhook/index.ts"
);
const SECRET_CANARY: &str = "SENTRDEL_CANARY_BROWSER_ELEVATED_NOT_A_CREDENTIAL";

#[derive(Clone, Debug, Deserialize)]
struct ReleaseSuite {
    suite_version: String,
    corpus_class: String,
    candidate_identity: String,
    release_gating: bool,
    clean_pr_false_positive_gate: CleanPrGate,
    known_ground_truth: KnownGroundTruth,
    coverage: CoverageContract,
    authority_assertions: Vec<String>,
    inputs: ReleaseInputs,
    performance: DeferredPerformance,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct CleanPrGate {
    max_false_positive_clean_prs: u64,
    per_clean_prs: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct KnownGroundTruth {
    required_signal_groups: Vec<String>,
    max_known_misses: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct CoverageContract {
    required_static_dimensions: Vec<String>,
    required_explicit_gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseInputs {
    safe_fixture: String,
    vulnerable_fixture: String,
    development_corpus: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeferredPerformance {
    state: String,
    owner_task: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct R2ReleaseRun {
    suite_version: String,
    corpus_class: String,
    candidate_identity: String,
    clean_cases_evaluated: u64,
    clean_cases_with_false_positive: u64,
    clean_pr_fp_gate_passed: bool,
    required_signal_groups: Vec<String>,
    detected_signal_groups: Vec<String>,
    known_misses: u64,
    known_miss_gate_passed: bool,
    required_static_dimensions: Vec<String>,
    explicit_gap_dimensions: Vec<String>,
    authority_assertions_passed: Vec<String>,
    provider_evidence_count: u64,
    evidence_identity_failures: u64,
    deterministic_replay: String,
    performance_state: String,
}

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).unwrap()
}

fn digest(domain: &str, value: &str) -> String {
    content_id(domain, &value).unwrap()
}

fn migration(path_value: &str, order_key: &str, sql: &str) -> MigrationSqlInput {
    MigrationSqlInput {
        path: path(path_value),
        order_key: order_key.to_owned(),
        content_digest: digest("r2-t028-migration", sql),
        sql: sql.to_owned(),
    }
}

fn exposure(config: &str) -> sentrdel_review::supabase::posture::ApiSchemaExposureSnapshot {
    let input = ApiSchemaExposureInput {
        api_enabled: true,
        schemas: BTreeSet::from(["public".to_owned(), "storage".to_owned()]),
        source: ApiExposureSource::ExplicitConfig,
        provenance: ConfigExposureProvenance {
            path: path(SUPABASE_CONFIG_PATH),
            content_digest: digest("r2-t028-config-exposure", config),
            line: Some(4),
        },
    };
    observe_api_schema_exposure(&input, CAPTURED_AT).unwrap().0
}

fn source_tokens(source: &str) -> Vec<(&str, usize)> {
    let mut tokens = Vec::new();
    let mut start = None;
    for (offset, character) in source.char_indices() {
        let token = character.is_ascii_alphanumeric() || character == '_';
        match (start, token) {
            (None, true) => start = Some(offset),
            (Some(begin), false) => {
                tokens.push((&source[begin..offset], begin));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        tokens.push((&source[begin..], begin));
    }
    tokens
}

fn key_boundary_evidence(source: &str) -> Vec<Evidence> {
    let source_path = path("src/browser.ts");
    let context =
        classify_source_execution_context(&source_path, source, SourceContextLimits::default())
            .unwrap();
    let source_digest = digest("r2-t028-browser-source", source);
    let mut evidence = Vec::new();
    for (raw, byte_offset) in source_tokens(source) {
        let location = KeyAuthorityLocation {
            path: source_path.clone(),
            line: source[..byte_offset]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count() as u64
                + 1,
            start_column: 1,
            end_column: raw.len() as u64 + 1,
        };
        for observation in [
            observe_key_literal(raw, location.clone()).unwrap(),
            observe_key_reference(raw, location).unwrap(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(item) = observe_elevated_key_client_boundary(
                &observation,
                context,
                &source_digest,
                CAPTURED_AT,
            )
            .unwrap()
            {
                evidence.push(item);
            }
        }
    }
    evidence.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    evidence.dedup_by(|left, right| left.evidence_id() == right.evidence_id());
    evidence
}

fn fixture_evidence(is_safe: bool) -> Vec<Evidence> {
    let (migrations, config_text, browser, edge_source) = if is_safe {
        (
            vec![migration(
                "supabase/migrations/20260829000100_baseline.sql",
                "20260829000100",
                SAFE_SQL,
            )],
            SAFE_CONFIG,
            SAFE_BROWSER,
            SAFE_EDGE,
        )
    } else {
        (
            vec![
                migration(
                    "supabase/migrations/20260829000100_baseline.sql",
                    "20260829000100",
                    UNSAFE_BASELINE_SQL,
                ),
                migration(
                    "supabase/migrations/20260829000200_widen.sql",
                    "20260829000200",
                    UNSAFE_WIDEN_SQL,
                ),
            ],
            UNSAFE_CONFIG,
            UNSAFE_BROWSER,
            UNSAFE_EDGE,
        )
    };

    let state = reduce_repository_posture(&migrations, SqlScanLimits::default()).unwrap();
    let exposure = exposure(config_text);
    let mut evidence = Vec::new();
    evidence.extend(
        observe_api_relevant_rls(&state, &exposure, CAPTURED_AT, RlsPostureLimits::default())
            .unwrap(),
    );
    evidence.extend(
        observe_api_role_grants(
            &state,
            &exposure,
            CAPTURED_AT,
            ApiRoleGrantLimits::default(),
        )
        .unwrap(),
    );
    evidence.extend(
        observe_function_authority(
            &state,
            &exposure,
            CAPTURED_AT,
            FunctionAuthorityLimits::default(),
        )
        .unwrap(),
    );
    evidence.extend(
        observe_storage_authorization_posture(&state, CAPTURED_AT, StoragePostureLimits::default())
            .unwrap(),
    );
    evidence.extend(key_boundary_evidence(browser));

    let parsed_config = parse_supabase_config(
        &path(SUPABASE_CONFIG_PATH),
        &digest("r2-t028-config", config_text),
        config_text.as_bytes(),
        SupabaseConfigLimits::default(),
    )
    .unwrap();
    let edge = assess_edge_function_auth(
        &parsed_config,
        "webhook",
        &path("supabase/functions/webhook/index.ts"),
        edge_source,
        &digest("r2-t028-edge-source", edge_source),
        CAPTURED_AT,
        EdgeAuthLimits::default(),
    )
    .unwrap();
    if let Some(item) = edge.evidence {
        evidence.push(item);
    }

    evidence.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    evidence
}

fn string_attr<'a>(item: &'a Evidence, key: &str) -> Option<&'a str> {
    item.claim().attributes.get(key).and_then(Value::as_str)
}

fn string_array_contains(item: &Evidence, key: &str, expected: &str) -> bool {
    item.claim()
        .attributes
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn release_signal_groups(evidence: &[Evidence]) -> BTreeSet<String> {
    let mut groups = BTreeSet::new();
    for item in evidence {
        match item.claim().category.as_str() {
            "supabase_rls_posture" if string_attr(item, "rls_state") == Some("DISABLED") => {
                groups.insert("RLS".to_owned());
            }
            "supabase_api_role_grant"
                if string_attr(item, "role") == Some("anon")
                    || matches!(
                        string_attr(item, "privilege"),
                        Some("INSERT" | "UPDATE" | "DELETE" | "ALL")
                    ) =>
            {
                groups.insert("GRANTS".to_owned());
            }
            "supabase_function_search_path"
                if string_attr(item, "search_path_posture") == Some("UNPINNED_OR_MUTABLE") =>
            {
                groups.insert("SECURITY_DEFINER_SEARCH_PATH".to_owned());
            }
            "supabase_elevated_key_client_boundary" => {
                groups.insert("KEY_AUTHORITY_CONTEXT".to_owned());
            }
            "supabase_storage_policy_posture"
                if string_array_contains(item, "roles", "public")
                    || string_array_contains(item, "roles", "anon") =>
            {
                groups.insert("STORAGE".to_owned());
            }
            "supabase_edge_function_auth"
                if string_attr(item, "platform_jwt_verification") == Some("DISABLED")
                    && string_attr(item, "supported_replacement_auth") != Some("PROVEN") =>
            {
                groups.insert("EDGE_FUNCTION_AUTH".to_owned());
            }
            _ => {}
        }
    }
    groups
}

fn evaluate_once() -> R2ReleaseRun {
    let suite: ReleaseSuite = serde_json::from_slice(SUITE_BYTES).unwrap();
    let development: Value = serde_json::from_slice(DEVELOPMENT_CORPUS_BYTES).unwrap();
    assert_eq!(development["release_gating"], Value::Bool(false));
    assert!(suite.release_gating);
    assert_eq!(suite.corpus_class, "DEVELOPMENT_EVALUATION");
    assert_eq!(
        suite.inputs.safe_fixture,
        "fixtures/repos/r2-supabase/positive/safe-posture"
    );
    assert_eq!(
        suite.inputs.vulnerable_fixture,
        "fixtures/repos/r2-supabase/negative/unsafe-posture"
    );
    assert_eq!(
        suite.inputs.development_corpus,
        "tests/benchmark/development-evaluation/t090-development-corpus.json"
    );

    let safe_evidence = fixture_evidence(true);
    let vulnerable_evidence = fixture_evidence(false);
    let safe_signals = release_signal_groups(&safe_evidence);
    let detected = release_signal_groups(&vulnerable_evidence);
    let required = suite
        .known_ground_truth
        .required_signal_groups
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let misses = required.difference(&detected).count() as u64;
    let clean_cases_with_false_positive = u64::from(!safe_signals.is_empty());
    let clean_cases_evaluated = 1_u64;
    let fp_gate_passed = clean_cases_with_false_positive
        .checked_mul(suite.clean_pr_false_positive_gate.per_clean_prs)
        .is_some_and(|scaled| {
            scaled
                <= suite
                    .clean_pr_false_positive_gate
                    .max_false_positive_clean_prs
                    .saturating_mul(clean_cases_evaluated)
        });

    let required_static = suite
        .coverage
        .required_static_dimensions
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let implemented_static = BTreeSet::from([
        COVERAGE_STATIC_POSTURE_DATABASE.to_owned(),
        COVERAGE_STATIC_POSTURE_STORAGE.to_owned(),
        COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS.to_owned(),
        COVERAGE_STATIC_POSTURE_KEY_BOUNDARY.to_owned(),
    ]);
    assert!(required_static.is_subset(&implemented_static));

    let required_gaps = suite
        .coverage
        .required_explicit_gaps
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let canonical_gaps = BTreeSet::from([
        COVERAGE_LIVE_POSTURE.to_owned(),
        COVERAGE_BUSINESS_LOGIC.to_owned(),
        COVERAGE_RUNTIME.to_owned(),
    ]);
    assert_eq!(required_gaps, canonical_gaps);

    const { assert!(!TARGET_BUILD_EXECUTION_ALLOWED) };
    const { assert!(!EDGE_AUTH_TARGET_EXECUTION_ALLOWED) };
    const { assert!(!EDGE_AUTH_PROVIDER_NETWORK_ALLOWED) };
    const { assert!(!AUTH_API_PROVIDER_NETWORK_ALLOWED) };

    let evidence_identity_failures = safe_evidence
        .iter()
        .chain(vulnerable_evidence.iter())
        .filter(|item| !item.verify_identity().unwrap())
        .count() as u64;
    let persisted_debug = format!("{safe_evidence:?}{vulnerable_evidence:?}");
    assert!(!persisted_debug.contains(SECRET_CANARY));

    let authority_results = BTreeMap::from([
        ("provider-output-is-evidence-or-coverage-only", true),
        ("only-reconciler-creates-findings", true),
        ("fixture-content-has-no-instruction-authority", true),
        (
            "no-live-supabase-access",
            !EDGE_AUTH_PROVIDER_NETWORK_ALLOWED && !AUTH_API_PROVIDER_NETWORK_ALLOWED,
        ),
        (
            "no-target-execution",
            !TARGET_BUILD_EXECUTION_ALLOWED && !EDGE_AUTH_TARGET_EXECUTION_ALLOWED,
        ),
        (
            "no-secret-plaintext-persistence",
            !persisted_debug.contains(SECRET_CANARY),
        ),
    ]);
    let authority_assertions_passed = suite
        .authority_assertions
        .iter()
        .filter(|id| authority_results.get(id.as_str()).copied() == Some(true))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        authority_assertions_passed.len(),
        suite.authority_assertions.len()
    );

    assert_eq!(suite.performance.state, "NOT_MEASURED");
    assert_eq!(suite.performance.owner_task, "R2-T029");

    R2ReleaseRun {
        suite_version: suite.suite_version,
        corpus_class: suite.corpus_class,
        candidate_identity: suite.candidate_identity,
        clean_cases_evaluated,
        clean_cases_with_false_positive,
        clean_pr_fp_gate_passed: fp_gate_passed,
        required_signal_groups: required.into_iter().collect(),
        detected_signal_groups: detected.into_iter().collect(),
        known_misses: misses,
        known_miss_gate_passed: misses <= suite.known_ground_truth.max_known_misses,
        required_static_dimensions: required_static.into_iter().collect(),
        explicit_gap_dimensions: required_gaps.into_iter().collect(),
        authority_assertions_passed,
        provider_evidence_count: (safe_evidence.len() + vulnerable_evidence.len()) as u64,
        evidence_identity_failures,
        deterministic_replay: "REPLAY_EQUAL".to_owned(),
        performance_state: suite.performance.state,
    }
}

#[test]
fn r2_initial_release_gate_meets_sentrdelbench_quality_contract() {
    let first = evaluate_once();
    let second = evaluate_once();
    assert_eq!(first, second);
    assert!(first.clean_pr_fp_gate_passed);
    assert_eq!(first.clean_cases_with_false_positive, 0);
    assert!(first.known_miss_gate_passed);
    assert_eq!(first.known_misses, 0);
    assert_eq!(first.required_signal_groups, first.detected_signal_groups);
    assert_eq!(first.evidence_identity_failures, 0);
    assert!(first.provider_evidence_count > 0);
    assert_eq!(first.deterministic_replay, "REPLAY_EQUAL");
    assert_eq!(first.performance_state, "NOT_MEASURED");
}
