#![forbid(unsafe_code)]

use std::{env, time::Instant};

use sentrdel_review::{
    TARGET_BUILD_EXECUTION_ALLOWED,
    supabase::{
        sql::{SqlScanError, SqlScanLimits, scan_sql},
        state::{MigrationSqlInput, reduce_repository_posture},
    },
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::canonical::content_id;
use serde::Deserialize;
use serde_json::json;

const POLICY_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/r2-t029-performance-policy.json");
const UNSAFE_BASELINE_SQL: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/migrations/20260829000100_baseline.sql"
);
const UNSAFE_WIDEN_SQL: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/migrations/20260829000200_widen.sql"
);
const R1_WARM_REVIEW_P95_CAP_MS: u128 = 5_000;
const R1_BROAD_100K_LOC_CAP_MS: u128 = 30_000;
const _: () = assert!(!TARGET_BUILD_EXECUTION_ALLOWED);

#[derive(Debug, Deserialize)]
struct PerformancePolicy {
    policy_version: String,
    measurement_mode: String,
    sample_count: usize,
    workload: WorkloadPolicy,
    latency_caps: LatencyCaps,
    resource_caps: ResourceCaps,
    machine_metadata_required: Vec<String>,
    external_engine_time_included: bool,
    network_time_included: bool,
    peak_memory: PeakMemoryPolicy,
}

#[derive(Debug, Deserialize)]
struct WorkloadPolicy {
    name: String,
    fixture_root: String,
    max_changed_loc: usize,
}

#[derive(Debug, Deserialize)]
struct LatencyCaps {
    r2_warm_p95_ms: u128,
    r1_warm_review_p95_ms: u128,
    r1_broad_100k_loc_ms: u128,
}

#[derive(Debug, Deserialize)]
struct ResourceCaps {
    max_sql_bytes: usize,
    max_sql_statements: usize,
    max_sql_tokens: usize,
    max_sql_nesting: usize,
    max_sql_diagnostics: usize,
    max_dollar_tag_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct PeakMemoryPolicy {
    state: String,
    reason: String,
}

fn policy() -> PerformancePolicy {
    serde_json::from_slice(POLICY_BYTES).expect("R2-T029 performance policy must be valid JSON")
}

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).unwrap()
}

fn migration(path_value: &str, order_key: &str, sql: &str) -> MigrationSqlInput {
    MigrationSqlInput {
        path: path(path_value),
        order_key: order_key.to_owned(),
        content_digest: content_id("r2-t029-migration", &sql).unwrap(),
        sql: sql.to_owned(),
    }
}

fn scan_limits(policy: &PerformancePolicy) -> SqlScanLimits {
    SqlScanLimits {
        max_bytes: policy.resource_caps.max_sql_bytes,
        max_statements: policy.resource_caps.max_sql_statements,
        max_tokens: policy.resource_caps.max_sql_tokens,
        max_nesting: policy.resource_caps.max_sql_nesting,
        max_diagnostics: policy.resource_caps.max_sql_diagnostics,
        max_dollar_tag_bytes: policy.resource_caps.max_dollar_tag_bytes,
    }
}

fn fixture_migrations() -> Vec<MigrationSqlInput> {
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
    ]
}

fn fixture_changed_loc() -> usize {
    UNSAFE_BASELINE_SQL.lines().count() + UNSAFE_WIDEN_SQL.lines().count()
}

fn machine_metadata() -> serde_json::Value {
    let runner = env::var("RUNNER_NAME").unwrap_or_else(|_| "local".to_owned());
    json!({
        "os": env::consts::OS,
        "architecture": env::consts::ARCH,
        "runner": runner,
    })
}

fn percentile_95_ms(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    let index = ((samples.len() * 95).div_ceil(100)).saturating_sub(1);
    samples[index]
}

#[test]
fn r2_t029_warm_state_reduction_has_qualified_metadata_and_preserves_r1_latency_ceiling() {
    let policy = policy();
    assert_eq!(policy.policy_version, "sentrdel-r2-performance/r2-t029-v1");
    assert_eq!(policy.measurement_mode, "WARM");
    assert_eq!(policy.workload.name, "r2-unsafe-posture-state-reduction");
    assert_eq!(
        policy.workload.fixture_root,
        "fixtures/repos/r2-supabase/negative/unsafe-posture"
    );
    assert!(policy.sample_count >= 20);
    assert!(fixture_changed_loc() <= policy.workload.max_changed_loc);
    assert_eq!(
        policy.latency_caps.r1_warm_review_p95_ms,
        R1_WARM_REVIEW_P95_CAP_MS
    );
    assert_eq!(
        policy.latency_caps.r1_broad_100k_loc_ms,
        R1_BROAD_100K_LOC_CAP_MS
    );
    assert!(policy.latency_caps.r2_warm_p95_ms <= R1_WARM_REVIEW_P95_CAP_MS);
    assert!(!policy.external_engine_time_included);
    assert!(!policy.network_time_included);
    assert_eq!(
        policy.machine_metadata_required,
        ["os", "architecture", "runner"]
    );

    let metadata = machine_metadata();
    for key in &policy.machine_metadata_required {
        assert!(
            metadata
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty()),
            "required machine metadata field {key} must be present"
        );
    }

    let migrations = fixture_migrations();
    let limits = scan_limits(&policy);

    for _ in 0..3 {
        let state = reduce_repository_posture(&migrations, limits).unwrap();
        assert!(!state.relations.is_empty());
    }

    let mut samples_ms = Vec::with_capacity(policy.sample_count);
    for _ in 0..policy.sample_count {
        let started = Instant::now();
        let state = reduce_repository_posture(&migrations, limits).unwrap();
        let elapsed_ms = started.elapsed().as_millis();
        assert!(!state.relations.is_empty());
        samples_ms.push(elapsed_ms);
    }

    let p95_ms = percentile_95_ms(samples_ms.clone());
    println!(
        "{}",
        json!({
            "benchmark": policy.policy_version,
            "measurement_mode": policy.measurement_mode,
            "workload": policy.workload.name,
            "changed_loc": fixture_changed_loc(),
            "sample_count": policy.sample_count,
            "samples_ms": samples_ms,
            "p95_ms": p95_ms,
            "p95_cap_ms": policy.latency_caps.r2_warm_p95_ms,
            "machine": metadata,
            "external_engine_time_included": policy.external_engine_time_included,
            "network_time_included": policy.network_time_included,
            "peak_memory_state": policy.peak_memory.state,
        })
    );

    assert!(
        p95_ms < policy.latency_caps.r2_warm_p95_ms,
        "R2 warm state-reduction p95 {p95_ms}ms exceeded cap {}ms",
        policy.latency_caps.r2_warm_p95_ms
    );
}

#[test]
fn r2_t029_resource_caps_are_explicit_and_fail_closed() {
    let policy = policy();
    let limits = scan_limits(&policy);

    assert!(limits.max_bytes > 0);
    assert!(limits.max_statements > 0);
    assert!(limits.max_tokens > 0);
    assert!(limits.max_nesting > 0);
    assert!(limits.max_diagnostics > 0);
    assert!(limits.max_dollar_tag_bytes > 0);

    let too_many_statements = SqlScanLimits {
        max_bytes: 1024,
        max_statements: 1,
        max_tokens: 64,
        max_nesting: 16,
        max_diagnostics: 8,
        max_dollar_tag_bytes: 16,
    };
    assert!(matches!(
        scan_sql("select 1; select 2;", too_many_statements),
        Err(SqlScanError::TooManyStatements { max: 1 })
    ));

    let too_many_bytes = SqlScanLimits {
        max_bytes: 4,
        ..too_many_statements
    };
    assert!(matches!(
        scan_sql("select 1;", too_many_bytes),
        Err(SqlScanError::InputTooLarge { max: 4, .. })
    ));

    assert_eq!(policy.peak_memory.state, "NOT_MEASURED");
    assert!(!policy.peak_memory.reason.trim().is_empty());
    assert!(!TARGET_BUILD_EXECUTION_ALLOWED);
}

#[test]
fn r2_t029_declared_resource_caps_match_the_frozen_r2_defaults() {
    let policy = policy();
    let defaults = SqlScanLimits::default();
    assert_eq!(policy.resource_caps.max_sql_bytes, defaults.max_bytes);
    assert_eq!(
        policy.resource_caps.max_sql_statements,
        defaults.max_statements
    );
    assert_eq!(policy.resource_caps.max_sql_tokens, defaults.max_tokens);
    assert_eq!(policy.resource_caps.max_sql_nesting, defaults.max_nesting);
    assert_eq!(
        policy.resource_caps.max_sql_diagnostics,
        defaults.max_diagnostics
    );
    assert_eq!(
        policy.resource_caps.max_dollar_tag_bytes,
        defaults.max_dollar_tag_bytes
    );
}
