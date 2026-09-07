#![forbid(unsafe_code)]

use std::{env, time::Instant};

use sentrdel_review::{
    TARGET_BUILD_EXECUTION_ALLOWED,
    business_logic::{
        R3_PROVIDER_CREDENTIALS_ALLOWED, R3_TARGET_EXECUTION_ALLOWED,
        actor::extract_actor_contexts,
        data::extract_supabase_data_operations,
        graph::{
            DEFAULT_MAX_R3_GRAPH_EDGES, DEFAULT_MAX_R3_GRAPH_NODES,
            DEFAULT_MAX_R3_GRAPH_PROVENANCE_IDS, R3GraphLimits, R3GraphMappingError,
            map_validated_observations,
        },
        guard::extract_guard_observations,
        invariant::{
            DEFAULT_MAX_PROJECT_INVARIANT_FILE_BYTES, DEFAULT_MAX_PROJECT_INVARIANT_ID_BYTES,
            DEFAULT_MAX_PROJECT_INVARIANT_KEYS, DEFAULT_MAX_PROJECT_INVARIANT_VALUE_BYTES,
            DEFAULT_MAX_PROJECT_INVARIANTS, ProjectInvariantLimits,
        },
        model::BusinessLogicLimits,
        path::{
            DEFAULT_MAX_CORRELATION_CANDIDATES, DEFAULT_MAX_CORRELATION_DEPTH,
            DEFAULT_MAX_CORRELATION_DIAGNOSTICS, DEFAULT_MAX_CORRELATION_EDGES,
            DEFAULT_MAX_CORRELATION_FRONTIER, DEFAULT_MAX_CORRELATION_NODES,
            DEFAULT_MAX_CORRELATION_OBSERVATIONS, DEFAULT_MAX_CORRELATION_WORK_ITEMS,
            PathCorrelationDiagnosticReason, PathCorrelationInputs, PathCorrelationLimits,
            correlate_cross_layer_paths,
        },
        project_invariant::{
            DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES, DEFAULT_MAX_PROJECT_COLLECTION_ITEMS,
            DEFAULT_MAX_PROJECT_DIAGNOSTICS, DEFAULT_MAX_PROJECT_INVARIANT_LINES,
            DEFAULT_MAX_PROJECT_SCOPE_PATH_BYTES, DEFAULT_MAX_PROJECT_SCOPE_TEXT_BYTES,
            PROJECT_INVARIANT_PATH, ProjectInvariantLoadState, load_project_invariants,
        },
        route::{RouteAdapter, extract_routes},
        value::extract_value_origins,
    },
    structural::{
        MAX_STRUCTURAL_DOCUMENT_BYTES, MAX_STRUCTURAL_PATTERN_BYTES, MAX_STRUCTURAL_RULE_ID_BYTES,
        MAX_STRUCTURAL_RULES, StructuralError, StructuralLanguage, StructuralRegistry,
    },
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use serde::Deserialize;
use serde_json::json;

const POLICY_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/r3-t032-performance-policy.json");
const UNSAFE_TENANT_SOURCE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/unsafe-tenant/src/routes/accounts.js"
);
const SAFE_PROJECT_INVARIANTS: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/project-invariants/safe-tightening/.sentrdel/invariants.toml"
);
const PROJECT_DIGEST: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000032";
const R1_WARM_REVIEW_P95_CAP_MS: u128 = 5_000;
const R1_BROAD_100K_LOC_CAP_MS: u128 = 30_000;
const _: () = assert!(!TARGET_BUILD_EXECUTION_ALLOWED);
const _: () = assert!(!R3_TARGET_EXECUTION_ALLOWED);
const _: () = assert!(!R3_PROVIDER_CREDENTIALS_ALLOWED);

#[derive(Debug, Deserialize)]
struct PerformancePolicy {
    policy_version: String,
    measurement_mode: String,
    sample_count: usize,
    workload: WorkloadPolicy,
    latency_caps: LatencyCaps,
    parser_caps: ParserCaps,
    path_caps: PathCaps,
    graph_caps: GraphCaps,
    invariant_caps: InvariantCaps,
    machine_metadata_required: Vec<String>,
    external_engine_time_included: bool,
    network_time_included: bool,
    target_execution_time_included: bool,
    peak_memory: PeakMemoryPolicy,
}

#[derive(Debug, Deserialize)]
struct WorkloadPolicy {
    name: String,
    fixture_root: String,
    fixture_file: String,
    max_changed_loc: usize,
}

#[derive(Debug, Deserialize)]
struct LatencyCaps {
    r3_warm_p95_ms: u128,
    r1_warm_review_p95_ms: u128,
    r1_broad_100k_loc_ms: u128,
}

#[derive(Debug, Deserialize)]
struct ParserCaps {
    max_structural_rules: usize,
    max_rule_id_bytes: usize,
    max_pattern_bytes: usize,
    max_document_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct PathCaps {
    max_observations: usize,
    max_nodes: usize,
    max_edges: usize,
    max_depth: usize,
    max_candidate_paths: usize,
    max_diagnostics: usize,
    max_work_items: usize,
    max_frontier: usize,
}

#[derive(Debug, Deserialize)]
struct GraphCaps {
    max_nodes: usize,
    max_edges: usize,
    max_provenance_ids_per_record: usize,
}

#[derive(Debug, Deserialize)]
struct InvariantCaps {
    max_file_bytes: usize,
    max_invariants: usize,
    max_id_bytes: usize,
    max_keys: usize,
    max_value_bytes: usize,
    max_lines: usize,
    max_scope_text_bytes: usize,
    max_collection_items: usize,
    max_collection_item_bytes: usize,
    max_diagnostics: usize,
    max_scope_path_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct PeakMemoryPolicy {
    state: String,
    reason: String,
}

#[derive(Clone, Copy, Debug)]
struct PipelineSnapshot {
    routes: usize,
    actors: usize,
    guards: usize,
    values: usize,
    operations: usize,
    graph_nodes: usize,
    graph_edges: usize,
    path_diagnostics: usize,
    project_invariants: usize,
}

fn policy() -> PerformancePolicy {
    serde_json::from_slice(POLICY_BYTES).expect("R3-T032 performance policy must be valid JSON")
}

fn normalized_path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path")
}

fn fixture_changed_loc() -> usize {
    UNSAFE_TENANT_SOURCE.lines().count()
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

fn run_static_pipeline() -> PipelineSnapshot {
    let limits = BusinessLogicLimits::default();
    let source_path = normalized_path("src/routes/accounts.js");
    let source = UNSAFE_TENANT_SOURCE.as_bytes();

    let routes = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("route extraction");
    let actors = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("actor extraction");
    let guards = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("guard extraction");
    let values = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("value extraction");
    let data = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        source,
        limits,
    )
    .expect("data extraction");

    let invariant_path = normalized_path(PROJECT_INVARIANT_PATH);
    let project_invariants = load_project_invariants(
        Some(SAFE_PROJECT_INVARIANTS),
        &invariant_path,
        PROJECT_DIGEST,
        ProjectInvariantLimits::default(),
        limits,
    );
    assert_eq!(
        project_invariants.state(),
        ProjectInvariantLoadState::Loaded
    );

    let graph = map_validated_observations(
        routes.routes(),
        data.operations(),
        project_invariants.definitions(),
        R3GraphLimits::default(),
    )
    .expect("R3 graph mapping");

    let correlation = correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: routes.routes(),
            actors: actors.actors(),
            guards: guards.guards(),
            values: values.values(),
            data_operations: data.operations(),
            provider_clients: &[],
            links: &[],
        },
        limits,
        PathCorrelationLimits::default(),
    )
    .expect("R3 path correlation");

    PipelineSnapshot {
        routes: routes.routes().len(),
        actors: actors.actors().len(),
        guards: guards.guards().len(),
        values: values.values().len(),
        operations: data.operations().len(),
        graph_nodes: graph.nodes().len(),
        graph_edges: graph.edges().len(),
        path_diagnostics: correlation.diagnostics().len(),
        project_invariants: project_invariants.definitions().len(),
    }
}

#[test]
fn r3_t032_warm_static_pipeline_has_machine_metadata_and_preserves_review_latency_ceilings() {
    let policy = policy();
    assert_eq!(policy.policy_version, "sentrdel-r3-performance/r3-t032-v1");
    assert_eq!(policy.measurement_mode, "WARM");
    assert_eq!(policy.workload.name, "r3-unsafe-tenant-static-pipeline");
    assert_eq!(
        policy.workload.fixture_root,
        "fixtures/repos/r3-business-logic/express/unsafe-tenant"
    );
    assert_eq!(
        policy.workload.fixture_file,
        "fixtures/repos/r3-business-logic/express/unsafe-tenant/src/routes/accounts.js"
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
    assert!(policy.latency_caps.r3_warm_p95_ms <= R1_WARM_REVIEW_P95_CAP_MS);
    assert!(!policy.external_engine_time_included);
    assert!(!policy.network_time_included);
    assert!(!policy.target_execution_time_included);
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

    for _ in 0..3 {
        let snapshot = run_static_pipeline();
        assert!(snapshot.routes > 0);
        assert!(snapshot.operations > 0);
    }

    let mut samples_ms = Vec::with_capacity(policy.sample_count);
    let mut final_snapshot = None;
    for _ in 0..policy.sample_count {
        let started = Instant::now();
        let snapshot = run_static_pipeline();
        samples_ms.push(started.elapsed().as_millis());
        final_snapshot = Some(snapshot);
    }

    let snapshot = final_snapshot.expect("at least one measured sample");
    assert!(snapshot.routes > 0);
    assert!(snapshot.operations > 0);
    assert!(snapshot.graph_nodes > 0);
    assert!(snapshot.project_invariants > 0);

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
            "p95_cap_ms": policy.latency_caps.r3_warm_p95_ms,
            "machine": metadata,
            "pipeline": {
                "routes": snapshot.routes,
                "actors": snapshot.actors,
                "guards": snapshot.guards,
                "values": snapshot.values,
                "operations": snapshot.operations,
                "graph_nodes": snapshot.graph_nodes,
                "graph_edges": snapshot.graph_edges,
                "path_diagnostics": snapshot.path_diagnostics,
                "project_invariants": snapshot.project_invariants,
            },
            "external_engine_time_included": policy.external_engine_time_included,
            "network_time_included": policy.network_time_included,
            "target_execution_time_included": policy.target_execution_time_included,
            "peak_memory_state": policy.peak_memory.state,
        })
    );

    assert!(
        p95_ms < policy.latency_caps.r3_warm_p95_ms,
        "R3 warm static-pipeline p95 {p95_ms}ms exceeded cap {}ms",
        policy.latency_caps.r3_warm_p95_ms
    );
}

#[test]
fn r3_t032_declared_hard_caps_match_frozen_parser_path_graph_and_invariant_defaults() {
    let policy = policy();

    assert_eq!(
        policy.parser_caps.max_structural_rules,
        MAX_STRUCTURAL_RULES
    );
    assert_eq!(
        policy.parser_caps.max_rule_id_bytes,
        MAX_STRUCTURAL_RULE_ID_BYTES
    );
    assert_eq!(
        policy.parser_caps.max_pattern_bytes,
        MAX_STRUCTURAL_PATTERN_BYTES
    );
    assert_eq!(
        policy.parser_caps.max_document_bytes,
        MAX_STRUCTURAL_DOCUMENT_BYTES
    );

    let path = PathCorrelationLimits::default();
    assert_eq!(policy.path_caps.max_observations, path.max_observations);
    assert_eq!(policy.path_caps.max_nodes, path.max_nodes);
    assert_eq!(policy.path_caps.max_edges, path.max_edges);
    assert_eq!(policy.path_caps.max_depth, path.max_depth);
    assert_eq!(
        policy.path_caps.max_candidate_paths,
        path.max_candidate_paths
    );
    assert_eq!(policy.path_caps.max_diagnostics, path.max_diagnostics);
    assert_eq!(policy.path_caps.max_work_items, path.max_work_items);
    assert_eq!(policy.path_caps.max_frontier, path.max_frontier);
    assert_eq!(path.max_observations, DEFAULT_MAX_CORRELATION_OBSERVATIONS);
    assert_eq!(path.max_nodes, DEFAULT_MAX_CORRELATION_NODES);
    assert_eq!(path.max_edges, DEFAULT_MAX_CORRELATION_EDGES);
    assert_eq!(path.max_depth, DEFAULT_MAX_CORRELATION_DEPTH);
    assert_eq!(path.max_candidate_paths, DEFAULT_MAX_CORRELATION_CANDIDATES);
    assert_eq!(path.max_diagnostics, DEFAULT_MAX_CORRELATION_DIAGNOSTICS);
    assert_eq!(path.max_work_items, DEFAULT_MAX_CORRELATION_WORK_ITEMS);
    assert_eq!(path.max_frontier, DEFAULT_MAX_CORRELATION_FRONTIER);

    let graph = R3GraphLimits::default();
    assert_eq!(policy.graph_caps.max_nodes, graph.max_nodes);
    assert_eq!(policy.graph_caps.max_edges, graph.max_edges);
    assert_eq!(
        policy.graph_caps.max_provenance_ids_per_record,
        graph.max_provenance_ids_per_record
    );
    assert_eq!(graph.max_nodes, DEFAULT_MAX_R3_GRAPH_NODES);
    assert_eq!(graph.max_edges, DEFAULT_MAX_R3_GRAPH_EDGES);
    assert_eq!(
        graph.max_provenance_ids_per_record,
        DEFAULT_MAX_R3_GRAPH_PROVENANCE_IDS
    );

    let invariants = ProjectInvariantLimits::default();
    assert_eq!(
        policy.invariant_caps.max_file_bytes,
        invariants.max_file_bytes
    );
    assert_eq!(
        policy.invariant_caps.max_invariants,
        invariants.max_invariants
    );
    assert_eq!(policy.invariant_caps.max_id_bytes, invariants.max_id_bytes);
    assert_eq!(policy.invariant_caps.max_keys, invariants.max_keys);
    assert_eq!(
        policy.invariant_caps.max_value_bytes,
        invariants.max_value_bytes
    );
    assert_eq!(
        invariants.max_file_bytes,
        DEFAULT_MAX_PROJECT_INVARIANT_FILE_BYTES
    );
    assert_eq!(invariants.max_invariants, DEFAULT_MAX_PROJECT_INVARIANTS);
    assert_eq!(
        invariants.max_id_bytes,
        DEFAULT_MAX_PROJECT_INVARIANT_ID_BYTES
    );
    assert_eq!(invariants.max_keys, DEFAULT_MAX_PROJECT_INVARIANT_KEYS);
    assert_eq!(
        invariants.max_value_bytes,
        DEFAULT_MAX_PROJECT_INVARIANT_VALUE_BYTES
    );
    assert_eq!(
        policy.invariant_caps.max_lines,
        DEFAULT_MAX_PROJECT_INVARIANT_LINES
    );
    assert_eq!(
        policy.invariant_caps.max_scope_text_bytes,
        DEFAULT_MAX_PROJECT_SCOPE_TEXT_BYTES
    );
    assert_eq!(
        policy.invariant_caps.max_collection_items,
        DEFAULT_MAX_PROJECT_COLLECTION_ITEMS
    );
    assert_eq!(
        policy.invariant_caps.max_collection_item_bytes,
        DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES
    );
    assert_eq!(
        policy.invariant_caps.max_diagnostics,
        DEFAULT_MAX_PROJECT_DIAGNOSTICS
    );
    assert_eq!(
        policy.invariant_caps.max_scope_path_bytes,
        DEFAULT_MAX_PROJECT_SCOPE_PATH_BYTES
    );

    assert_eq!(policy.peak_memory.state, "NOT_MEASURED");
    assert!(!policy.peak_memory.reason.trim().is_empty());
}

#[test]
fn r3_t032_parser_path_graph_and_invariant_caps_fail_closed_or_fail_visible() {
    let model_limits = BusinessLogicLimits::default();
    let source_path = normalized_path("src/routes/accounts.js");
    let registry = StructuralRegistry::new(&[]).expect("empty structural registry");
    let oversized = vec![b'a'; MAX_STRUCTURAL_DOCUMENT_BYTES + 1];
    assert!(matches!(
        registry.scan_language(StructuralLanguage::JavaScript, &source_path, &oversized),
        Err(StructuralError::DocumentTooLarge { max, .. }) if max == MAX_STRUCTURAL_DOCUMENT_BYTES
    ));

    let routes = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &source_path,
        UNSAFE_TENANT_SOURCE.as_bytes(),
        model_limits,
    )
    .expect("route extraction");
    assert!(!routes.routes().is_empty());

    let duplicated_routes = vec![routes.routes()[0].clone(), routes.routes()[0].clone()];
    let path_limited = correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: &duplicated_routes,
            actors: &[],
            guards: &[],
            values: &[],
            data_operations: &[],
            provider_clients: &[],
            links: &[],
        },
        model_limits,
        PathCorrelationLimits {
            max_observations: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("observation-limited path correlation");
    assert!(path_limited.paths().is_empty());
    assert!(path_limited.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::ObservationLimitExceeded
    }));

    assert!(matches!(
        map_validated_observations(
            routes.routes(),
            &[],
            &[],
            R3GraphLimits {
                max_nodes: 1,
                ..R3GraphLimits::default()
            },
        ),
        Err(R3GraphMappingError::NodeLimitExceeded { maximum: 1 })
    ));

    let invariant_path = normalized_path(PROJECT_INVARIANT_PATH);
    let invariant_limits = ProjectInvariantLimits::default();
    let oversized_invariants = "x".repeat(invariant_limits.max_file_bytes + 1);
    let rejected = load_project_invariants(
        Some(&oversized_invariants),
        &invariant_path,
        PROJECT_DIGEST,
        invariant_limits,
        model_limits,
    );
    assert_eq!(rejected.state(), ProjectInvariantLoadState::Rejected);
    assert!(
        rejected
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == "file_too_large")
    );
}
