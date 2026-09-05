#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        graph_map::R3_GRAPH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY,
        model::{
            BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, DataOperation,
            DataOperationKind, FrameworkFamily, HttpMethod, LinkBasis, PathState, ResourceKind,
            ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
        },
        path::{
            PathCorrelationDiagnosticReason, PathCorrelationInputs, PathCorrelationLimits,
            R3_PATH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY,
            R3_PATH_CORRELATION_CONSUMES_R2_EVIDENCE, correlate_cross_layer_paths,
        },
        r2_support::{R2_SUPPORT_CONFIDENCE_GRANTS_AUTHORITY, R2_SUPPORT_PROVES_LIVE_POSTURE},
    },
    view::NormalizedRepoPath,
};
use sentrdel_schema::coverage::CoverageState;

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/r3-t020.js", 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn route(callback: StableSemanticId) -> RouteObservation {
    RouteObservation::new(
        id("r3.t020.route", "profiles"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/profiles/:id",
        Some("handler".to_owned()),
        vec![callback],
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn resource(name: &str) -> ResourceRef {
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some("public".to_owned()),
        name,
        ResourceKind::Table,
        None,
        limits(),
    )
    .expect("resource")
}

fn operation(
    name: &str,
    handler: Option<StableSemanticId>,
    start: usize,
) -> DataOperation {
    DataOperation::new(
        id("r3.t020.operation", name),
        DataOperationKind::Read,
        resource(name),
        None,
        Vec::new(),
        None,
        None,
        None,
        handler,
        vec![location(start)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn explicit_link(
    namespace: &str,
    source: StableSemanticId,
    target: StableSemanticId,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
    start: usize,
) -> CrossLayerLink {
    CrossLayerLink::new(
        StableSemanticId::from_parts(namespace, &[source.as_str(), target.as_str()], limits())
            .expect("link id"),
        source,
        target,
        "r3_t020_bridge",
        basis,
        confidence,
        vec![location(start)],
        limits(),
    )
    .expect("cross-layer link")
}

fn inputs<'a>(
    routes: &'a [RouteObservation],
    operations: &'a [DataOperation],
    links: &'a [CrossLayerLink],
) -> PathCorrelationInputs<'a> {
    PathCorrelationInputs {
        routes,
        actors: &[],
        guards: &[],
        values: &[],
        data_operations: operations,
        provider_clients: &[],
        links,
    }
}

#[test]
fn supported_and_ambiguous_cross_layer_paths_remain_distinguishable() {
    let callback = id("r3.t020.callback", "handler");
    let routes = vec![route(callback.clone())];

    let safe_operations = vec![operation("profiles", Some(callback.clone()), 100)];
    let safe = correlate_cross_layer_paths(
        inputs(&routes, &safe_operations, &[]),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("supported correlation");

    assert_eq!(safe.coverage_state(), &CoverageState::Covered);
    assert_eq!(safe.paths().len(), 1);
    assert_eq!(safe.paths()[0].path_state(), PathState::Supported);

    let ambiguous_operations = vec![operation("profiles", None, 200)];
    let ambiguous_links = vec![explicit_link(
        "r3.t020.ambiguous-link",
        callback,
        ambiguous_operations[0].operation_id().clone(),
        LinkBasis::ScipReference,
        ConfidenceBasis::Ambiguous,
        220,
    )];
    let ambiguous = correlate_cross_layer_paths(
        inputs(&routes, &ambiguous_operations, &ambiguous_links),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("ambiguous correlation");

    assert_eq!(ambiguous.coverage_state(), &CoverageState::Partial);
    assert_eq!(ambiguous.paths().len(), 1);
    assert_eq!(ambiguous.paths()[0].path_state(), PathState::Ambiguous);
    assert_ne!(ambiguous.paths()[0].path_state(), PathState::Supported);
}

#[test]
fn ambiguous_links_cannot_meet_the_supported_path_prerequisite_for_invariants() {
    let callback = id("r3.t020.callback", "guarded-handler");
    let routes = vec![route(callback.clone())];
    let operations = vec![operation("accounts", None, 300)];
    let links = vec![explicit_link(
        "r3.t020.ambiguous-invariant-link",
        callback,
        operations[0].operation_id().clone(),
        LinkBasis::ScipReference,
        ConfidenceBasis::Ambiguous,
        320,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &operations, &links),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("ambiguous correlation");

    let path = result.paths().first().expect("ambiguous path remains visible");
    assert_eq!(path.path_state(), PathState::Ambiguous);
    assert_ne!(path.path_state(), PathState::Supported);
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
}

#[test]
fn graph_and_path_confidence_never_upgrade_epistemic_authority() {
    const { assert!(!R3_GRAPH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY) };
    const { assert!(!R3_PATH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY) };
    const { assert!(!R2_SUPPORT_CONFIDENCE_GRANTS_AUTHORITY) };
}

#[test]
fn r2_static_support_cannot_become_hosted_truth_through_path_correlation() {
    const { assert!(!R2_SUPPORT_PROVES_LIVE_POSTURE) };
    const { assert!(!R3_PATH_CORRELATION_CONSUMES_R2_EVIDENCE) };
}

#[test]
fn candidate_path_cap_exhaustion_fails_visible_instead_of_returning_clean() {
    let callback = id("r3.t020.callback", "fanout-handler");
    let routes = vec![route(callback.clone())];
    let operations = vec![
        operation("profiles", Some(callback.clone()), 400),
        operation("accounts", Some(callback), 500),
    ];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &operations, &[]),
        limits(),
        PathCorrelationLimits {
            max_candidate_paths: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("candidate-limited correlation");

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::CandidatePathLimitExceeded
    }));
}
