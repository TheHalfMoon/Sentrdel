#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        model::{
            BusinessLogicLimits, DataOperation, DataOperationKind, FrameworkFamily, HttpMethod,
            PathState, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
            StableSemanticId,
        },
        path::{
            INLINE_ROUTE_OPERATION_RELATION, PathCorrelationDiagnosticReason,
            PathCorrelationInputs, PathCorrelationLimits, correlate_cross_layer_paths,
        },
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

fn location(start: usize, end: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/routes/profile.js", 4_096).expect("normalized path"),
        start,
        end,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn route(name: &str, start: usize, end: usize) -> RouteObservation {
    RouteObservation::new(
        id("r3.t017.inline.route", name),
        FrameworkFamily::Express,
        HttpMethod::Patch,
        format!("/profiles/{name}"),
        Some(format!("inline@{start}")),
        vec![id("r3.t017.inline.callback", name)],
        vec![location(start, end)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn operation(state: CoverageState, start: usize, end: usize) -> DataOperation {
    DataOperation::new(
        id("r3.t017.inline.operation", "update-profile"),
        DataOperationKind::Update,
        ResourceRef::new(
            None,
            None,
            "profiles",
            ResourceKind::Table,
            None,
            limits(),
        )
        .expect("resource"),
        None,
        Vec::new(),
        None,
        None,
        None,
        None,
        vec![location(start, end)],
        state,
        limits(),
    )
    .expect("operation")
}

fn correlate(routes: &[RouteObservation], operations: &[DataOperation]) -> sentrdel_review::business_logic::path::PathCorrelationResult {
    correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes,
            actors: &[],
            guards: &[],
            values: &[],
            data_operations: operations,
            provider_clients: &[],
            links: &[],
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlation")
}

#[test]
fn unique_covered_inline_containment_creates_supported_route_operation_path() {
    let routes = vec![route("primary", 0, 220)];
    let operations = vec![operation(CoverageState::Covered, 80, 140)];
    let result = correlate(&routes, &operations);

    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].path_state(), PathState::Supported);
    assert!(result.paths()[0].links().iter().any(|link| {
        link.source_semantic_id() == routes[0].route_id()
            && link.target_semantic_id() == operations[0].operation_id()
            && link.relation() == INLINE_ROUTE_OPERATION_RELATION
    }));
}

#[test]
fn overlapping_route_containment_stays_partial_instead_of_guessing_owner() {
    let routes = vec![route("one", 0, 220), route("two", 20, 200)];
    let operations = vec![operation(CoverageState::Covered, 80, 140)];
    let result = correlate(&routes, &operations);

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        matches!(
            diagnostic.reason(),
            PathCorrelationDiagnosticReason::MissingRouteDataPath
                | PathCorrelationDiagnosticReason::UncorrelatedDataOperation
        )
    }));
}

#[test]
fn partial_operation_is_never_promoted_by_provenance_containment() {
    let routes = vec![route("primary", 0, 220)];
    let operations = vec![operation(CoverageState::Partial, 80, 140)];
    let result = correlate(&routes, &operations);

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
}
