use sentrdel_review::{
    business_logic::{
        graph::{R3GraphLimits, map_validated_observations},
        model::{
            BusinessLogicLimits, FrameworkFamily, HttpMethod, RouteObservation, SourceLocation,
            StableSemanticId,
        },
    },
    view::NormalizedRepoPath,
};
use sentrdel_schema::{coverage::CoverageState, graph::GraphRelation};

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
        .expect("stable semantic id")
}

fn location(path: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse(path, 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn route(
    route_key: &str,
    path: &str,
    raw_handler_key: &str,
    callback_key: Option<&str>,
    coverage_state: CoverageState,
) -> RouteObservation {
    RouteObservation::new(
        id("r3.route", route_key),
        FrameworkFamily::NextApp,
        HttpMethod::Get,
        "/api/profiles",
        Some(raw_handler_key.to_owned()),
        callback_key
            .map(|value| vec![id("r3.route-callback", value)])
            .unwrap_or_default(),
        vec![location(path, 0)],
        coverage_state,
        BusinessLogicLimits::default(),
    )
    .expect("route")
}

#[test]
fn identical_raw_handler_names_do_not_merge_distinct_validated_callbacks() {
    let first = route(
        "first-route",
        "src/app/first/route.ts",
        "GET",
        Some("first-get"),
        CoverageState::Covered,
    );
    let second = route(
        "second-route",
        "src/app/second/route.ts",
        "GET",
        Some("second-get"),
        CoverageState::Covered,
    );

    let records = map_validated_observations(&[first, second], &[], &[], R3GraphLimits::default())
        .expect("graph records");

    assert_eq!(records.nodes().len(), 4);
    assert_eq!(
        records
            .edges()
            .iter()
            .filter(|edge| edge.relation == GraphRelation::Refs)
            .count(),
        2
    );
}

#[test]
fn unresolved_partial_handler_does_not_become_a_graph_symbol_or_ref() {
    let unresolved = route(
        "partial-route",
        "src/app/partial/route.ts",
        "GET",
        None,
        CoverageState::Partial,
    );

    let records = map_validated_observations(&[unresolved], &[], &[], R3GraphLimits::default())
        .expect("graph records");

    assert_eq!(records.nodes().len(), 1);
    assert!(records.edges().is_empty());
}
