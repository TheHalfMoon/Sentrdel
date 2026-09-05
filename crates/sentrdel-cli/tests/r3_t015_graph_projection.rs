use sentrdel_graph::{GraphNodeKind, GraphProjection, GraphRelation, UNIVERSAL_CPG};
use sentrdel_review::{
    business_logic::{
        graph::{R3GraphLimits, map_validated_observations},
        model::{
            BusinessLogicLimits, DataOperation, DataOperationKind, FrameworkFamily, HttpMethod,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
        },
    },
    view::NormalizedRepoPath,
};
use sentrdel_schema::coverage::CoverageState;

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

#[test]
fn r3_t015_records_use_existing_thin_graph_projection() {
    let route = RouteObservation::new(
        id("r3.route", "profiles"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/profiles/:id",
        Some("src/routes/profiles.js::handler".to_owned()),
        Vec::new(),
        vec![location("src/routes/profiles.js", 0)],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("route");

    let operation = DataOperation::new(
        id("r3.operation", "read-profile"),
        DataOperationKind::Read,
        ResourceRef::new(
            Some("supabase".to_owned()),
            Some("public".to_owned()),
            "profiles",
            ResourceKind::Table,
            None,
            BusinessLogicLimits::default(),
        )
        .expect("resource"),
        None,
        Vec::new(),
        None,
        None,
        None,
        Some(id("r3.handler", "profile-reader")),
        vec![location("src/data/profiles.js", 16)],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("data operation");

    let records = map_validated_observations(
        &[route],
        &[operation],
        &[],
        R3GraphLimits::default(),
    )
    .expect("R3 graph records");
    let (nodes, edges) = records.into_parts();

    assert!(!UNIVERSAL_CPG);
    assert!(nodes.iter().any(|node| node.node_kind == GraphNodeKind::Resource));
    assert!(edges.iter().any(|edge| edge.relation == GraphRelation::Refs));
    assert!(edges.iter().any(|edge| edge.relation == GraphRelation::ReadsFrom));

    let projection = GraphProjection::from_records(nodes, edges)
        .expect("existing sentrdel-graph projection accepts canonical R3 records");
    assert_eq!(projection.node_count(), 4);
    assert_eq!(projection.edge_count(), 2);
}
