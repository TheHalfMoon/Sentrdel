use sentrdel_review::{
    business_logic::{
        graph::{R3GraphLimits, R3GraphMappingError, map_validated_observations},
        model::{
            BusinessLogicLimits, DataOperation, DataOperationKind, FrameworkFamily, HttpMethod,
            InvariantDefinition, InvariantKind, InvariantRequirement, InvariantScope,
            InvariantSource, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
            StableSemanticId,
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

fn over_cap_provenance(path: &str) -> Vec<SourceLocation> {
    vec![location(path, 0), location(path, 16)]
}

fn one_provenance_limit() -> R3GraphLimits {
    R3GraphLimits {
        max_provenance_ids_per_record: 1,
        ..R3GraphLimits::default()
    }
}

fn assert_provenance_cap(error: R3GraphMappingError) {
    assert!(matches!(
        error,
        R3GraphMappingError::ProvenanceLimitExceeded { maximum: 1 }
    ));
}

#[test]
fn route_initial_record_provenance_cap_fails_closed() {
    let route = RouteObservation::new(
        id("r3.route", "provenance-cap-route"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/profiles/:id",
        Some("src/routes/profiles.js::handler".to_owned()),
        Vec::new(),
        over_cap_provenance("src/routes/profiles.js"),
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("route");

    let error = map_validated_observations(&[route], &[], &[], one_provenance_limit())
        .expect_err("route provenance must exceed the configured cap");
    assert_provenance_cap(error);
}

#[test]
fn data_operation_initial_record_provenance_cap_fails_closed() {
    let operation = DataOperation::new(
        id("r3.operation", "provenance-cap-read"),
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
        over_cap_provenance("src/data/profiles.js"),
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("data operation");

    let error = map_validated_observations(&[], &[operation], &[], one_provenance_limit())
        .expect_err("data-operation provenance must exceed the configured cap");
    assert_provenance_cap(error);
}

#[test]
fn invariant_initial_record_provenance_cap_fails_closed() {
    let invariant = InvariantDefinition::new(
        id("r3.invariant", "provenance-cap-role"),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            None,
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
            BusinessLogicLimits::default(),
        )
        .expect("invariant scope"),
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        over_cap_provenance("src/security/invariants.rs"),
        BusinessLogicLimits::default(),
    )
    .expect("invariant");

    let error = map_validated_observations(&[], &[], &[invariant], one_provenance_limit())
        .expect_err("invariant provenance must exceed the configured cap");
    assert_provenance_cap(error);
}
