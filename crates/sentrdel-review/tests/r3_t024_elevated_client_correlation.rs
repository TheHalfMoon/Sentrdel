#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        elevated_client::{
            R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
        },
        model::{
            BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink, DataOperation,
            DataOperationKind, DominanceScope, FrameworkFamily, GuardKind, GuardObservation,
            HttpMethod, LinkBasis, PathState, ProviderAuthorityClass, ProviderClientAuthority,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
        },
        path::{PathCorrelationInputs, PathCorrelationLimits, correlate_cross_layer_paths},
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
        NormalizedRepoPath::parse("src/r3-t024-correlation.js", 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn resource() -> ResourceRef {
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some("public".to_owned()),
        "accounts",
        ResourceKind::Table,
        None,
        limits(),
    )
    .expect("resource")
}

fn route() -> RouteObservation {
    RouteObservation::new(
        id("r3.t024.correlation.route", "delete-account"),
        FrameworkFamily::Express,
        HttpMethod::Delete,
        "/accounts/:id",
        Some("deleteAccount".to_owned()),
        Vec::new(),
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn client(authority: ProviderAuthorityClass) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        id("r3.t024.correlation.client", "supabase"),
        "supabase",
        authority,
        vec!["evidence:r3-t024-key-boundary".to_owned()],
        vec![location(20)],
        limits(),
    )
    .expect("client")
}

fn operation(client: &ProviderClientAuthority) -> DataOperation {
    DataOperation::new(
        id("r3.t024.correlation.operation", "delete-account"),
        DataOperationKind::Delete,
        resource(),
        Some(client.client_id().clone()),
        Vec::new(),
        None,
        None,
        None,
        Some(id("r3.t024.correlation.handler", "delete-account")),
        vec![location(80)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn role_guard(dominance: DominanceScope) -> GuardObservation {
    GuardObservation::new(
        id("r3.t024.correlation.guard", "admin"),
        GuardKind::RequiredRole,
        None,
        Some(resource()),
        vec!["admin".to_owned()],
        ComparisonShape::Equal,
        dominance,
        vec![location(40)],
        limits(),
    )
    .expect("role guard")
}

fn generic_link(
    name: &str,
    source: StableSemanticId,
    target: StableSemanticId,
    confidence: ConfidenceBasis,
) -> CrossLayerLink {
    CrossLayerLink::new(
        id("r3.t024.correlation.link", name),
        source,
        target,
        format!("supported_{name}"),
        LinkBasis::ExplicitAdapterLink,
        confidence,
        vec![location(60)],
        limits(),
    )
    .expect("generic link")
}

fn correlate(
    route: &RouteObservation,
    guard: &GuardObservation,
    operation: &DataOperation,
    client: &ProviderClientAuthority,
    links: &[CrossLayerLink],
) -> sentrdel_review::business_logic::path::PathCorrelationResult {
    correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: std::slice::from_ref(route),
            actors: &[],
            guards: std::slice::from_ref(guard),
            values: &[],
            data_operations: std::slice::from_ref(operation),
            provider_clients: std::slice::from_ref(client),
            links,
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlate elevated-client path")
}

#[test]
fn elevated_client_path_mints_application_authorization_links_for_supported_guard() {
    let route = route();
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(&client);
    let guard = role_guard(DominanceScope::SameHandlerPrefix);
    let links = vec![
        generic_link(
            "route-role-guard",
            route.route_id().clone(),
            guard.guard_id().clone(),
            ConfidenceBasis::Extracted,
        ),
        generic_link(
            "role-guard-operation",
            guard.guard_id().clone(),
            operation.operation_id().clone(),
            ConfidenceBasis::Extracted,
        ),
    ];

    let result = correlate(&route, &guard, &operation, &client, &links);
    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    let path = &result.paths()[0];
    assert_eq!(path.path_state(), PathState::Supported);
    assert_eq!(path.provider_client_id(), Some(client.client_id()));
    assert!(path.links().iter().any(|link| {
        link.source_semantic_id() == route.route_id()
            && link.target_semantic_id() == guard.guard_id()
            && link.relation() == R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
            && link.basis() == LinkBasis::ExplicitAdapterLink
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
    assert!(path.links().iter().any(|link| {
        link.source_semantic_id() == guard.guard_id()
            && link.target_semantic_id() == operation.operation_id()
            && link.relation() == R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
            && link.basis() == LinkBasis::ExplicitAdapterLink
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
}

#[test]
fn non_elevated_client_never_mints_elevated_authorization_links() {
    let route = route();
    let client = client(ProviderAuthorityClass::PublishableOrAnon);
    let operation = operation(&client);
    let guard = role_guard(DominanceScope::SameHandlerPrefix);
    let links = vec![
        generic_link(
            "route-role-guard-anon",
            route.route_id().clone(),
            guard.guard_id().clone(),
            ConfidenceBasis::Extracted,
        ),
        generic_link(
            "role-guard-operation-anon",
            guard.guard_id().clone(),
            operation.operation_id().clone(),
            ConfidenceBasis::Extracted,
        ),
    ];

    let result = correlate(&route, &guard, &operation, &client, &links);
    let path = result.paths().first().expect("correlated path");
    assert!(path.links().iter().all(|link| {
        link.relation() != R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
            && link.relation() != R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
    }));
}

#[test]
fn unknown_guard_dominance_never_mints_elevated_authorization_links() {
    let route = route();
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(&client);
    let guard = role_guard(DominanceScope::Unknown);
    let links = vec![
        generic_link(
            "route-role-guard-unknown",
            route.route_id().clone(),
            guard.guard_id().clone(),
            ConfidenceBasis::Extracted,
        ),
        generic_link(
            "role-guard-operation-unknown",
            guard.guard_id().clone(),
            operation.operation_id().clone(),
            ConfidenceBasis::Extracted,
        ),
    ];

    let result = correlate(&route, &guard, &operation, &client, &links);
    let path = result.paths().first().expect("correlated path remains visible");
    assert!(path.links().iter().all(|link| {
        link.relation() != R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
            && link.relation() != R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
    }));
}

#[test]
fn ambiguous_connectivity_never_mints_elevated_authorization_links() {
    let route = route();
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(&client);
    let guard = role_guard(DominanceScope::LinkedHelper);
    let links = vec![
        generic_link(
            "route-role-guard-ambiguous",
            route.route_id().clone(),
            guard.guard_id().clone(),
            ConfidenceBasis::Ambiguous,
        ),
        generic_link(
            "role-guard-operation-ambiguous",
            guard.guard_id().clone(),
            operation.operation_id().clone(),
            ConfidenceBasis::Extracted,
        ),
    ];

    let result = correlate(&route, &guard, &operation, &client, &links);
    let path = result.paths().first().expect("ambiguous path remains visible");
    assert_ne!(path.path_state(), PathState::Supported);
    assert!(path.links().iter().all(|link| {
        link.relation() != R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
            && link.relation() != R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
    }));
}
