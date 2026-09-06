#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        model::{
            BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink, DataOperation,
            DataOperationKind, DominanceScope, FrameworkFamily, GuardKind, GuardObservation,
            HttpMethod, InvariantDefinition, InvariantEvaluationState, InvariantKind,
            InvariantRequirement, InvariantScope, InvariantSource, LinkBasis, PathState,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
        },
        path::{PathCorrelationInputs, PathCorrelationLimits, correlate_cross_layer_paths},
        required_role::{
            R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION, R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION,
            RequiredRoleInputs, evaluate_required_role,
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

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/r3-t022-correlation.js", 4_096).expect("normalized path"),
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
        id("r3.t022.correlation.route", "admin-delete"),
        FrameworkFamily::Express,
        HttpMethod::Delete,
        "/admin/accounts/:id",
        Some("handler".to_owned()),
        Vec::new(),
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn operation() -> DataOperation {
    DataOperation::new(
        id("r3.t022.correlation.operation", "delete-account"),
        DataOperationKind::Delete,
        resource(),
        None,
        Vec::new(),
        None,
        None,
        None,
        None,
        vec![location(80)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn role_guard(dominance: DominanceScope) -> GuardObservation {
    GuardObservation::new(
        id("r3.t022.correlation.guard", "admin"),
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
        id("r3.t022.correlation.link", name),
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
    links: &[CrossLayerLink],
) -> sentrdel_review::business_logic::path::PathCorrelationResult {
    correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: std::slice::from_ref(route),
            actors: &[],
            guards: std::slice::from_ref(guard),
            values: &[],
            data_operations: std::slice::from_ref(operation),
            provider_clients: &[],
            links,
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlate required-role path")
}

fn invariant() -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "required-role-correlation"),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/admin/accounts/:id".to_owned()),
            vec![HttpMethod::Delete],
            Some(resource()),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("invariant scope"),
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        vec![location(100)],
        limits(),
    )
    .expect("required-role invariant")
}

#[test]
fn supported_correlated_role_guard_produces_authorization_links_and_satisfies() {
    let route = route();
    let operation = operation();
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

    let result = correlate(&route, &guard, &operation, &links);
    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    let path = &result.paths()[0];
    assert_eq!(path.path_state(), PathState::Supported);
    assert!(path.links().iter().any(|link| {
        link.source_semantic_id() == route.route_id()
            && link.target_semantic_id() == guard.guard_id()
            && link.relation() == R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION
            && link.basis() == LinkBasis::ExplicitAdapterLink
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
    assert!(path.links().iter().any(|link| {
        link.source_semantic_id() == guard.guard_id()
            && link.target_semantic_id() == operation.operation_id()
            && link.relation() == R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION
            && link.basis() == LinkBasis::ExplicitAdapterLink
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));

    let evaluation = evaluate_required_role(
        RequiredRoleInputs {
            invariant: &invariant(),
            path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: std::slice::from_ref(&guard),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluate correlated role guard");
    assert_eq!(evaluation.state(), InvariantEvaluationState::Satisfied);
}

#[test]
fn unknown_dominance_never_mints_authorization_links() {
    let route = route();
    let operation = operation();
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

    let result = correlate(&route, &guard, &operation, &links);
    let path = result.paths().first().expect("partial path remains visible");
    assert_ne!(path.path_state(), PathState::Supported);
    assert!(path.links().iter().all(|link| {
        link.relation() != R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION
            && link.relation() != R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION
    }));

    let evaluation = evaluate_required_role(
        RequiredRoleInputs {
            invariant: &invariant(),
            path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: std::slice::from_ref(&guard),
            operation: &operation,
        },
        limits(),
    )
    .expect("unknown dominance evaluation");
    assert_eq!(evaluation.state(), InvariantEvaluationState::Unknown);
}

#[test]
fn unrelated_role_observation_outside_the_correlated_path_gets_no_authority_links() {
    let route = route();
    let operation = operation();
    let guard = role_guard(DominanceScope::SameHandlerPrefix);
    let links = vec![generic_link(
        "route-operation-only",
        route.route_id().clone(),
        operation.operation_id().clone(),
        ConfidenceBasis::Extracted,
    )];

    let result = correlate(&route, &guard, &operation, &links);
    let path = result.paths().first().expect("route-operation path");
    assert!(path.guard_ids().is_empty());
    assert!(path.links().iter().all(|link| {
        link.relation() != R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION
            && link.relation() != R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION
    }));
}

#[test]
fn ambiguous_connectivity_never_mints_authorization_links() {
    let route = route();
    let operation = operation();
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

    let result = correlate(&route, &guard, &operation, &links);
    let path = result.paths().first().expect("ambiguous path remains visible");
    assert_eq!(path.path_state(), PathState::Ambiguous);
    assert!(path.links().iter().all(|link| {
        link.relation() != R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION
            && link.relation() != R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION
    }));
}
