#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        elevated_client::{
            ElevatedClientInputs, R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION, evaluate_elevated_client,
        },
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
            ConfidenceBasis, CrossLayerLink, DataOperation, DataOperationKind, DominanceScope,
            FrameworkFamily, GuardKind, GuardObservation, HttpMethod, InvariantDefinition,
            InvariantEvaluationState, InvariantKind, InvariantRequirement, InvariantScope,
            InvariantSource, LinkBasis, ProviderAuthorityClass, ProviderClientAuthority,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
            TrustBasis,
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
        NormalizedRepoPath::parse("src/r3-t024-correlation.ts", 4_096).expect("normalized path"),
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
        FrameworkFamily::SupabaseEdge,
        HttpMethod::Delete,
        "/internal/accounts/:id",
        Some("handler".to_owned()),
        Vec::new(),
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn actor() -> ActorContext {
    ActorContext::new(
        id("r3.t024.correlation.actor", "request-id"),
        ActorIdentityKind::RequestControlled,
        ActorSourceKind::RequestParam,
        "request.params.id",
        TrustBasis::DirectObservation,
        vec![location(20)],
        limits(),
    )
    .expect("actor")
}

fn guard(actor: &ActorContext, dominance: DominanceScope) -> GuardObservation {
    GuardObservation::new(
        id("r3.t024.correlation.guard", "required-role"),
        GuardKind::RequiredRole,
        Some(actor.actor_id().clone()),
        Some(resource()),
        vec!["admin".to_owned()],
        ComparisonShape::Equal,
        dominance,
        vec![location(40)],
        limits(),
    )
    .expect("guard")
}

fn client(authority: ProviderAuthorityClass) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        id("r3.t024.correlation.client", "supabase"),
        "supabase",
        authority,
        vec!["evidence:r2-key-boundary".to_owned()],
        vec![location(60)],
        limits(),
    )
    .expect("provider client")
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
        None,
        vec![location(80)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn link(
    name: &str,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
) -> CrossLayerLink {
    CrossLayerLink::new(
        id("r3.t024.correlation.link", name),
        source.clone(),
        target.clone(),
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![location(100)],
        limits(),
    )
    .expect("link")
}

fn invariant() -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "elevated-client-correlation"),
        InvariantKind::ElevatedClientContext,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/internal/accounts/:id".to_owned()),
            vec![HttpMethod::Delete],
            Some(resource()),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::ElevatedClientContext {
            allowed_server_contexts: Vec::new(),
            required_guard_kinds: vec![GuardKind::RequiredRole],
        },
        vec![location(120)],
        limits(),
    )
    .expect("invariant")
}

#[test]
fn production_correlator_qualifies_guard_and_makes_elevated_path_satisfiable() {
    let route = route();
    let actor = actor();
    let guard = guard(&actor, DominanceScope::SameHandlerPrefix);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(&client);
    let links = vec![
        link(
            "route-actor",
            route.route_id(),
            actor.actor_id(),
            "route_receives_actor",
        ),
        link(
            "guard-operation",
            guard.guard_id(),
            operation.operation_id(),
            "guard_precedes_operation",
        ),
    ];

    let result = correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: std::slice::from_ref(&actor),
            guards: std::slice::from_ref(&guard),
            values: &[],
            data_operations: std::slice::from_ref(&operation),
            provider_clients: std::slice::from_ref(&client),
            links: &links,
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlate path");

    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    let path = &result.paths()[0];
    assert!(path.links().iter().any(|value| {
        value.source_semantic_id() == route.route_id()
            && value.target_semantic_id() == guard.guard_id()
            && value.relation() == R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
    }));
    assert!(path.links().iter().any(|value| {
        value.source_semantic_id() == guard.guard_id()
            && value.target_semantic_id() == operation.operation_id()
            && value.relation() == R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
    }));

    let evaluation = evaluate_elevated_client(
        ElevatedClientInputs {
            invariant: &invariant(),
            path,
            route: &route,
            actor_coverage_state: &CoverageState::Covered,
            guard_coverage_state: &CoverageState::Covered,
            actors: &[actor],
            guards: &[guard],
            provider_clients: &[client],
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluate correlated elevated path");
    assert_eq!(evaluation.state(), InvariantEvaluationState::Satisfied);
}

#[test]
fn production_correlator_does_not_mint_elevated_links_from_unknown_guard_dominance() {
    let route = route();
    let actor = actor();
    let guard = guard(&actor, DominanceScope::Unknown);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(&client);
    let links = vec![
        link(
            "route-actor-unknown",
            route.route_id(),
            actor.actor_id(),
            "route_receives_actor",
        ),
        link(
            "guard-operation-unknown",
            guard.guard_id(),
            operation.operation_id(),
            "guard_precedes_operation",
        ),
    ];

    let result = correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: std::slice::from_ref(&actor),
            guards: std::slice::from_ref(&guard),
            values: &[],
            data_operations: std::slice::from_ref(&operation),
            provider_clients: std::slice::from_ref(&client),
            links: &links,
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlate path");

    assert_eq!(result.paths().len(), 1);
    let path = &result.paths()[0];
    assert!(!path.links().iter().any(|value| {
        matches!(
            value.relation(),
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
                | R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
        )
    }));

    let evaluation = evaluate_elevated_client(
        ElevatedClientInputs {
            invariant: &invariant(),
            path,
            route: &route,
            actor_coverage_state: &CoverageState::Covered,
            guard_coverage_state: &CoverageState::Partial,
            actors: &[actor],
            guards: &[guard],
            provider_clients: &[client],
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluate unresolved correlated elevated path");
    assert_eq!(evaluation.state(), InvariantEvaluationState::Unknown);
}
