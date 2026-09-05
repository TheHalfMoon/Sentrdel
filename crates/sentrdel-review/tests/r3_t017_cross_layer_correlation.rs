use sentrdel_review::{
    business_logic::{
        correlation::{
            CorrelationDiagnosticReason, CorrelationInputs, CorrelationLimits,
            R3_CORRELATION_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY,
            R3_CORRELATION_CREATES_FINDINGS, R3_CORRELATION_EXECUTES_TARGET_CODE,
            R3_CORRELATION_PERFORMS_NETWORK_ACCESS, R3_CORRELATION_USES_PROVIDER_CREDENTIALS,
            correlate_cross_layer_paths,
        },
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
            ConfidenceBasis, CrossLayerLink, DataOperation, DataOperationKind, DominanceScope,
            FilterOperator, FilterPredicate, FrameworkFamily, GuardKind, GuardObservation,
            HttpMethod, LinkBasis, PathState, ProviderAuthorityClass, ProviderClientAuthority,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
            TrustBasis, ValueOrigin, ValueOriginKind,
        },
    },
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::coverage::CoverageState;

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path")
}

fn loc(value: &str, start: usize, end: usize) -> SourceLocation {
    SourceLocation::new(
        path(value),
        start,
        end,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("source location")
}

fn resource() -> ResourceRef {
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some("public".to_owned()),
        "profiles",
        ResourceKind::Table,
        None,
        limits(),
    )
    .expect("resource")
}

fn route(route_key: &str, callback: StableSemanticId, start: usize, end: usize) -> RouteObservation {
    RouteObservation::new(
        id("r3.test.route", route_key),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/profiles/:id",
        Some("handler".to_owned()),
        vec![callback],
        vec![loc("src/routes.ts", start, end)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn callback_link(route: &RouteObservation, callback: &StableSemanticId) -> CrossLayerLink {
    CrossLayerLink::new(
        id("r3.test.link", route.route_id().as_str()),
        route.route_id().clone(),
        callback.clone(),
        "callback_chain",
        LinkBasis::SupportedCallbackChain,
        ConfidenceBasis::Extracted,
        route.provenance().to_vec(),
        limits(),
    )
    .expect("callback link")
}

fn actor() -> ActorContext {
    ActorContext::new(
        id("r3.test.actor", "user"),
        ActorIdentityKind::AuthenticatedUser,
        ActorSourceKind::VerifiedAuthAdapter,
        "auth.user.id",
        TrustBasis::DirectObservation,
        vec![loc("src/handler.ts", 20, 30)],
        limits(),
    )
    .expect("actor")
}

fn value(actor: &ActorContext, kind: ValueOriginKind) -> ValueOrigin {
    ValueOrigin::new(
        id("r3.test.value", "user-id"),
        kind,
        "auth.user.id",
        Some(actor.actor_id().clone()),
        Vec::new(),
        0,
        vec![loc("src/handler.ts", 31, 40)],
        limits(),
    )
    .expect("value")
}

fn guard(actor: &ActorContext) -> GuardObservation {
    GuardObservation::new(
        id("r3.test.guard", "tenant-binding"),
        GuardKind::TenantBinding,
        Some(actor.actor_id().clone()),
        Some(resource()),
        Vec::new(),
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        vec![loc("src/handler.ts", 41, 50)],
        limits(),
    )
    .expect("guard")
}

fn client(authority: ProviderAuthorityClass) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        id("r3.test.client", "supabase"),
        "supabase",
        authority,
        vec!["r2:evidence:static-client".to_owned()],
        vec![loc("src/handler.ts", 10, 15)],
        limits(),
    )
    .expect("client")
}

fn operation(
    handler: Option<StableSemanticId>,
    value: Option<&ValueOrigin>,
    client: Option<&ProviderClientAuthority>,
    start: usize,
    end: usize,
) -> DataOperation {
    let filters = value
        .map(|value| {
            vec![FilterPredicate::new(
                "id",
                FilterOperator::Eq,
                value.value_id().clone(),
                loc("src/handler.ts", start, end),
                limits(),
            )
            .expect("filter")]
        })
        .unwrap_or_default();
    DataOperation::new(
        id("r3.test.operation", &format!("{start}-{end}")),
        DataOperationKind::Read,
        resource(),
        client.map(|client| client.client_id().clone()),
        filters,
        None,
        None,
        None,
        handler,
        vec![loc("src/handler.ts", start, end)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

#[test]
fn explicit_route_value_actor_guard_client_path_is_supported_and_deterministic() {
    let handler = id("r3.test.handler", "handler");
    let route = route("primary", handler.clone(), 0, 10);
    let actor = actor();
    let value = value(&actor, ValueOriginKind::AuthenticatedUserId);
    let guard = guard(&actor);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(handler.clone()), Some(&value), Some(&client), 60, 80);
    let link = callback_link(&route, &handler);

    let first = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: std::slice::from_ref(&actor),
            guards: std::slice::from_ref(&guard),
            values: std::slice::from_ref(&value),
            operations: std::slice::from_ref(&operation),
            provider_clients: std::slice::from_ref(&client),
            links: std::slice::from_ref(&link),
        },
        limits(),
        CorrelationLimits::default(),
    )
    .expect("correlation");
    let second = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: std::slice::from_ref(&actor),
            guards: std::slice::from_ref(&guard),
            values: std::slice::from_ref(&value),
            operations: std::slice::from_ref(&operation),
            provider_clients: std::slice::from_ref(&client),
            links: std::slice::from_ref(&link),
        },
        limits(),
        CorrelationLimits::default(),
    )
    .expect("deterministic correlation");

    assert_eq!(first, second);
    assert_eq!(first.coverage_state(), &CoverageState::Covered);
    assert!(first.diagnostics().is_empty());
    assert_eq!(first.paths().len(), 1);
    let path = &first.paths()[0];
    assert_eq!(path.path_state(), PathState::Supported);
    assert_eq!(path.actor_ids(), &[actor.actor_id().clone()]);
    assert_eq!(path.guard_ids(), &[guard.guard_id().clone()]);
    assert_eq!(path.provider_client_id(), Some(client.client_id()));
    assert!(path.r2_evidence_ids().is_empty(), "T018 owns R2 evidence correlation");
    assert!(path.links().iter().any(|link| {
        link.basis() == LinkBasis::SupportedCallbackChain
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
}

#[test]
fn missing_handler_without_structural_containment_is_partial_not_clean() {
    let callback = id("r3.test.handler", "handler");
    let route = route("primary", callback, 0, 10);
    let operation = operation(None, None, None, 60, 80);
    let result = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: &[],
            guards: &[],
            values: &[],
            operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: &[],
        },
        limits(),
        CorrelationLimits::default(),
    )
    .expect("partial correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.paths().is_empty());
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == CorrelationDiagnosticReason::MissingOperationHandler
    }));
}

#[test]
fn proven_inline_structural_containment_can_form_inferred_same_handler_path() {
    let callback = id("r3.test.handler", "inline");
    let route = route("inline", callback, 0, 100);
    let operation = operation(None, None, None, 60, 80);
    let result = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: &[],
            guards: &[],
            values: &[],
            operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: &[],
        },
        limits(),
        CorrelationLimits::default(),
    )
    .expect("structural correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].path_state(), PathState::Supported);
    assert!(result.paths()[0].links().iter().any(|link| {
        link.basis() == LinkBasis::SameHandlerStructural
            && link.confidence_basis() == ConfidenceBasis::Inferred
    }));
}

#[test]
fn shared_handler_across_two_routes_remains_ambiguous() {
    let handler = id("r3.test.handler", "shared");
    let route_a = route("a", handler.clone(), 0, 10);
    let route_b = route("b", handler.clone(), 100, 110);
    let operation = operation(Some(handler.clone()), None, None, 60, 80);
    let links = vec![
        callback_link(&route_a, &handler),
        callback_link(&route_b, &handler),
    ];
    let routes = vec![route_b, route_a];
    let result = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: &routes,
            actors: &[],
            guards: &[],
            values: &[],
            operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: &links,
        },
        limits(),
        CorrelationLimits::default(),
    )
    .expect("ambiguous correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert_eq!(result.paths().len(), 2);
    assert!(result.paths().iter().all(|path| path.path_state() == PathState::Ambiguous));
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == CorrelationDiagnosticReason::AmbiguousRouteForOperation
    }));
}

#[test]
fn unknown_value_origin_propagates_partial_state() {
    let handler = id("r3.test.handler", "handler");
    let route = route("primary", handler.clone(), 0, 10);
    let actor = actor();
    let value = value(&actor, ValueOriginKind::Unknown);
    let operation = operation(Some(handler.clone()), Some(&value), None, 60, 80);
    let link = callback_link(&route, &handler);
    let result = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: std::slice::from_ref(&link),
        },
        limits(),
        CorrelationLimits::default(),
    )
    .expect("unknown correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert_eq!(result.paths()[0].path_state(), PathState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == CorrelationDiagnosticReason::UnknownValueOrigin
    }));
}

#[test]
fn graph_and_depth_caps_fail_visible_instead_of_clean() {
    let handler = id("r3.test.handler", "handler");
    let middle = id("r3.test.handler", "middle");
    let route = route("primary", handler.clone(), 0, 10);
    let operation = operation(Some(handler.clone()), None, None, 60, 80);
    let links = vec![
        CrossLayerLink::new(
            id("r3.test.link", "route-middle"),
            route.route_id().clone(),
            middle.clone(),
            "callback_chain",
            LinkBasis::SupportedCallbackChain,
            ConfidenceBasis::Extracted,
            route.provenance().to_vec(),
            limits(),
        )
        .unwrap(),
        CrossLayerLink::new(
            id("r3.test.link", "middle-handler"),
            middle,
            handler,
            "resolves_to",
            LinkBasis::SupportedImportBinding,
            ConfidenceBasis::Inferred,
            route.provenance().to_vec(),
            limits(),
        )
        .unwrap(),
    ];

    let edge_capped = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: &[],
            guards: &[],
            values: &[],
            operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: &links,
        },
        limits(),
        CorrelationLimits {
            max_graph_edges: 1,
            ..CorrelationLimits::default()
        },
    )
    .expect("edge cap");
    assert_eq!(edge_capped.coverage_state(), &CoverageState::Partial);
    assert!(edge_capped.paths().is_empty());
    assert!(edge_capped.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == CorrelationDiagnosticReason::GraphEdgeLimitExceeded
    }));

    let depth_capped = correlate_cross_layer_paths(
        CorrelationInputs {
            routes: std::slice::from_ref(&route),
            actors: &[],
            guards: &[],
            values: &[],
            operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: &links,
        },
        limits(),
        CorrelationLimits {
            max_traversal_depth: 1,
            ..CorrelationLimits::default()
        },
    )
    .expect("depth cap");
    assert_eq!(depth_capped.coverage_state(), &CoverageState::Partial);
    assert!(depth_capped.paths().is_empty());
    assert!(depth_capped.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == CorrelationDiagnosticReason::TraversalDepthExceeded
    }));
}

#[test]
fn authority_canaries_remain_false() {
    const { assert!(!R3_CORRELATION_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_CORRELATION_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_CORRELATION_USES_PROVIDER_CREDENTIALS) };
    const { assert!(!R3_CORRELATION_CREATES_FINDINGS) };
    const { assert!(!R3_CORRELATION_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY) };
}
