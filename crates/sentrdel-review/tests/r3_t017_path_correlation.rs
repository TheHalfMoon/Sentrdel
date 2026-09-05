use sentrdel_review::{
    business_logic::{
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
            ConfidenceBasis, CrossLayerLink, DataOperation, DataOperationKind, DominanceScope,
            FilterOperator, FilterPredicate, FrameworkFamily, GuardKind, GuardObservation,
            HttpMethod, LinkBasis, PathState, ProviderAuthorityClass, ProviderClientAuthority,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
            TrustBasis, ValueOrigin, ValueOriginKind,
        },
        path::{
            PathCorrelationDiagnosticReason, PathCorrelationInputs, PathCorrelationLimits,
            R3_PATH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY,
            R3_PATH_CORRELATION_CLASSIFIES_PROVIDER_AUTHORITY,
            R3_PATH_CORRELATION_CONSUMES_R2_EVIDENCE, R3_PATH_CORRELATION_CREATES_FINDINGS,
            R3_PATH_CORRELATION_EXECUTES_TARGET_CODE, R3_PATH_CORRELATION_PERFORMS_NETWORK_ACCESS,
            correlate_cross_layer_paths,
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

fn location(path: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse(path, 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn route(callback: StableSemanticId, coverage: CoverageState) -> RouteObservation {
    RouteObservation::new(
        id("r3.route", "fixture-route"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/profiles/:id",
        Some("handler".to_owned()),
        vec![callback],
        vec![location("src/routes.js", 0)],
        coverage,
        limits(),
    )
    .expect("route")
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

fn operation(
    handler: Option<StableSemanticId>,
    provider_client: Option<StableSemanticId>,
    filters: Vec<FilterPredicate>,
    coverage: CoverageState,
) -> DataOperation {
    DataOperation::new(
        id("r3.operation", "fixture-read"),
        DataOperationKind::Read,
        resource(),
        provider_client,
        filters,
        None,
        None,
        None,
        handler,
        vec![location("src/data.js", 100)],
        coverage,
        limits(),
    )
    .expect("operation")
}

fn actor() -> ActorContext {
    ActorContext::new(
        id("r3.actor", "authenticated-user"),
        ActorIdentityKind::AuthenticatedUser,
        ActorSourceKind::VerifiedAuthAdapter,
        "auth.user.id",
        TrustBasis::DirectObservation,
        vec![location("src/auth.js", 200)],
        limits(),
    )
    .expect("actor")
}

fn guard(actor_id: StableSemanticId) -> GuardObservation {
    GuardObservation::new(
        id("r3.guard", "tenant-binding"),
        GuardKind::TenantBinding,
        Some(actor_id),
        None,
        vec!["tenant_id".to_owned()],
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        vec![location("src/guards.js", 300)],
        limits(),
    )
    .expect("guard")
}

fn value(kind: ValueOriginKind) -> ValueOrigin {
    ValueOrigin::new(
        id("r3.value", "request-tenant"),
        kind,
        "req.params.tenantId",
        None,
        Vec::new(),
        0,
        vec![location("src/routes.js", 400)],
        limits(),
    )
    .expect("value")
}

fn client(client_id: StableSemanticId) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        client_id,
        "supabase",
        ProviderAuthorityClass::UserScoped,
        Vec::new(),
        vec![location("src/client.js", 500)],
        limits(),
    )
    .expect("provider client")
}

fn explicit_link(
    namespace: &str,
    source: StableSemanticId,
    target: StableSemanticId,
    relation: &str,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
    start: usize,
) -> CrossLayerLink {
    CrossLayerLink::new(
        StableSemanticId::from_parts(namespace, &[source.as_str(), target.as_str()], limits())
            .expect("link id"),
        source,
        target,
        relation,
        basis,
        confidence,
        vec![location("src/link.js", start)],
        limits(),
    )
    .expect("cross-layer link")
}

fn inputs<'a>(
    routes: &'a [RouteObservation],
    actors: &'a [ActorContext],
    guards: &'a [GuardObservation],
    values: &'a [ValueOrigin],
    operations: &'a [DataOperation],
    clients: &'a [ProviderClientAuthority],
    links: &'a [CrossLayerLink],
) -> PathCorrelationInputs<'a> {
    PathCorrelationInputs {
        routes,
        actors,
        guards,
        values,
        data_operations: operations,
        provider_clients: clients,
        links,
    }
}

#[test]
fn validated_callback_and_handler_identity_produce_supported_path() {
    let callback = id("r3.callback", "handler");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        None,
        Vec::new(),
        CoverageState::Covered,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].path_state(), PathState::Supported);
    assert!(result.diagnostics().is_empty());
    assert!(result.paths()[0].r2_evidence_ids().is_empty());
}

#[test]
fn explicit_actor_guard_value_operation_and_client_chain_is_preserved() {
    let callback = id("r3.callback", "handler");
    let actor = actor();
    let guard = guard(actor.actor_id().clone());
    let value = value(ValueOriginKind::RequestPath);
    let client_id = id("r3.client", "user-scoped");
    let filter = FilterPredicate::new(
        "tenant_id",
        FilterOperator::Eq,
        value.value_id().clone(),
        location("src/data.js", 108),
        limits(),
    )
    .expect("filter");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let actors = vec![actor.clone()];
    let guards = vec![guard.clone()];
    let values = vec![value.clone()];
    let operations = vec![operation(
        None,
        Some(client_id.clone()),
        vec![filter],
        CoverageState::Covered,
    )];
    let clients = vec![client(client_id.clone())];
    let links = vec![
        explicit_link(
            "r3.test.callback-actor",
            callback,
            actor.actor_id().clone(),
            "authenticated_actor",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            600,
        ),
        explicit_link(
            "r3.test.guard-value",
            guard.guard_id().clone(),
            value.value_id().clone(),
            "guarded_value",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            620,
        ),
    ];

    let result = correlate_cross_layer_paths(
        inputs(
            &routes,
            &actors,
            &guards,
            &values,
            &operations,
            &clients,
            &links,
        ),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Covered);
    assert_eq!(result.paths().len(), 1);
    let path = &result.paths()[0];
    assert_eq!(path.path_state(), PathState::Supported);
    assert_eq!(path.actor_ids(), &[actor.actor_id().clone()]);
    assert_eq!(path.guard_ids(), &[guard.guard_id().clone()]);
    assert_eq!(path.provider_client_id(), Some(&client_id));
    assert!(path.r2_evidence_ids().is_empty());
    assert!(path.links().iter().any(|link| {
        link.source_semantic_id() == value.value_id()
            && link.target_semantic_id() == operations[0].operation_id()
    }));
}

#[test]
fn lexical_similarity_and_same_file_never_create_a_path() {
    let callback = id("r3.callback", "same-name");
    let routes = vec![route(callback, CoverageState::Covered)];
    let actors = vec![
        ActorContext::new(
            id("r3.actor", "same-name"),
            ActorIdentityKind::AuthenticatedUser,
            ActorSourceKind::VerifiedAuthAdapter,
            "same-name",
            TrustBasis::DirectObservation,
            vec![location("src/routes.js", 20)],
            limits(),
        )
        .expect("actor"),
    ];
    let values = vec![
        ValueOrigin::new(
            id("r3.value", "same-name"),
            ValueOriginKind::RequestPath,
            "same-name",
            None,
            Vec::new(),
            0,
            vec![location("src/routes.js", 40)],
            limits(),
        )
        .expect("value"),
    ];
    let operations = vec![operation(None, None, Vec::new(), CoverageState::Covered)];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &actors, &[], &values, &operations, &[], &[]),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.paths().is_empty());
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::MissingRouteDataPath
    }));
}

#[test]
fn unknown_value_propagates_partial_path_state() {
    let callback = id("r3.callback", "handler");
    let value = value(ValueOriginKind::Unknown);
    let filter = FilterPredicate::new(
        "tenant_id",
        FilterOperator::Eq,
        value.value_id().clone(),
        location("src/data.js", 108),
        limits(),
    )
    .expect("filter");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let values = vec![value.clone()];
    let operations = vec![operation(None, None, vec![filter], CoverageState::Covered)];
    let links = vec![explicit_link(
        "r3.test.callback-value",
        callback,
        value.value_id().clone(),
        "value_origin",
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        700,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &values, &operations, &[], &links),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].path_state(), PathState::Partial);
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
}

#[test]
fn ambiguous_link_never_becomes_supported() {
    let callback = id("r3.callback", "handler");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(None, None, Vec::new(), CoverageState::Covered)];
    let links = vec![explicit_link(
        "r3.test.ambiguous",
        callback,
        operations[0].operation_id().clone(),
        "ambiguous_bridge",
        LinkBasis::ScipReference,
        ConfidenceBasis::Ambiguous,
        720,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &links),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].path_state(), PathState::Ambiguous);
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
}

#[test]
fn dangling_filter_value_is_visible_and_cannot_clean_the_path() {
    let callback = id("r3.callback", "handler");
    let missing_value = id("r3.value", "missing");
    let filter = FilterPredicate::new(
        "tenant_id",
        FilterOperator::Eq,
        missing_value,
        location("src/data.js", 108),
        limits(),
    )
    .expect("filter");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        None,
        vec![filter],
        CoverageState::Covered,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].path_state(), PathState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::DanglingValueReference
    }));
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
}

#[test]
fn equivalent_input_permutations_are_deterministic() {
    let callback = id("r3.callback", "handler");
    let actor = actor();
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let actors = vec![actor.clone()];
    let operations = vec![operation(None, None, Vec::new(), CoverageState::Covered)];
    let links = vec![
        explicit_link(
            "r3.test.callback-actor",
            callback,
            actor.actor_id().clone(),
            "authenticated_actor",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            800,
        ),
        explicit_link(
            "r3.test.actor-operation",
            actor.actor_id().clone(),
            operations[0].operation_id().clone(),
            "actor_operation",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            820,
        ),
    ];

    let first = correlate_cross_layer_paths(
        inputs(&routes, &actors, &[], &[], &operations, &[], &links),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("first correlation");

    let mut reversed_routes = routes.clone();
    reversed_routes.reverse();
    let mut reversed_actors = actors.clone();
    reversed_actors.reverse();
    let mut reversed_operations = operations.clone();
    reversed_operations.reverse();
    let mut reversed_links = links.clone();
    reversed_links.reverse();
    let second = correlate_cross_layer_paths(
        inputs(
            &reversed_routes,
            &reversed_actors,
            &[],
            &[],
            &reversed_operations,
            &[],
            &reversed_links,
        ),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("second correlation");

    assert_eq!(first, second);
}

#[test]
fn node_and_edge_caps_fail_visible_without_clean_paths() {
    let callback = id("r3.callback", "handler");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        None,
        Vec::new(),
        CoverageState::Covered,
    )];

    let node_limited = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits {
            max_nodes: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("node-limited correlation");
    assert!(node_limited.paths().is_empty());
    assert_eq!(node_limited.coverage_state(), &CoverageState::Partial);
    assert!(node_limited.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::NodeLimitExceeded
    }));

    let edge_limited = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits {
            max_edges: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("edge-limited correlation");
    assert!(edge_limited.paths().is_empty());
    assert_eq!(edge_limited.coverage_state(), &CoverageState::Partial);
    assert!(edge_limited.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::EdgeLimitExceeded
    }));
}

#[test]
fn depth_cap_is_fail_visible() {
    let callback = id("r3.callback", "handler");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        None,
        Vec::new(),
        CoverageState::Covered,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits {
            max_depth: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("depth-limited correlation");

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::DepthLimitExceeded
    }));
}

#[test]
fn candidate_path_cap_is_deterministic_and_fail_visible() {
    let callback = id("r3.callback", "handler");
    let bridge_a = id("r3.bridge", "a");
    let bridge_b = id("r3.bridge", "b");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(None, None, Vec::new(), CoverageState::Covered)];
    let links = vec![
        explicit_link(
            "r3.test.a1",
            callback.clone(),
            bridge_a.clone(),
            "bridge",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            900,
        ),
        explicit_link(
            "r3.test.a2",
            bridge_a,
            operations[0].operation_id().clone(),
            "bridge",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            920,
        ),
        explicit_link(
            "r3.test.b1",
            callback,
            bridge_b.clone(),
            "bridge",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            940,
        ),
        explicit_link(
            "r3.test.b2",
            bridge_b,
            operations[0].operation_id().clone(),
            "bridge",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            960,
        ),
    ];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &links),
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

#[test]
fn observation_cap_rejects_before_correlation_state_is_built() {
    let callback = id("r3.callback", "handler");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        None,
        Vec::new(),
        CoverageState::Covered,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits {
            max_observations: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("observation-limited correlation");

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::ObservationLimitExceeded
    }));
}

#[test]
fn traversal_work_cap_rejects_without_retaining_clean_paths() {
    let callback = id("r3.callback", "handler");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        None,
        Vec::new(),
        CoverageState::Covered,
    )];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &[]),
        limits(),
        PathCorrelationLimits {
            max_work_items: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("work-limited correlation");

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::TraversalWorkLimitExceeded
    }));
}

#[test]
fn frontier_cap_rejects_branch_explosion_without_clean_paths() {
    let callback = id("r3.callback", "handler");
    let bridge_a = id("r3.bridge", "frontier-a");
    let bridge_b = id("r3.bridge", "frontier-b");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(None, None, Vec::new(), CoverageState::Covered)];
    let links = vec![
        explicit_link(
            "r3.test.frontier-a",
            callback.clone(),
            bridge_a,
            "branch",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            980,
        ),
        explicit_link(
            "r3.test.frontier-b",
            callback,
            bridge_b,
            "branch",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
            1_000,
        ),
    ];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &[], &links),
        limits(),
        PathCorrelationLimits {
            max_frontier: 1,
            ..PathCorrelationLimits::default()
        },
    )
    .expect("frontier-limited correlation");

    assert!(result.paths().is_empty());
    assert_eq!(result.coverage_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == PathCorrelationDiagnosticReason::FrontierLimitExceeded
    }));
}

#[test]
fn provider_client_reference_is_consumed_without_r2_or_classification_authority() {
    let callback = id("r3.callback", "handler");
    let client_id = id("r3.client", "user-scoped");
    let routes = vec![route(callback.clone(), CoverageState::Covered)];
    let operations = vec![operation(
        Some(callback),
        Some(client_id.clone()),
        Vec::new(),
        CoverageState::Covered,
    )];
    let clients = vec![client(client_id.clone())];

    let result = correlate_cross_layer_paths(
        inputs(&routes, &[], &[], &[], &operations, &clients, &[]),
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("path correlation");

    assert_eq!(result.paths().len(), 1);
    assert_eq!(result.paths()[0].provider_client_id(), Some(&client_id));
    assert!(result.paths()[0].r2_evidence_ids().is_empty());
    assert_eq!(result.paths()[0].path_state(), PathState::Supported);
}

#[test]
fn t017_authority_canaries_remain_false() {
    const { assert!(!R3_PATH_CORRELATION_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_PATH_CORRELATION_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_PATH_CORRELATION_CLASSIFIES_PROVIDER_AUTHORITY) };
    const { assert!(!R3_PATH_CORRELATION_CONSUMES_R2_EVIDENCE) };
    const { assert!(!R3_PATH_CORRELATION_CREATES_FINDINGS) };
    const { assert!(!R3_PATH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY) };
}
