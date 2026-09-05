#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
            ConfidenceBasis, CrossLayerLink, DataOperation, DataOperationKind, DominanceScope,
            FilterOperator, FilterPredicate, FrameworkFamily, GuardKind, GuardObservation,
            HttpMethod, InvariantDefinition, InvariantEvaluationState, InvariantKind,
            InvariantRequirement, InvariantScope, InvariantSource, LinkBasis, PathState,
            ResourceKind, ResourceRef, RouteObservation, SourceLocation, StableSemanticId,
            TrustBasis, ValueOrigin, ValueOriginKind,
        },
        path::{PathCorrelationInputs, PathCorrelationLimits, correlate_cross_layer_paths},
        tenant_binding::{
            R3_TENANT_BINDING_CREATES_FINDINGS, R3_TENANT_BINDING_EXECUTES_TARGET_CODE,
            R3_TENANT_BINDING_PERFORMS_NETWORK_ACCESS,
            R3_TENANT_BINDING_PROVES_RUNTIME_AUTHORIZATION, TenantBindingInputs,
            evaluate_tenant_binding,
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
        NormalizedRepoPath::parse("src/r3-t021.js", 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
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

fn route(callback: StableSemanticId) -> RouteObservation {
    RouteObservation::new(
        id("r3.t021.route", "account"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/accounts/:id",
        Some("handler".to_owned()),
        vec![callback],
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn actor(name: &str, identity: ActorIdentityKind) -> ActorContext {
    ActorContext::new(
        id("r3.t021.actor", name),
        identity,
        ActorSourceKind::VerifiedAuthAdapter,
        format!("auth.{name}"),
        TrustBasis::DirectObservation,
        vec![location(20)],
        limits(),
    )
    .expect("actor")
}

fn value(name: &str, kind: ValueOriginKind, source_actor: Option<StableSemanticId>) -> ValueOrigin {
    ValueOrigin::new(
        id("r3.t021.value", name),
        kind,
        format!("value.{name}"),
        source_actor,
        Vec::new(),
        0,
        vec![location(40)],
        limits(),
    )
    .expect("value")
}

fn guard(actor_id: StableSemanticId, kind: GuardKind, field: &str) -> GuardObservation {
    GuardObservation::new(
        id("r3.t021.guard", field),
        kind,
        Some(actor_id),
        None,
        vec![field.to_owned()],
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        vec![location(60)],
        limits(),
    )
    .expect("guard")
}

fn operation(value_id: StableSemanticId, field: &str) -> DataOperation {
    let filter = FilterPredicate::new(field, FilterOperator::Eq, value_id, location(80), limits())
        .expect("filter");
    DataOperation::new(
        id("r3.t021.operation", "read-account"),
        DataOperationKind::Read,
        resource("accounts"),
        None,
        vec![filter],
        None,
        None,
        None,
        None,
        vec![location(100)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn explicit_link(
    namespace: &str,
    source: StableSemanticId,
    target: StableSemanticId,
    start: usize,
) -> CrossLayerLink {
    CrossLayerLink::new(
        StableSemanticId::from_parts(namespace, &[source.as_str(), target.as_str()], limits())
            .expect("link id"),
        source,
        target,
        "r3_t021_bridge",
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![location(start)],
        limits(),
    )
    .expect("link")
}

fn definition(
    field: &str,
    identity: ActorIdentityKind,
    resource_name: &str,
) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "tenant-binding"),
        InvariantKind::TenantBinding,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/accounts/:id".to_owned()),
            vec![HttpMethod::Get],
            Some(resource(resource_name)),
            vec![DataOperationKind::Read],
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::TenantBinding {
            resource_tenant_field: field.to_owned(),
            required_actor_identity: identity,
        },
        vec![location(140)],
        limits(),
    )
    .expect("tenant-binding invariant")
}

fn correlate<'a>(
    routes: &'a [RouteObservation],
    actors: &'a [ActorContext],
    guards: &'a [GuardObservation],
    values: &'a [ValueOrigin],
    operations: &'a [DataOperation],
    links: &'a [CrossLayerLink],
) -> sentrdel_review::business_logic::path::PathCorrelationResult {
    correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes,
            actors,
            guards,
            values,
            data_operations: operations,
            provider_clients: &[],
            links,
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlation")
}

#[test]
fn guarded_request_value_binding_is_satisfied_only_on_supported_path() {
    let callback = id("r3.t021.callback", "handler");
    let actor = actor("user", ActorIdentityKind::AuthenticatedUser);
    let guard = guard(
        actor.actor_id().clone(),
        GuardKind::OwnershipBinding,
        "user_id",
    );
    let value = value("request-user-id", ValueOriginKind::RequestPath, None);
    let operation = operation(value.value_id().clone(), "user_id");
    let route = route(callback.clone());
    let links = vec![
        explicit_link(
            "r3.t021.callback-actor",
            callback,
            actor.actor_id().clone(),
            160,
        ),
        explicit_link(
            "r3.t021.guard-value",
            guard.guard_id().clone(),
            value.value_id().clone(),
            180,
        ),
    ];
    let result = correlate(
        std::slice::from_ref(&route),
        std::slice::from_ref(&actor),
        std::slice::from_ref(&guard),
        std::slice::from_ref(&value),
        std::slice::from_ref(&operation),
        &links,
    );
    let path = result.paths().first().expect("supported path");
    assert_eq!(path.path_state(), PathState::Supported);

    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &definition("user_id", ActorIdentityKind::AuthenticatedUser, "accounts"),
            path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: std::slice::from_ref(&guard),
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation");

    assert_eq!(evaluation.state(), InvariantEvaluationState::Satisfied);
    assert!(evaluation.contradicting_observation_ids().is_empty());
}

#[test]
fn covered_request_filter_without_supported_binding_is_violated() {
    let callback = id("r3.t021.callback", "unsafe-handler");
    let actor = actor("unsafe-user", ActorIdentityKind::AuthenticatedUser);
    let value = value("unsafe-request-user-id", ValueOriginKind::RequestPath, None);
    let operation = operation(value.value_id().clone(), "user_id");
    let route = route(callback.clone());
    let links = vec![
        explicit_link(
            "r3.t021.callback-actor-unsafe",
            callback,
            actor.actor_id().clone(),
            200,
        ),
        explicit_link(
            "r3.t021.actor-value-unsafe",
            actor.actor_id().clone(),
            value.value_id().clone(),
            220,
        ),
    ];
    let result = correlate(
        std::slice::from_ref(&route),
        std::slice::from_ref(&actor),
        &[],
        std::slice::from_ref(&value),
        std::slice::from_ref(&operation),
        &links,
    );
    let path = result.paths().first().expect("covered unsafe path");
    assert_eq!(path.path_state(), PathState::Supported);

    let invariant = definition("user_id", ActorIdentityKind::AuthenticatedUser, "accounts");
    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation");

    assert_eq!(evaluation.state(), InvariantEvaluationState::Violated);
    assert!(!evaluation.contradicting_observation_ids().is_empty());
}

#[test]
fn authenticated_identity_value_can_supply_direct_supported_binding() {
    let callback = id("r3.t021.callback", "direct-handler");
    let actor = actor("direct-user", ActorIdentityKind::AuthenticatedUser);
    let value = value(
        "authenticated-user-id",
        ValueOriginKind::AuthenticatedUserId,
        Some(actor.actor_id().clone()),
    );
    let operation = operation(value.value_id().clone(), "user_id");
    let route = route(callback.clone());
    let links = vec![explicit_link(
        "r3.t021.callback-actor-direct",
        callback,
        actor.actor_id().clone(),
        240,
    )];
    let result = correlate(
        std::slice::from_ref(&route),
        std::slice::from_ref(&actor),
        &[],
        std::slice::from_ref(&value),
        std::slice::from_ref(&operation),
        &links,
    );
    let path = result.paths().first().expect("supported direct path");

    let invariant = definition("user_id", ActorIdentityKind::AuthenticatedUser, "accounts");
    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation");

    assert_eq!(evaluation.state(), InvariantEvaluationState::Satisfied);
}

#[test]
fn partial_or_ambiguous_path_remains_unknown_and_cannot_satisfy() {
    let callback = id("r3.t021.callback", "unknown-handler");
    let actor = actor("unknown-user", ActorIdentityKind::AuthenticatedUser);
    let value = value("unknown-request-user", ValueOriginKind::RequestPath, None);
    let operation = operation(value.value_id().clone(), "user_id");
    let route = route(callback.clone());
    let ambiguous = CrossLayerLink::new(
        id("r3.t021.link", "ambiguous"),
        callback,
        operation.operation_id().clone(),
        "ambiguous_bridge",
        LinkBasis::ScipReference,
        ConfidenceBasis::Ambiguous,
        vec![location(260)],
        limits(),
    )
    .expect("ambiguous link");
    let links = vec![ambiguous];
    let result = correlate(
        std::slice::from_ref(&route),
        std::slice::from_ref(&actor),
        &[],
        std::slice::from_ref(&value),
        std::slice::from_ref(&operation),
        &links,
    );
    let path = result.paths().first().expect("ambiguous path");
    assert_eq!(path.path_state(), PathState::Ambiguous);

    let invariant = definition("user_id", ActorIdentityKind::AuthenticatedUser, "accounts");
    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation");

    assert_eq!(evaluation.state(), InvariantEvaluationState::Unknown);
    assert_ne!(evaluation.state(), InvariantEvaluationState::Satisfied);
}

#[test]
fn scope_mismatch_is_not_applicable() {
    let callback = id("r3.t021.callback", "scope-handler");
    let actor = actor("scope-user", ActorIdentityKind::AuthenticatedUser);
    let value = value(
        "scope-user-id",
        ValueOriginKind::AuthenticatedUserId,
        Some(actor.actor_id().clone()),
    );
    let operation = operation(value.value_id().clone(), "user_id");
    let route = route(callback.clone());
    let links = vec![explicit_link(
        "r3.t021.callback-actor-scope",
        callback,
        actor.actor_id().clone(),
        280,
    )];
    let result = correlate(
        std::slice::from_ref(&route),
        std::slice::from_ref(&actor),
        &[],
        std::slice::from_ref(&value),
        std::slice::from_ref(&operation),
        &links,
    );
    let path = result.paths().first().expect("supported path");

    let invariant = definition(
        "user_id",
        ActorIdentityKind::AuthenticatedUser,
        "different_resource",
    );
    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation");

    assert_eq!(evaluation.state(), InvariantEvaluationState::NotApplicable);
}

#[test]
fn tenant_binding_evaluator_grants_no_runtime_or_finding_authority() {
    const { assert!(!R3_TENANT_BINDING_CREATES_FINDINGS) };
    const { assert!(!R3_TENANT_BINDING_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_TENANT_BINDING_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_TENANT_BINDING_PROVES_RUNTIME_AUTHORIZATION) };
}
