#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
            ConfidenceBasis, CrossLayerLink, CrossLayerPath, DataOperation, DataOperationKind,
            DominanceScope, FilterOperator, FilterPredicate, FrameworkFamily, GuardKind,
            GuardObservation, HttpMethod, InvariantDefinition, InvariantEvaluationState,
            InvariantKind, InvariantRequirement, InvariantScope, InvariantSource, LinkBasis,
            PathState, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
            StableSemanticId, TrustBasis, ValueOrigin, ValueOriginKind,
        },
        tenant_binding::{TenantBindingInputs, evaluate_tenant_binding},
    },
    view::NormalizedRepoPath,
};
use sentrdel_schema::coverage::CoverageState;

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable id")
}

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/r3-t021-field-regression.js", 4_096)
            .expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("location")
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

fn link(
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
        "r3_t021_field_regression",
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![location(start)],
        limits(),
    )
    .expect("link")
}

fn evaluate_with_guard_fields(required_values: Vec<String>) -> InvariantEvaluationState {
    let callback_id = id("r3.t021.regression.callback", "handler");
    let route = RouteObservation::new(
        id("r3.t021.regression.route", "account"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/accounts/:id",
        Some("handler".to_owned()),
        vec![callback_id],
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route");

    let actor = ActorContext::new(
        id("r3.t021.regression.actor", "user"),
        ActorIdentityKind::AuthenticatedUser,
        ActorSourceKind::VerifiedAuthAdapter,
        "req.user",
        TrustBasis::DirectObservation,
        vec![location(20)],
        limits(),
    )
    .expect("actor");

    let value = ValueOrigin::new(
        id("r3.t021.regression.value", "request-user-id"),
        ValueOriginKind::RequestPath,
        "req.params.user_id",
        None,
        Vec::new(),
        0,
        vec![location(40)],
        limits(),
    )
    .expect("value");

    let guard = GuardObservation::new(
        id("r3.t021.regression.guard", "ownership"),
        GuardKind::OwnershipBinding,
        Some(actor.actor_id().clone()),
        None,
        required_values,
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        vec![location(60)],
        limits(),
    )
    .expect("guard");

    let filter = FilterPredicate::new(
        "user_id",
        FilterOperator::Eq,
        value.value_id().clone(),
        location(80),
        limits(),
    )
    .expect("filter");
    let operation = DataOperation::new(
        id("r3.t021.regression.operation", "read-account"),
        DataOperationKind::Read,
        resource(),
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
    .expect("operation");

    let links = vec![
        link(
            "r3.t021.regression.actor-guard",
            actor.actor_id().clone(),
            guard.guard_id().clone(),
            120,
        ),
        link(
            "r3.t021.regression.guard-value",
            guard.guard_id().clone(),
            value.value_id().clone(),
            140,
        ),
        link(
            "r3.t021.regression.value-operation",
            value.value_id().clone(),
            operation.operation_id().clone(),
            160,
        ),
    ];
    let path = CrossLayerPath::new(
        id("r3.t021.regression.path", "account"),
        route.route_id().clone(),
        vec![actor.actor_id().clone()],
        vec![guard.guard_id().clone()],
        operation.operation_id().clone(),
        None,
        links,
        Vec::new(),
        PathState::Supported,
        vec![location(180)],
        limits(),
    )
    .expect("path");

    let invariant = InvariantDefinition::new(
        id(
            "sentrdel.r3.builtin-invariant",
            "tenant-binding-field-regression",
        ),
        InvariantKind::TenantBinding,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/accounts/:id".to_owned()),
            vec![HttpMethod::Get],
            Some(resource()),
            vec![DataOperationKind::Read],
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::TenantBinding {
            resource_tenant_field: "user_id".to_owned(),
            required_actor_identity: ActorIdentityKind::AuthenticatedUser,
        },
        vec![location(200)],
        limits(),
    )
    .expect("invariant");

    evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: std::slice::from_ref(&guard),
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation")
    .state()
}

#[test]
fn guard_for_different_field_cannot_satisfy_tenant_binding() {
    let state = evaluate_with_guard_fields(vec!["different_field".to_owned()]);
    assert_eq!(state, InvariantEvaluationState::Violated);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn guard_without_field_semantics_remains_unknown() {
    let state = evaluate_with_guard_fields(Vec::new());
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}
