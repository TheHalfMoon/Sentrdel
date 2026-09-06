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
        tenant_binding::{
            R3_TENANT_ACTOR_GUARD_RELATION, R3_TENANT_ACTOR_VALUE_RELATION,
            R3_TENANT_GUARD_VALUE_RELATION, R3_TENANT_VALUE_OPERATION_RELATION,
            TenantBindingInputs, evaluate_tenant_binding,
        },
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
    relation: &str,
    start: usize,
) -> CrossLayerLink {
    CrossLayerLink::new(
        StableSemanticId::from_parts(
            namespace,
            &[source.as_str(), target.as_str(), relation],
            limits(),
        )
        .expect("link id"),
        source,
        target,
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![location(start)],
        limits(),
    )
    .expect("link")
}

#[allow(clippy::too_many_arguments)]
fn evaluate_with_guard(
    guard_kind: GuardKind,
    required_values: Vec<String>,
    include_guard_value_link: bool,
    include_unresolved_filter: bool,
    include_unresolved_binding_guard: bool,
    include_unbound_filter: bool,
    direct_binding: bool,
) -> InvariantEvaluationState {
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
        if direct_binding {
            ValueOriginKind::AuthenticatedUserId
        } else {
            ValueOriginKind::RequestPath
        },
        "req.params.user_id",
        direct_binding.then(|| actor.actor_id().clone()),
        Vec::new(),
        0,
        vec![location(40)],
        limits(),
    )
    .expect("value");
    let unbound_value = ValueOrigin::new(
        id("r3.t021.regression.value", "unbound-user-id"),
        ValueOriginKind::RequestQuery,
        "req.query.user_id",
        None,
        Vec::new(),
        0,
        vec![location(50)],
        limits(),
    )
    .expect("unbound value");

    let guard = GuardObservation::new(
        id("r3.t021.regression.guard", "candidate"),
        guard_kind,
        Some(actor.actor_id().clone()),
        None,
        required_values,
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        vec![location(60)],
        limits(),
    )
    .expect("guard");

    let mut guards = vec![guard];
    if include_unresolved_binding_guard {
        guards.push(
            GuardObservation::new(
                id("r3.t021.regression.guard", "unresolved-binding"),
                GuardKind::OwnershipBinding,
                Some(actor.actor_id().clone()),
                None,
                Vec::new(),
                ComparisonShape::Equal,
                DominanceScope::SameHandlerPrefix,
                vec![location(70)],
                limits(),
            )
            .expect("unresolved guard"),
        );
    }

    let mut filters = vec![
        FilterPredicate::new(
            "user_id",
            FilterOperator::Eq,
            value.value_id().clone(),
            location(80),
            limits(),
        )
        .expect("filter"),
    ];
    if include_unresolved_filter {
        filters.push(
            FilterPredicate::new(
                "user_id",
                FilterOperator::OtherSupported,
                value.value_id().clone(),
                location(90),
                limits(),
            )
            .expect("unresolved filter"),
        );
    }
    if include_unbound_filter {
        filters.push(
            FilterPredicate::new(
                "user_id",
                FilterOperator::Eq,
                unbound_value.value_id().clone(),
                location(95),
                limits(),
            )
            .expect("unbound filter"),
        );
    }

    let operation = DataOperation::new(
        id("r3.t021.regression.operation", "read-account"),
        DataOperationKind::Read,
        resource(),
        None,
        filters,
        None,
        None,
        None,
        None,
        vec![location(100)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation");

    let primary_guard_id = guards[0].guard_id().clone();
    let mut links = vec![
        link(
            "r3.t021.regression.actor-guard",
            actor.actor_id().clone(),
            primary_guard_id.clone(),
            R3_TENANT_ACTOR_GUARD_RELATION,
            120,
        ),
        link(
            "r3.t021.regression.value-operation",
            value.value_id().clone(),
            operation.operation_id().clone(),
            R3_TENANT_VALUE_OPERATION_RELATION,
            160,
        ),
    ];
    if direct_binding {
        links.push(link(
            "r3.t021.regression.actor-value",
            actor.actor_id().clone(),
            value.value_id().clone(),
            R3_TENANT_ACTOR_VALUE_RELATION,
            130,
        ));
    }
    if include_guard_value_link {
        links.push(link(
            "r3.t021.regression.guard-value",
            primary_guard_id,
            value.value_id().clone(),
            R3_TENANT_GUARD_VALUE_RELATION,
            140,
        ));
    }
    if let Some(unresolved_guard) = guards.get(1) {
        links.push(link(
            "r3.t021.regression.actor-unresolved-guard",
            actor.actor_id().clone(),
            unresolved_guard.guard_id().clone(),
            R3_TENANT_ACTOR_GUARD_RELATION,
            150,
        ));
    }
    if include_unbound_filter {
        links.push(link(
            "r3.t021.regression.unbound-value-operation",
            unbound_value.value_id().clone(),
            operation.operation_id().clone(),
            R3_TENANT_VALUE_OPERATION_RELATION,
            170,
        ));
    }

    let guard_ids = guards
        .iter()
        .map(|candidate| candidate.guard_id().clone())
        .collect();
    let path = CrossLayerPath::new(
        id("r3.t021.regression.path", "account"),
        route.route_id().clone(),
        vec![actor.actor_id().clone()],
        guard_ids,
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

    let mut values = vec![value];
    if include_unbound_filter {
        values.push(unbound_value);
    }

    evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: &guards,
            values: &values,
            operation: &operation,
        },
        limits(),
    )
    .expect("evaluation")
    .state()
}

#[test]
fn guard_for_different_field_cannot_satisfy_tenant_binding() {
    let state = evaluate_with_guard(
        GuardKind::OwnershipBinding,
        vec!["different_field".to_owned()],
        true,
        false,
        false,
        false,
        false,
    );
    assert_eq!(state, InvariantEvaluationState::Violated);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn binding_guard_without_field_semantics_remains_unknown() {
    let state = evaluate_with_guard(
        GuardKind::OwnershipBinding,
        Vec::new(),
        true,
        false,
        false,
        false,
        false,
    );
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn unrelated_guard_without_field_semantics_does_not_mask_violation() {
    let state = evaluate_with_guard(
        GuardKind::Authentication,
        Vec::new(),
        true,
        false,
        false,
        false,
        false,
    );
    assert_eq!(state, InvariantEvaluationState::Violated);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn binding_guard_with_unresolved_value_link_remains_unknown() {
    let state = evaluate_with_guard(
        GuardKind::OwnershipBinding,
        vec!["user_id".to_owned()],
        false,
        false,
        false,
        false,
        false,
    );
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn satisfied_filter_cannot_hide_another_unresolved_tenant_filter() {
    let state = evaluate_with_guard(
        GuardKind::OwnershipBinding,
        vec!["user_id".to_owned()],
        true,
        true,
        false,
        false,
        false,
    );
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn satisfied_guard_cannot_hide_another_unresolved_binding_guard() {
    let state = evaluate_with_guard(
        GuardKind::OwnershipBinding,
        vec!["user_id".to_owned()],
        true,
        false,
        true,
        false,
        false,
    );
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn one_bound_filter_cannot_hide_another_analyzable_unbound_filter() {
    let state = evaluate_with_guard(
        GuardKind::Authentication,
        Vec::new(),
        false,
        false,
        false,
        true,
        true,
    );
    assert_eq!(state, InvariantEvaluationState::Violated);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn direct_binding_cannot_bypass_unresolved_binding_guard() {
    let state = evaluate_with_guard(
        GuardKind::Authentication,
        Vec::new(),
        false,
        false,
        true,
        false,
        true,
    );
    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}
