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
            R3_TENANT_ACTOR_GUARD_RELATION, R3_TENANT_GUARD_VALUE_RELATION,
            R3_TENANT_VALUE_OPERATION_RELATION, TenantBindingInputs, evaluate_tenant_binding,
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
        NormalizedRepoPath::parse("src/r3-t021-authority-regression.js", 4_096)
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
    basis: LinkBasis,
    confidence: ConfidenceBasis,
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
        basis,
        confidence,
        vec![location(start)],
        limits(),
    )
    .expect("link")
}

#[allow(clippy::too_many_arguments)]
fn evaluate_guarded_path(
    comparison: ComparisonShape,
    dominance: DominanceScope,
    actor_guard_relation: &str,
    guard_value_relation: &str,
    value_operation_relation: &str,
    guard_value_basis: LinkBasis,
    guard_value_confidence: ConfidenceBasis,
) -> InvariantEvaluationState {
    let route = RouteObservation::new(
        id("r3.t021.authority.route", "account"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/accounts/:id",
        Some("handler".to_owned()),
        Vec::new(),
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route");

    let actor = ActorContext::new(
        id("r3.t021.authority.actor", "user"),
        ActorIdentityKind::AuthenticatedUser,
        ActorSourceKind::VerifiedAuthAdapter,
        "req.user",
        TrustBasis::DirectObservation,
        vec![location(20)],
        limits(),
    )
    .expect("actor");

    let value = ValueOrigin::new(
        id("r3.t021.authority.value", "request-user-id"),
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
        id("r3.t021.authority.guard", "ownership"),
        GuardKind::OwnershipBinding,
        Some(actor.actor_id().clone()),
        None,
        vec!["user_id".to_owned()],
        comparison,
        dominance,
        vec![location(60)],
        limits(),
    )
    .expect("guard");

    let operation = DataOperation::new(
        id("r3.t021.authority.operation", "read-account"),
        DataOperationKind::Read,
        resource(),
        None,
        vec![
            FilterPredicate::new(
                "user_id",
                FilterOperator::Eq,
                value.value_id().clone(),
                location(80),
                limits(),
            )
            .expect("filter"),
        ],
        None,
        None,
        None,
        None,
        vec![location(100)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation");

    let path = CrossLayerPath::new(
        id("r3.t021.authority.path", "account"),
        route.route_id().clone(),
        vec![actor.actor_id().clone()],
        vec![guard.guard_id().clone()],
        operation.operation_id().clone(),
        None,
        vec![
            link(
                "r3.t021.authority.actor-guard",
                actor.actor_id().clone(),
                guard.guard_id().clone(),
                actor_guard_relation,
                120,
                LinkBasis::ExplicitAdapterLink,
                ConfidenceBasis::Extracted,
            ),
            link(
                "r3.t021.authority.guard-value",
                guard.guard_id().clone(),
                value.value_id().clone(),
                guard_value_relation,
                140,
                guard_value_basis,
                guard_value_confidence,
            ),
            link(
                "r3.t021.authority.value-operation",
                value.value_id().clone(),
                operation.operation_id().clone(),
                value_operation_relation,
                160,
                LinkBasis::ExplicitAdapterLink,
                ConfidenceBasis::Extracted,
            ),
        ],
        Vec::new(),
        PathState::Supported,
        vec![location(180)],
        limits(),
    )
    .expect("path");

    let invariant = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "tenant-binding-authority"),
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

fn supported_guarded_path(
    comparison: ComparisonShape,
    dominance: DominanceScope,
    guard_value_basis: LinkBasis,
    guard_value_confidence: ConfidenceBasis,
) -> InvariantEvaluationState {
    evaluate_guarded_path(
        comparison,
        dominance,
        R3_TENANT_ACTOR_GUARD_RELATION,
        R3_TENANT_GUARD_VALUE_RELATION,
        R3_TENANT_VALUE_OPERATION_RELATION,
        guard_value_basis,
        guard_value_confidence,
    )
}

#[test]
fn extracted_supported_guard_baseline_is_satisfied() {
    assert_eq!(
        supported_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Satisfied
    );
}

#[test]
fn unsupported_guard_comparison_remains_unknown() {
    assert_eq!(
        supported_guarded_path(
            ComparisonShape::OtherSupported,
            DominanceScope::SameHandlerPrefix,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unknown_guard_dominance_remains_unknown() {
    assert_eq!(
        supported_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::Unknown,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn inferred_required_link_cannot_upgrade_authority() {
    assert_eq!(
        supported_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Inferred,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unknown_basis_required_link_cannot_upgrade_authority() {
    assert_eq!(
        supported_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            LinkBasis::Unknown,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unrelated_actor_guard_relation_cannot_upgrade_authority() {
    assert_eq!(
        evaluate_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            "unrelated_actor_guard_relation",
            R3_TENANT_GUARD_VALUE_RELATION,
            R3_TENANT_VALUE_OPERATION_RELATION,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unrelated_guard_value_relation_cannot_upgrade_authority() {
    assert_eq!(
        evaluate_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            R3_TENANT_ACTOR_GUARD_RELATION,
            "unrelated_guard_value_relation",
            R3_TENANT_VALUE_OPERATION_RELATION,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unrelated_value_operation_relation_cannot_upgrade_authority() {
    assert_eq!(
        evaluate_guarded_path(
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            R3_TENANT_ACTOR_GUARD_RELATION,
            R3_TENANT_GUARD_VALUE_RELATION,
            "unrelated_value_operation_relation",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ),
        InvariantEvaluationState::Unknown
    );
}
