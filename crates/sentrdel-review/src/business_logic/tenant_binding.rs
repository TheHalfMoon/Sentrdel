//! Bounded R3-T021 tenant/object-binding invariant evaluation.
//!
//! This evaluator consumes only already-normalized R3 observations and a correlated
//! path. It never reparses target source, executes target code, accesses providers,
//! creates Findings, or promotes unresolved semantics into a secure result.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::model::{
    ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
    CrossLayerPath, DataOperation, DominanceScope, FilterOperator, GuardKind, GuardObservation,
    InvariantDefinition, InvariantEvaluation, InvariantEvaluationState, InvariantKind,
    InvariantRequirement, ModelError, PathState, RouteObservation, StableSemanticId, TrustBasis,
    ValueOrigin, ValueOriginKind,
};

pub const R3_TENANT_BINDING_CREATES_FINDINGS: bool = false;
pub const R3_TENANT_BINDING_EXECUTES_TARGET_CODE: bool = false;
pub const R3_TENANT_BINDING_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_TENANT_BINDING_PROVES_RUNTIME_AUTHORIZATION: bool = false;

pub struct TenantBindingInputs<'a> {
    pub invariant: &'a InvariantDefinition,
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub actors: &'a [ActorContext],
    pub guards: &'a [GuardObservation],
    pub values: &'a [ValueOrigin],
    pub operation: &'a DataOperation,
}

#[derive(Debug)]
pub enum TenantBindingError {
    InvalidInvariantKind,
    PathRouteMismatch,
    PathOperationMismatch,
    Model(ModelError),
}

impl fmt::Display for TenantBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvariantKind => {
                formatter.write_str("tenant-binding evaluator requires a tenant-binding invariant")
            }
            Self::PathRouteMismatch => {
                formatter.write_str("tenant-binding path route does not match supplied route")
            }
            Self::PathOperationMismatch => formatter
                .write_str("tenant-binding path operation does not match supplied data operation"),
            Self::Model(source) => write!(
                formatter,
                "tenant-binding model validation failed: {source}"
            ),
        }
    }
}

impl Error for TenantBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for TenantBindingError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn evaluate_tenant_binding(
    inputs: TenantBindingInputs<'_>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, TenantBindingError> {
    let limits = limits.validate()?;
    if inputs.invariant.kind() != InvariantKind::TenantBinding {
        return Err(TenantBindingError::InvalidInvariantKind);
    }
    if inputs.path.route_id() != inputs.route.route_id() {
        return Err(TenantBindingError::PathRouteMismatch);
    }
    if inputs.path.data_operation_id() != inputs.operation.operation_id() {
        return Err(TenantBindingError::PathOperationMismatch);
    }

    let InvariantRequirement::TenantBinding {
        resource_tenant_field,
        required_actor_identity,
    } = inputs.invariant.requirements()
    else {
        return Err(TenantBindingError::InvalidInvariantKind);
    };

    if !scope_applies(
        inputs.invariant,
        inputs.path,
        inputs.route,
        inputs.operation,
    ) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::NotApplicable,
            Vec::new(),
            Vec::new(),
            vec!["tenant_binding_scope_not_applicable".to_owned()],
            limits,
        );
    }

    if !matches!(
        required_actor_identity,
        ActorIdentityKind::AuthenticatedUser | ActorIdentityKind::Tenant
    ) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["unsupported_tenant_binding_actor_identity".to_owned()],
            limits,
        );
    }

    if inputs.path.path_state() != PathState::Supported
        || inputs.route.coverage_state() != &CoverageState::Covered
        || inputs.operation.coverage_state() != &CoverageState::Covered
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["tenant_binding_path_or_operation_not_fully_supported".to_owned()],
            limits,
        );
    }

    let actors = inputs
        .actors
        .iter()
        .map(|actor| (actor.actor_id().as_str(), actor))
        .collect::<BTreeMap<_, _>>();
    let guards = inputs
        .guards
        .iter()
        .map(|guard| (guard.guard_id().as_str(), guard))
        .collect::<BTreeMap<_, _>>();
    let values = inputs
        .values
        .iter()
        .map(|value| (value.value_id().as_str(), value))
        .collect::<BTreeMap<_, _>>();

    if inputs
        .path
        .actor_ids()
        .iter()
        .any(|actor_id| !actors.contains_key(actor_id.as_str()))
        || inputs
            .path
            .guard_ids()
            .iter()
            .any(|guard_id| !guards.contains_key(guard_id.as_str()))
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["tenant_binding_path_references_unresolved_observation".to_owned()],
            limits,
        );
    }

    let candidate_actors = inputs
        .path
        .actor_ids()
        .iter()
        .filter_map(|actor_id| actors.get(actor_id.as_str()).copied())
        .filter(|actor| actor.identity_kind() == *required_actor_identity)
        .collect::<Vec<_>>();

    if candidate_actors.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["required_authenticated_actor_not_proven_on_path".to_owned()],
            limits,
        );
    }

    if candidate_actors
        .iter()
        .all(|actor| !supported_authenticated_actor(actor))
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["required_actor_identity_has_unsupported_trust_basis".to_owned()],
            limits,
        );
    }

    let relevant_filters = inputs
        .operation
        .filters()
        .iter()
        .filter(|filter| filter.field_semantic_key() == resource_tenant_field)
        .collect::<Vec<_>>();

    if relevant_filters.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            Vec::new(),
            vec![inputs.operation.operation_id().clone()],
            vec!["required_tenant_or_owner_filter_missing".to_owned()],
            limits,
        );
    }

    let mut unknown_filter_semantics = false;
    let mut contradicting = BTreeSet::new();
    for filter in relevant_filters {
        if !matches!(filter.operator(), FilterOperator::Eq | FilterOperator::In) {
            unknown_filter_semantics = true;
            continue;
        }
        let Some(value) = values.get(filter.value_origin().as_str()).copied() else {
            unknown_filter_semantics = true;
            continue;
        };
        if !has_link(
            inputs.path,
            value.value_id(),
            inputs.operation.operation_id(),
        ) {
            unknown_filter_semantics = true;
            continue;
        }

        for actor in candidate_actors
            .iter()
            .copied()
            .filter(|actor| supported_authenticated_actor(actor))
        {
            if direct_actor_value_binding(inputs.path, actor, value, *required_actor_identity) {
                return evaluation(
                    inputs.invariant,
                    inputs.path,
                    InvariantEvaluationState::Satisfied,
                    vec![
                        actor.actor_id().clone(),
                        value.value_id().clone(),
                        inputs.operation.operation_id().clone(),
                    ],
                    Vec::new(),
                    vec!["supported_authenticated_actor_filter_binding".to_owned()],
                    limits,
                );
            }

            for guard_id in inputs.path.guard_ids() {
                let Some(guard) = guards.get(guard_id.as_str()).copied() else {
                    unknown_filter_semantics = true;
                    continue;
                };
                if guard.required_values().is_empty() {
                    unknown_filter_semantics = true;
                    continue;
                }
                if !guard
                    .required_values()
                    .iter()
                    .any(|field| field == resource_tenant_field)
                {
                    continue;
                }
                if guard_binds_actor_value(
                    inputs.path,
                    actor,
                    guard,
                    value,
                    inputs.operation,
                    *required_actor_identity,
                ) {
                    return evaluation(
                        inputs.invariant,
                        inputs.path,
                        InvariantEvaluationState::Satisfied,
                        vec![
                            actor.actor_id().clone(),
                            guard.guard_id().clone(),
                            value.value_id().clone(),
                            inputs.operation.operation_id().clone(),
                        ],
                        Vec::new(),
                        vec!["supported_guarded_tenant_or_owner_binding".to_owned()],
                        limits,
                    );
                }
            }
        }
        contradicting.insert(value.value_id().clone());
    }

    if unknown_filter_semantics {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            contradicting.into_iter().collect(),
            vec!["tenant_binding_filter_or_link_semantics_unresolved".to_owned()],
            limits,
        );
    }

    contradicting.insert(inputs.operation.operation_id().clone());
    evaluation(
        inputs.invariant,
        inputs.path,
        InvariantEvaluationState::Violated,
        Vec::new(),
        contradicting.into_iter().collect(),
        vec!["covered_path_lacks_supported_tenant_or_owner_binding".to_owned()],
        limits,
    )
}

fn scope_applies(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    route: &RouteObservation,
    operation: &DataOperation,
) -> bool {
    let scope = invariant.scope();
    if scope
        .route_pattern()
        .is_some_and(|pattern| pattern != route.route_pattern())
    {
        return false;
    }
    if !scope.http_methods().is_empty() && !scope.http_methods().contains(&route.method()) {
        return false;
    }
    if scope
        .resource()
        .is_some_and(|resource| resource != operation.resource())
    {
        return false;
    }
    if !scope.operation_kinds().is_empty()
        && !scope
            .operation_kinds()
            .contains(&operation.operation_kind())
    {
        return false;
    }
    scope.target_paths().is_empty()
        || path
            .provenance()
            .iter()
            .any(|location| scope.target_paths().contains(location.path()))
}

fn supported_authenticated_actor(actor: &ActorContext) -> bool {
    matches!(
        actor.source_kind(),
        ActorSourceKind::VerifiedAuthAdapter
            | ActorSourceKind::TokenClaim
            | ActorSourceKind::DerivedSupported
    ) && matches!(
        actor.trust_basis(),
        TrustBasis::DirectObservation | TrustBasis::SupportedDerivation
    )
}

fn direct_actor_value_binding(
    path: &CrossLayerPath,
    actor: &ActorContext,
    value: &ValueOrigin,
    required_identity: ActorIdentityKind,
) -> bool {
    let kind_matches = matches!(
        (required_identity, value.origin_kind()),
        (
            ActorIdentityKind::AuthenticatedUser,
            ValueOriginKind::AuthenticatedUserId
        ) | (
            ActorIdentityKind::Tenant,
            ValueOriginKind::AuthenticatedTenantId
        )
    );
    kind_matches
        && value.source_actor() == Some(actor.actor_id())
        && has_link(path, actor.actor_id(), value.value_id())
}

fn guard_binds_actor_value(
    path: &CrossLayerPath,
    actor: &ActorContext,
    guard: &GuardObservation,
    value: &ValueOrigin,
    operation: &DataOperation,
    required_identity: ActorIdentityKind,
) -> bool {
    let guard_kind_supported = match required_identity {
        ActorIdentityKind::AuthenticatedUser => matches!(
            guard.guard_kind(),
            GuardKind::OwnershipBinding | GuardKind::TenantBinding | GuardKind::ObjectMembership
        ),
        ActorIdentityKind::Tenant => guard.guard_kind() == GuardKind::TenantBinding,
        _ => false,
    };
    guard_kind_supported
        && guard.subject_actor() == Some(actor.actor_id())
        && guard
            .resource()
            .is_none_or(|resource| resource == operation.resource())
        && matches!(
            guard.comparison_shape(),
            ComparisonShape::Equal
                | ComparisonShape::Membership
                | ComparisonShape::ConjunctionSupported
        )
        && guard.dominance_scope() != DominanceScope::Unknown
        && has_link(path, actor.actor_id(), guard.guard_id())
        && has_link(path, guard.guard_id(), value.value_id())
}

fn has_link(path: &CrossLayerPath, source: &StableSemanticId, target: &StableSemanticId) -> bool {
    path.links()
        .iter()
        .any(|link| link.source_semantic_id() == source && link.target_semantic_id() == target)
}

fn evaluation(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    state: InvariantEvaluationState,
    supporting_observation_ids: Vec<StableSemanticId>,
    contradicting_observation_ids: Vec<StableSemanticId>,
    coverage_reasons: Vec<String>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, TenantBindingError> {
    let evaluation_id = StableSemanticId::from_parts(
        "r3-tenant-binding-evaluation",
        &[invariant.invariant_id().as_str(), path.path_id().as_str()],
        limits,
    )?;
    let mut provenance = invariant.provenance().to_vec();
    provenance.extend(path.provenance().iter().cloned());
    provenance.sort();
    provenance.dedup();

    Ok(InvariantEvaluation::new(
        evaluation_id,
        invariant.invariant_id().clone(),
        Some(path.path_id().clone()),
        state,
        supporting_observation_ids,
        contradicting_observation_ids,
        coverage_reasons,
        provenance,
        limits,
    )?)
}
