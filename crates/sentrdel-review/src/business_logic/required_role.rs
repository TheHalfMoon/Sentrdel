//! Bounded R3-T022 privileged function/role authorization invariant evaluation.
//!
//! The evaluator consumes only normalized R3 observations and a correlated path.
//! Privilege comes from the invariant scope, never route naming or lexical role text.
//! A secure result requires a supported role guard on the correlated path with supported
//! dominance. Unresolved path or guard semantics remain UNKNOWN. This module never
//! executes target code, accesses providers, creates Findings, or proves runtime authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::model::{
    BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerPath, DataOperation,
    DominanceScope, GuardKind, GuardObservation, InvariantDefinition, InvariantEvaluation,
    InvariantEvaluationState, InvariantKind, InvariantRequirement, LinkBasis, ModelError,
    PathState, RouteObservation, StableSemanticId,
};

pub const R3_REQUIRED_ROLE_CREATES_FINDINGS: bool = false;
pub const R3_REQUIRED_ROLE_EXECUTES_TARGET_CODE: bool = false;
pub const R3_REQUIRED_ROLE_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_REQUIRED_ROLE_PROVES_RUNTIME_AUTHORIZATION: bool = false;
pub const R3_REQUIRED_ROLE_USES_ROUTE_NAMING_AS_PRIVILEGE_PROOF: bool = false;
pub const R3_REQUIRED_ROLE_USES_UNLINKED_ROLE_TEXT_AS_AUTHORIZATION_PROOF: bool = false;

pub struct RequiredRoleInputs<'a> {
    pub invariant: &'a InvariantDefinition,
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub guard_coverage_state: &'a CoverageState,
    pub guards: &'a [GuardObservation],
    pub operation: &'a DataOperation,
}

#[derive(Debug)]
pub enum RequiredRoleError {
    InvalidInvariantKind,
    PathRouteMismatch,
    PathOperationMismatch,
    Model(ModelError),
}

impl fmt::Display for RequiredRoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvariantKind => {
                formatter.write_str("required-role evaluator requires a required-role invariant")
            }
            Self::PathRouteMismatch => {
                formatter.write_str("required-role path route does not match supplied route")
            }
            Self::PathOperationMismatch => formatter
                .write_str("required-role path operation does not match supplied data operation"),
            Self::Model(source) => {
                write!(formatter, "required-role model validation failed: {source}")
            }
        }
    }
}

impl Error for RequiredRoleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for RequiredRoleError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn evaluate_required_role(
    inputs: RequiredRoleInputs<'_>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, RequiredRoleError> {
    let limits = limits.validate()?;
    if inputs.invariant.kind() != InvariantKind::RequiredRole {
        return Err(RequiredRoleError::InvalidInvariantKind);
    }
    if inputs.path.route_id() != inputs.route.route_id() {
        return Err(RequiredRoleError::PathRouteMismatch);
    }
    if inputs.path.data_operation_id() != inputs.operation.operation_id() {
        return Err(RequiredRoleError::PathOperationMismatch);
    }

    let InvariantRequirement::RequiredRole { required_roles } = inputs.invariant.requirements()
    else {
        return Err(RequiredRoleError::InvalidInvariantKind);
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
            vec!["required_role_scope_not_applicable".to_owned()],
            limits,
        );
    }

    if required_roles.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["required_role_requirement_is_empty".to_owned()],
            limits,
        );
    }

    if inputs.path.path_state() != PathState::Supported
        || inputs.route.coverage_state() != &CoverageState::Covered
        || inputs.guard_coverage_state != &CoverageState::Covered
        || inputs.operation.coverage_state() != &CoverageState::Covered
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["required_role_path_guard_or_operation_not_fully_supported".to_owned()],
            limits,
        );
    }

    if inputs.path.links().iter().any(|link| {
        link.confidence_basis() != ConfidenceBasis::Extracted || link.basis() == LinkBasis::Unknown
    }) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["required_role_path_contains_non_authoritative_link".to_owned()],
            limits,
        );
    }

    let guards = inputs
        .guards
        .iter()
        .map(|guard| (guard.guard_id().as_str(), guard))
        .collect::<BTreeMap<_, _>>();
    if inputs
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
            vec!["required_role_path_references_unresolved_guard".to_owned()],
            limits,
        );
    }

    let required = required_roles
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let role_guards = inputs
        .path
        .guard_ids()
        .iter()
        .filter_map(|guard_id| guards.get(guard_id.as_str()).copied())
        .filter(|guard| guard.guard_kind() == GuardKind::RequiredRole)
        .collect::<Vec<_>>();

    if role_guards.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            Vec::new(),
            vec![inputs.operation.operation_id().clone()],
            vec!["covered_privileged_path_lacks_required_role_guard".to_owned()],
            limits,
        );
    }

    let mut unresolved_semantics = false;
    let mut contradicting = BTreeSet::new();

    for guard in role_guards {
        if guard
            .resource()
            .is_some_and(|resource| resource != inputs.operation.resource())
        {
            contradicting.insert(guard.guard_id().clone());
            continue;
        }
        if guard.required_values().is_empty()
            || !matches!(
                guard.comparison_shape(),
                ComparisonShape::Equal
                    | ComparisonShape::Membership
                    | ComparisonShape::ConjunctionSupported
            )
            || guard.dominance_scope() == DominanceScope::Unknown
            || !guard_is_linked_on_path(inputs.path, guard.guard_id())
        {
            unresolved_semantics = true;
            continue;
        }

        if guard
            .required_values()
            .iter()
            .any(|observed| required.contains(observed.as_str()))
        {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::Satisfied,
                vec![
                    guard.guard_id().clone(),
                    inputs.operation.operation_id().clone(),
                ],
                Vec::new(),
                vec!["supported_required_role_guard_dominates_privileged_path".to_owned()],
                limits,
            );
        }

        contradicting.insert(guard.guard_id().clone());
    }

    if unresolved_semantics {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            contradicting.into_iter().collect(),
            vec!["required_role_guard_dominance_or_linkage_unresolved".to_owned()],
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
        vec!["covered_privileged_path_lacks_matching_required_role_guard".to_owned()],
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

fn guard_is_linked_on_path(path: &CrossLayerPath, guard_id: &StableSemanticId) -> bool {
    path.links().iter().any(|link| {
        (link.source_semantic_id() == guard_id || link.target_semantic_id() == guard_id)
            && link.confidence_basis() == ConfidenceBasis::Extracted
            && link.basis() != LinkBasis::Unknown
    })
}

fn evaluation(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    state: InvariantEvaluationState,
    supporting_observation_ids: Vec<StableSemanticId>,
    contradicting_observation_ids: Vec<StableSemanticId>,
    coverage_reasons: Vec<String>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, RequiredRoleError> {
    let evaluation_id = StableSemanticId::from_parts(
        "r3-required-role-evaluation",
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
