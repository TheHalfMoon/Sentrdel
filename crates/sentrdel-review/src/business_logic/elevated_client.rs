//! Bounded R3-T024 elevated provider-client application-boundary invariant evaluation.
//!
//! Elevated provider authority is contextual. Merely observing a service-role or secret-backed
//! client is not itself a violation. Conclusive evaluation requires a fully supported correlated
//! route/guard/data/client path with extracted links. Unknown client authority, unresolved guard
//! semantics, or unresolved optional server-context evidence remains UNKNOWN. This module never
//! executes target code, accesses providers, receives credentials, creates Findings, or proves
//! runtime authorization/exploitability.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::model::{
    BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink, CrossLayerPath,
    DataOperation, DominanceScope, GuardKind, GuardObservation, InvariantDefinition,
    InvariantEvaluation, InvariantEvaluationState, InvariantKind, InvariantRequirement, LinkBasis,
    ModelError, PathState, ProviderAuthorityClass, ProviderClientAuthority, RouteObservation,
    StableSemanticId,
};

pub const R3_ELEVATED_CLIENT_CREATES_FINDINGS: bool = false;
pub const R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE: bool = false;
pub const R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_ELEVATED_CLIENT_RECEIVES_PROVIDER_CREDENTIALS: bool = false;
pub const R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION: bool = false;
pub const R3_ELEVATED_CLIENT_TREATS_EXISTENCE_AS_VULNERABILITY: bool = false;
pub const R3_ELEVATED_CLIENT_ASSUMES_UNKNOWN_AUTHORITY_IS_SAFE: bool = false;

pub struct ElevatedClientInputs<'a> {
    pub invariant: &'a InvariantDefinition,
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub guard_coverage_state: &'a CoverageState,
    pub guards: &'a [GuardObservation],
    pub operation: &'a DataOperation,
    pub client: &'a ProviderClientAuthority,
}

#[derive(Debug)]
pub enum ElevatedClientError {
    InvalidInvariantKind,
    PathRouteMismatch,
    PathOperationMismatch,
    PathProviderClientMismatch,
    OperationProviderClientMismatch,
    Model(ModelError),
}

impl fmt::Display for ElevatedClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvariantKind => formatter.write_str(
                "elevated-client evaluator requires an elevated-client-context invariant",
            ),
            Self::PathRouteMismatch => {
                formatter.write_str("elevated-client path route does not match supplied route")
            }
            Self::PathOperationMismatch => formatter
                .write_str("elevated-client path operation does not match supplied data operation"),
            Self::PathProviderClientMismatch => formatter.write_str(
                "elevated-client path provider client does not match supplied provider client",
            ),
            Self::OperationProviderClientMismatch => formatter.write_str(
                "elevated-client operation provider client does not match supplied provider client",
            ),
            Self::Model(source) => {
                write!(formatter, "elevated-client model validation failed: {source}")
            }
        }
    }
}

impl Error for ElevatedClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for ElevatedClientError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn evaluate_elevated_client(
    inputs: ElevatedClientInputs<'_>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, ElevatedClientError> {
    let limits = limits.validate()?;
    if inputs.invariant.kind() != InvariantKind::ElevatedClientContext {
        return Err(ElevatedClientError::InvalidInvariantKind);
    }
    if inputs.path.route_id() != inputs.route.route_id() {
        return Err(ElevatedClientError::PathRouteMismatch);
    }
    if inputs.path.data_operation_id() != inputs.operation.operation_id() {
        return Err(ElevatedClientError::PathOperationMismatch);
    }
    if inputs.path.provider_client_id() != Some(inputs.client.client_id()) {
        return Err(ElevatedClientError::PathProviderClientMismatch);
    }
    if inputs.operation.provider_client() != Some(inputs.client.client_id()) {
        return Err(ElevatedClientError::OperationProviderClientMismatch);
    }

    let InvariantRequirement::ElevatedClientContext {
        allowed_server_contexts,
        required_guard_kinds,
    } = inputs.invariant.requirements()
    else {
        return Err(ElevatedClientError::InvalidInvariantKind);
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
            vec!["elevated_client_scope_not_applicable".to_owned()],
            limits,
        );
    }

    match inputs.client.authority_class() {
        ProviderAuthorityClass::UserScoped | ProviderAuthorityClass::PublishableOrAnon => {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::NotApplicable,
                vec![inputs.client.client_id().clone()],
                Vec::new(),
                vec!["provider_client_is_not_elevated".to_owned()],
                limits,
            );
        }
        ProviderAuthorityClass::ServerUnknown | ProviderAuthorityClass::Unknown => {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::Unknown,
                Vec::new(),
                vec![inputs.client.client_id().clone()],
                vec!["provider_client_authority_is_unknown".to_owned()],
                limits,
            );
        }
        ProviderAuthorityClass::ElevatedSecretOrServiceRole => {}
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
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_path_guard_or_operation_not_fully_supported".to_owned()],
            limits,
        );
    }

    if inputs.path.links().iter().any(|link| !authoritative_link(link)) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_path_contains_non_authoritative_link".to_owned()],
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
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_path_references_unresolved_guard".to_owned()],
            limits,
        );
    }

    if required_guard_kinds.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_required_guard_kinds_are_empty".to_owned()],
            limits,
        );
    }

    let path_guards = inputs
        .path
        .guard_ids()
        .iter()
        .filter_map(|guard_id| guards.get(guard_id.as_str()).copied())
        .collect::<Vec<_>>();

    let mut supporting = BTreeSet::from([
        inputs.client.client_id().clone(),
        inputs.operation.operation_id().clone(),
    ]);
    let mut contradicting = BTreeSet::new();
    let mut unresolved_required_guard = false;

    for required_kind in required_guard_kinds {
        let candidates = path_guards
            .iter()
            .copied()
            .filter(|guard| guard.guard_kind() == *required_kind)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            contradicting.insert(inputs.operation.operation_id().clone());
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::Violated,
                supporting.into_iter().collect(),
                contradicting.into_iter().collect(),
                vec!["covered_elevated_client_path_lacks_required_application_guard".to_owned()],
                limits,
            );
        }

        let mut kind_supported = false;
        for guard in candidates {
            if guard
                .resource()
                .is_some_and(|resource| resource != inputs.operation.resource())
            {
                contradicting.insert(guard.guard_id().clone());
                continue;
            }
            if guard.comparison_shape() == ComparisonShape::Unknown
                || guard.dominance_scope() == DominanceScope::Unknown
                || !guard_is_supported_on_path(inputs.path, guard.guard_id())
            {
                unresolved_required_guard = true;
                continue;
            }
            supporting.insert(guard.guard_id().clone());
            kind_supported = true;
            break;
        }
        if !kind_supported && !unresolved_required_guard {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::Violated,
                supporting.into_iter().collect(),
                contradicting.into_iter().collect(),
                vec!["covered_elevated_client_path_has_no_applicable_required_guard".to_owned()],
                limits,
            );
        }
    }

    if unresolved_required_guard {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            supporting.into_iter().collect(),
            contradicting.into_iter().collect(),
            vec!["elevated_client_required_guard_dominance_or_linkage_unresolved".to_owned()],
            limits,
        );
    }

    if !allowed_server_contexts.is_empty() {
        let allowed = allowed_server_contexts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let boundary_guards = path_guards
            .iter()
            .copied()
            .filter(|guard| guard.guard_kind() == GuardKind::ElevatedClientBoundary)
            .collect::<Vec<_>>();

        if boundary_guards.is_empty() {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::Unknown,
                supporting.into_iter().collect(),
                contradicting.into_iter().collect(),
                vec!["elevated_client_server_context_is_unresolved".to_owned()],
                limits,
            );
        }

        let mut unresolved_context = false;
        for guard in boundary_guards {
            if guard.required_values().is_empty()
                || guard.comparison_shape() == ComparisonShape::Unknown
                || guard.dominance_scope() == DominanceScope::Unknown
                || !guard_is_supported_on_path(inputs.path, guard.guard_id())
            {
                unresolved_context = true;
                continue;
            }
            if guard
                .required_values()
                .iter()
                .any(|context| allowed.contains(context.as_str()))
            {
                supporting.insert(guard.guard_id().clone());
                return evaluation(
                    inputs.invariant,
                    inputs.path,
                    InvariantEvaluationState::Satisfied,
                    supporting.into_iter().collect(),
                    contradicting.into_iter().collect(),
                    vec!["elevated_client_path_has_required_guard_and_allowed_server_context".to_owned()],
                    limits,
                );
            }
            contradicting.insert(guard.guard_id().clone());
        }

        if unresolved_context {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::Unknown,
                supporting.into_iter().collect(),
                contradicting.into_iter().collect(),
                vec!["elevated_client_server_context_semantics_unresolved".to_owned()],
                limits,
            );
        }

        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            supporting.into_iter().collect(),
            contradicting.into_iter().collect(),
            vec!["elevated_client_path_is_outside_allowed_server_context".to_owned()],
            limits,
        );
    }

    evaluation(
        inputs.invariant,
        inputs.path,
        InvariantEvaluationState::Satisfied,
        supporting.into_iter().collect(),
        contradicting.into_iter().collect(),
        vec!["elevated_client_path_has_required_application_guards".to_owned()],
        limits,
    )
}

fn authoritative_link(link: &CrossLayerLink) -> bool {
    link.confidence_basis() == ConfidenceBasis::Extracted && link.basis() != LinkBasis::Unknown
}

fn guard_is_supported_on_path(path: &CrossLayerPath, guard_id: &StableSemanticId) -> bool {
    supported_reachable(path, path.route_id(), guard_id)
        && supported_reachable(path, guard_id, path.data_operation_id())
}

fn supported_reachable(
    path: &CrossLayerPath,
    source: &StableSemanticId,
    target: &StableSemanticId,
) -> bool {
    if source == target {
        return true;
    }
    let mut adjacency = BTreeMap::<&str, Vec<&CrossLayerLink>>::new();
    for link in path.links().iter().filter(|link| authoritative_link(link)) {
        adjacency
            .entry(link.source_semantic_id().as_str())
            .or_default()
            .push(link);
    }
    let mut visited = BTreeSet::from([source.as_str()]);
    let mut queue = VecDeque::from([source.as_str()]);
    while let Some(current) = queue.pop_front() {
        let Some(outgoing) = adjacency.get(current) else {
            continue;
        };
        for link in outgoing {
            let next = link.target_semantic_id().as_str();
            if next == target.as_str() {
                return true;
            }
            if visited.insert(next) {
                queue.push_back(next);
            }
        }
    }
    false
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

fn evaluation(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    state: InvariantEvaluationState,
    supporting_observation_ids: Vec<StableSemanticId>,
    contradicting_observation_ids: Vec<StableSemanticId>,
    coverage_reasons: Vec<String>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, ElevatedClientError> {
    let evaluation_id = StableSemanticId::from_parts(
        "r3-elevated-client-evaluation",
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
