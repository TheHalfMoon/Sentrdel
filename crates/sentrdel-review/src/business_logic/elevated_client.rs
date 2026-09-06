//! Bounded R3-T024 elevated provider-client application-boundary invariant evaluation.
//!
//! The evaluator consumes only normalized R3 observations and a correlated path. Elevated
//! provider authority is contextual: it is never a violation by itself. A conclusive violation
//! requires a supported request-controlled actor feeding a supported data operation through an
//! elevated client without every required supported application guard. Unresolved path, client,
//! request, guard, or server-context semantics remain UNKNOWN. This module never executes target
//! code, accesses providers, receives credentials, creates Findings, or proves runtime
//! authorization/exploitability.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::model::{
    ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
    ConfidenceBasis, CrossLayerPath, DataOperation, DataOperationKind, DominanceScope, GuardKind,
    GuardObservation, InvariantDefinition, InvariantEvaluation, InvariantEvaluationState,
    InvariantKind, InvariantRequirement, LinkBasis, ModelError, PathState, ProviderAuthorityClass,
    ProviderClientAuthority, RouteObservation, StableSemanticId, TrustBasis,
};

pub const R3_ELEVATED_CLIENT_CREATES_FINDINGS: bool = false;
pub const R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE: bool = false;
pub const R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_ELEVATED_CLIENT_RECEIVES_PROVIDER_CREDENTIALS: bool = false;
pub const R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION: bool = false;
pub const R3_ELEVATED_CLIENT_AUTHORITY_ALONE_IS_VIOLATION: bool = false;
pub const R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION: &str =
    "route_authorized_by_elevated_client_guard";
pub const R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION: &str =
    "elevated_client_guard_authorizes_operation";
pub const R3_ELEVATED_CLIENT_OPERATION_CLIENT_RELATION: &str = "operation_uses_provider_client";

pub struct ElevatedClientInputs<'a> {
    pub invariant: &'a InvariantDefinition,
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub actor_coverage_state: &'a CoverageState,
    pub guard_coverage_state: &'a CoverageState,
    pub actors: &'a [ActorContext],
    pub guards: &'a [GuardObservation],
    pub provider_clients: &'a [ProviderClientAuthority],
    pub operation: &'a DataOperation,
}

#[derive(Debug)]
pub enum ElevatedClientError {
    InvalidInvariantKind,
    PathRouteMismatch,
    PathOperationMismatch,
    PathClientMismatch,
    Model(ModelError),
}

impl fmt::Display for ElevatedClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvariantKind => formatter
                .write_str("elevated-client evaluator requires an elevated-client invariant"),
            Self::PathRouteMismatch => {
                formatter.write_str("elevated-client path route does not match supplied route")
            }
            Self::PathOperationMismatch => formatter
                .write_str("elevated-client path operation does not match supplied data operation"),
            Self::PathClientMismatch => formatter.write_str(
                "elevated-client path provider client does not match supplied data operation",
            ),
            Self::Model(source) => {
                write!(
                    formatter,
                    "elevated-client model validation failed: {source}"
                )
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
    if inputs.path.provider_client_id() != inputs.operation.provider_client() {
        return Err(ElevatedClientError::PathClientMismatch);
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

    if inputs.path.path_state() != PathState::Supported
        || inputs.route.coverage_state() != &CoverageState::Covered
        || inputs.actor_coverage_state != &CoverageState::Covered
        || inputs.guard_coverage_state != &CoverageState::Covered
        || inputs.operation.coverage_state() != &CoverageState::Covered
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["elevated_client_path_actor_guard_or_operation_not_fully_supported".to_owned()],
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
            vec!["elevated_client_path_contains_non_authoritative_link".to_owned()],
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
    let clients = inputs
        .provider_clients
        .iter()
        .map(|client| (client.client_id().as_str(), client))
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
            vec!["elevated_client_path_references_unresolved_observation".to_owned()],
            limits,
        );
    }

    let Some(client_id) = inputs.path.provider_client_id() else {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::NotApplicable,
            Vec::new(),
            Vec::new(),
            vec!["elevated_client_provider_client_not_observed".to_owned()],
            limits,
        );
    };
    let Some(client) = clients.get(client_id.as_str()).copied() else {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["elevated_client_provider_client_unresolved".to_owned()],
            limits,
        );
    };

    match client.authority_class() {
        ProviderAuthorityClass::UserScoped | ProviderAuthorityClass::PublishableOrAnon => {
            return evaluation(
                inputs.invariant,
                inputs.path,
                InvariantEvaluationState::NotApplicable,
                vec![client.client_id().clone()],
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
                Vec::new(),
                vec!["provider_client_authority_is_unresolved".to_owned()],
                limits,
            );
        }
        ProviderAuthorityClass::ElevatedSecretOrServiceRole => {}
    }

    if !has_exact_authorization_link(
        inputs.path,
        inputs.operation.operation_id(),
        client.client_id(),
        R3_ELEVATED_CLIENT_OPERATION_CLIENT_RELATION,
    ) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![client.client_id().clone()],
            vec!["elevated_client_operation_client_link_unresolved".to_owned()],
            limits,
        );
    }

    if !allowed_server_contexts.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![client.client_id().clone()],
            vec!["elevated_client_server_context_not_observed".to_owned()],
            limits,
        );
    }

    if !supported_risky_operation(inputs.operation.operation_kind()) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            if inputs.operation.operation_kind() == DataOperationKind::OtherSupported {
                InvariantEvaluationState::Unknown
            } else {
                InvariantEvaluationState::NotApplicable
            },
            vec![client.client_id().clone()],
            Vec::new(),
            vec!["elevated_client_operation_risk_not_supported".to_owned()],
            limits,
        );
    }

    let path_actors = inputs
        .path
        .actor_ids()
        .iter()
        .filter_map(|actor_id| actors.get(actor_id.as_str()).copied())
        .collect::<Vec<_>>();
    let request_actors = path_actors
        .iter()
        .copied()
        .filter(|actor| supported_request_controlled_actor(actor))
        .filter(|actor| {
            has_authoritative_directed_path(
                inputs.path,
                actor.actor_id(),
                inputs.operation.operation_id(),
            )
        })
        .collect::<Vec<_>>();

    if request_actors.is_empty() {
        let unresolved_request_semantics = path_actors.iter().any(|actor| {
            actor.identity_kind() == ActorIdentityKind::RequestControlled
                && !supported_request_controlled_actor(actor)
        });
        return evaluation(
            inputs.invariant,
            inputs.path,
            if unresolved_request_semantics {
                InvariantEvaluationState::Unknown
            } else {
                InvariantEvaluationState::NotApplicable
            },
            vec![client.client_id().clone()],
            Vec::new(),
            vec![if unresolved_request_semantics {
                "request_controlled_actor_semantics_unresolved".to_owned()
            } else {
                "elevated_authority_has_no_supported_request_controlled_data_path".to_owned()
            }],
            limits,
        );
    }

    let required = required_guard_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut satisfied_guard_ids = BTreeSet::new();
    let mut unresolved_guard_semantics = false;
    let mut missing_guard_kinds = BTreeSet::new();

    for required_kind in required {
        let candidates = inputs
            .path
            .guard_ids()
            .iter()
            .filter_map(|guard_id| guards.get(guard_id.as_str()).copied())
            .filter(|guard| guard.guard_kind() == required_kind)
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            missing_guard_kinds.insert(required_kind);
            continue;
        }

        let mut kind_satisfied = false;
        let mut kind_unresolved = false;
        for guard in candidates {
            if guard
                .resource()
                .is_some_and(|resource| resource != inputs.operation.resource())
            {
                continue;
            }
            if guard.comparison_shape() == ComparisonShape::Unknown
                || guard.dominance_scope() == DominanceScope::Unknown
                || !guard_is_authoritatively_linked(inputs.path, guard.guard_id())
            {
                kind_unresolved = true;
                continue;
            }
            kind_satisfied = true;
            satisfied_guard_ids.insert(guard.guard_id().clone());
            break;
        }

        if !kind_satisfied {
            if kind_unresolved {
                unresolved_guard_semantics = true;
            } else {
                missing_guard_kinds.insert(required_kind);
            }
        }
    }

    if unresolved_guard_semantics {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            satisfied_guard_ids.into_iter().collect(),
            vec![
                client.client_id().clone(),
                inputs.operation.operation_id().clone(),
            ],
            vec!["required_elevated_client_guard_semantics_unresolved".to_owned()],
            limits,
        );
    }

    if !missing_guard_kinds.is_empty() {
        let mut contradicting = vec![
            client.client_id().clone(),
            inputs.operation.operation_id().clone(),
        ];
        contradicting.extend(request_actors.iter().map(|actor| actor.actor_id().clone()));
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            satisfied_guard_ids.into_iter().collect(),
            contradicting,
            vec![
                "supported_request_controlled_elevated_path_lacks_required_application_guard"
                    .to_owned(),
            ],
            limits,
        );
    }

    let mut supporting = vec![
        client.client_id().clone(),
        inputs.operation.operation_id().clone(),
    ];
    supporting.extend(request_actors.iter().map(|actor| actor.actor_id().clone()));
    supporting.extend(satisfied_guard_ids);
    evaluation(
        inputs.invariant,
        inputs.path,
        InvariantEvaluationState::Satisfied,
        supporting,
        Vec::new(),
        vec![
            "supported_required_application_guards_bound_request_controlled_elevated_path"
                .to_owned(),
        ],
        limits,
    )
}

fn supported_request_controlled_actor(actor: &ActorContext) -> bool {
    actor.identity_kind() == ActorIdentityKind::RequestControlled
        && matches!(
            actor.source_kind(),
            ActorSourceKind::RequestParam
                | ActorSourceKind::RequestBody
                | ActorSourceKind::RequestHeader
                | ActorSourceKind::DerivedSupported
        )
        && actor.trust_basis() != TrustBasis::Unknown
}

const fn supported_risky_operation(kind: DataOperationKind) -> bool {
    matches!(
        kind,
        DataOperationKind::Read
            | DataOperationKind::Insert
            | DataOperationKind::Update
            | DataOperationKind::Upsert
            | DataOperationKind::Delete
            | DataOperationKind::Rpc
    )
}

fn guard_is_authoritatively_linked(path: &CrossLayerPath, guard_id: &StableSemanticId) -> bool {
    has_exact_authorization_link(
        path,
        path.route_id(),
        guard_id,
        R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
    ) && has_exact_authorization_link(
        path,
        guard_id,
        path.data_operation_id(),
        R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
    )
}

fn has_exact_authorization_link(
    path: &CrossLayerPath,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
) -> bool {
    path.links().iter().any(|link| {
        link.source_semantic_id() == source
            && link.target_semantic_id() == target
            && link.relation() == relation
            && link.basis() == LinkBasis::ExplicitAdapterLink
            && link.confidence_basis() == ConfidenceBasis::Extracted
    })
}

fn has_authoritative_directed_path(
    path: &CrossLayerPath,
    source: &StableSemanticId,
    target: &StableSemanticId,
) -> bool {
    if source == target {
        return true;
    }
    let mut queue = VecDeque::from([source.clone()]);
    let mut visited = BTreeSet::from([source.clone()]);
    let max_visits = path.links().len().saturating_add(1);

    while let Some(current) = queue.pop_front() {
        if visited.len() > max_visits {
            return false;
        }
        for link in path.links().iter().filter(|link| {
            link.source_semantic_id() == &current
                && link.confidence_basis() == ConfidenceBasis::Extracted
                && link.basis() != LinkBasis::Unknown
        }) {
            if link.target_semantic_id() == target {
                return true;
            }
            if visited.insert(link.target_semantic_id().clone()) {
                queue.push_back(link.target_semantic_id().clone());
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
