//! Bounded R3-T024 elevated provider-client application-boundary invariant evaluation.
//!
//! Elevated provider authority is contextual rather than automatically vulnerable. A clean
//! evaluation requires exact provider-client identity, canonical R2 key/client-boundary support,
//! an allowed supported server context, and a required application-authorization guard with
//! authoritative route-to-guard and guard-to-operation linkage. Unresolved context, R2 support,
//! guard semantics, or linkage remains UNKNOWN. This module never executes target code, accesses
//! providers, creates Findings, or proves runtime authorization, hosted posture, or exploitability.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::model::{
    BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerPath, DataOperation,
    DominanceScope, FrameworkFamily, GuardKind, GuardObservation, InvariantDefinition,
    InvariantEvaluation, InvariantEvaluationState, InvariantKind, InvariantRequirement, LinkBasis,
    ModelError, PathState, ProviderAuthorityClass, ProviderClientAuthority, RouteObservation,
    StableSemanticId,
};
use super::r2_support::{R2SupportCorrelation, R2SupportKind, R2SupportTargetKind};

pub const R3_ELEVATED_CLIENT_CREATES_FINDINGS: bool = false;
pub const R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE: bool = false;
pub const R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION: bool = false;
pub const R3_ELEVATED_CLIENT_PROVES_LIVE_PROVIDER_POSTURE: bool = false;
pub const R3_ELEVATED_CLIENT_TREATS_ELEVATED_AUTHORITY_AS_AUTOMATIC_VIOLATION: bool = false;

pub const R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION: &str =
    "route_authorized_by_elevated_client_guard";
pub const R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION: &str =
    "elevated_client_guard_authorizes_operation";

pub const R3_SERVER_CONTEXT_EXPRESS: &str = "express-server";
pub const R3_SERVER_CONTEXT_NEXT_APP: &str = "next-app-server";
pub const R3_SERVER_CONTEXT_NEXT_PAGES_API: &str = "next-pages-api-server";
pub const R3_SERVER_CONTEXT_SUPABASE_EDGE: &str = "supabase-edge";

pub struct ElevatedClientInputs<'a> {
    pub invariant: &'a InvariantDefinition,
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub guard_coverage_state: &'a CoverageState,
    pub guards: &'a [GuardObservation],
    pub operation: &'a DataOperation,
    pub client: &'a ProviderClientAuthority,
    pub r2_support: &'a R2SupportCorrelation,
}

#[derive(Debug)]
pub enum ElevatedClientError {
    InvalidInvariantKind,
    PathRouteMismatch,
    PathOperationMismatch,
    OperationClientMismatch,
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
            Self::OperationClientMismatch => formatter.write_str(
                "elevated-client data operation does not reference the supplied provider client",
            ),
            Self::PathClientMismatch => formatter
                .write_str("elevated-client path does not reference the supplied provider client"),
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

    let operation_client = inputs.operation.provider_client();
    if operation_client != Some(inputs.client.client_id()) {
        return Err(ElevatedClientError::OperationClientMismatch);
    }
    if inputs.path.provider_client_id() != Some(inputs.client.client_id()) {
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
                vec!["provider_client_authority_is_unresolved".to_owned()],
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

    if inputs.path.links().iter().any(|link| {
        link.confidence_basis() != ConfidenceBasis::Extracted || link.basis() == LinkBasis::Unknown
    }) {
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

    if !has_exact_r2_key_client_boundary(inputs.r2_support, inputs.client) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_lacks_exact_canonical_r2_boundary_support".to_owned()],
            limits,
        );
    }

    let Some(server_context) = supported_server_context(inputs.route.framework()) else {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_server_context_is_unresolved".to_owned()],
            limits,
        );
    };

    if allowed_server_contexts.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_allowed_server_contexts_are_empty".to_owned()],
            limits,
        );
    }

    if !allowed_server_contexts
        .iter()
        .any(|allowed| allowed == server_context)
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            Vec::new(),
            vec![
                inputs.client.client_id().clone(),
                inputs.operation.operation_id().clone(),
            ],
            vec!["elevated_client_used_outside_allowed_server_context".to_owned()],
            limits,
        );
    }

    if required_guard_kinds.is_empty()
        || required_guard_kinds
            .iter()
            .any(|kind| !supported_application_guard_kind(*kind))
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            vec![inputs.client.client_id().clone()],
            vec!["elevated_client_required_guard_kind_is_unsupported".to_owned()],
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

    let required = required_guard_kinds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let candidate_guards = inputs
        .path
        .guard_ids()
        .iter()
        .filter_map(|guard_id| guards.get(guard_id.as_str()).copied())
        .filter(|guard| required.contains(&guard.guard_kind()))
        .collect::<Vec<_>>();

    if candidate_guards.is_empty() {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            Vec::new(),
            vec![
                inputs.client.client_id().clone(),
                inputs.operation.operation_id().clone(),
            ],
            vec!["covered_elevated_client_path_lacks_required_application_guard".to_owned()],
            limits,
        );
    }

    let mut unresolved_semantics = false;
    let mut contradicting = BTreeSet::new();
    for guard in candidate_guards {
        if guard
            .resource()
            .is_some_and(|resource| resource != inputs.operation.resource())
        {
            contradicting.insert(guard.guard_id().clone());
            continue;
        }
        if !application_guard_semantics_supported(guard)
            || guard.dominance_scope() == DominanceScope::Unknown
            || !guard_is_authoritatively_linked(inputs.path, guard.guard_id())
        {
            unresolved_semantics = true;
            continue;
        }

        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Satisfied,
            vec![
                inputs.client.client_id().clone(),
                guard.guard_id().clone(),
                inputs.operation.operation_id().clone(),
            ],
            Vec::new(),
            vec!["supported_application_guard_protects_elevated_client_path".to_owned()],
            limits,
        );
    }

    if unresolved_semantics {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            contradicting.into_iter().collect(),
            vec!["elevated_client_guard_dominance_or_linkage_unresolved".to_owned()],
            limits,
        );
    }

    contradicting.insert(inputs.client.client_id().clone());
    contradicting.insert(inputs.operation.operation_id().clone());
    evaluation(
        inputs.invariant,
        inputs.path,
        InvariantEvaluationState::Violated,
        Vec::new(),
        contradicting.into_iter().collect(),
        vec!["covered_elevated_client_path_lacks_matching_application_guard".to_owned()],
        limits,
    )
}

#[must_use]
pub const fn supported_server_context(framework: FrameworkFamily) -> Option<&'static str> {
    match framework {
        FrameworkFamily::Express => Some(R3_SERVER_CONTEXT_EXPRESS),
        FrameworkFamily::NextApp => Some(R3_SERVER_CONTEXT_NEXT_APP),
        FrameworkFamily::NextPagesApi => Some(R3_SERVER_CONTEXT_NEXT_PAGES_API),
        FrameworkFamily::SupabaseEdge => Some(R3_SERVER_CONTEXT_SUPABASE_EDGE),
        FrameworkFamily::OtherSupported => None,
    }
}

#[must_use]
pub const fn supported_application_guard_kind(kind: GuardKind) -> bool {
    matches!(
        kind,
        GuardKind::RequiredRole
            | GuardKind::TenantBinding
            | GuardKind::OwnershipBinding
            | GuardKind::ObjectMembership
            | GuardKind::ElevatedClientBoundary
    )
}

#[must_use]
pub(crate) fn application_guard_semantics_supported(guard: &GuardObservation) -> bool {
    match guard.guard_kind() {
        GuardKind::RequiredRole => {
            !guard.required_values().is_empty()
                && matches!(
                    guard.comparison_shape(),
                    ComparisonShape::Equal
                        | ComparisonShape::Membership
                        | ComparisonShape::ConjunctionSupported
                )
        }
        GuardKind::TenantBinding | GuardKind::OwnershipBinding | GuardKind::ObjectMembership => {
            !guard.required_values().is_empty()
                && matches!(
                    guard.comparison_shape(),
                    ComparisonShape::Equal
                        | ComparisonShape::Membership
                        | ComparisonShape::ConjunctionSupported
                        | ComparisonShape::OtherSupported
                )
        }
        GuardKind::ElevatedClientBoundary => {
            guard.comparison_shape() == ComparisonShape::OtherSupported
        }
        _ => false,
    }
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

fn has_exact_r2_key_client_boundary(
    r2_support: &R2SupportCorrelation,
    client: &ProviderClientAuthority,
) -> bool {
    r2_support.matches().iter().any(|support| {
        support.target_kind() == R2SupportTargetKind::ProviderClient
            && support.target_id() == client.client_id().as_str()
            && support.support_kind() == R2SupportKind::KeyClientBoundary
            && client
                .source_evidence_ids()
                .iter()
                .any(|id| id == support.evidence_id())
    })
}

fn guard_is_authoritatively_linked(path: &CrossLayerPath, guard_id: &StableSemanticId) -> bool {
    has_authorization_link(
        path,
        path.route_id(),
        guard_id,
        R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
    ) && has_authorization_link(
        path,
        guard_id,
        path.data_operation_id(),
        R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
    )
}

fn has_authorization_link(
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
