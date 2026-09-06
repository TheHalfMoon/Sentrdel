//! Deterministic bounded R3 path correlation with T022/T024 authorization-link qualification.
//!
//! The canonical T017 correlator remains unchanged in `path_base.rs`. This wrapper may add
//! authorization-specific links only when an already-supported correlated route-to-operation path
//! contains a supported application guard with proven non-UNKNOWN dominance and extracted directed
//! connectivity. Required-role and elevated-client authorization links are distinct and cannot be
//! minted from route naming, lexical role strings, fuzzy graph confidence, or unrelated links. This
//! module never reparses source, executes target code, performs network access, or creates Findings.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use sentrdel_schema::coverage::CoverageState;

use super::elevated_client::{
    R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION, R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
    supported_application_guard_kind,
};
use super::model::{
    ActorContext, BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink,
    CrossLayerPath, DataOperation, DominanceScope, GuardKind, GuardObservation, LinkBasis,
    PathState, ProviderAuthorityClass, ProviderClientAuthority, RouteObservation, SourceLocation,
    StableSemanticId, ValueOrigin,
};
use super::required_role::{
    R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION, R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION,
};
pub(crate) use super::{link, model};

#[path = "path_base.rs"]
mod base;

pub use base::{
    DEFAULT_MAX_CORRELATION_CANDIDATES, DEFAULT_MAX_CORRELATION_DEPTH,
    DEFAULT_MAX_CORRELATION_DIAGNOSTICS, DEFAULT_MAX_CORRELATION_EDGES,
    DEFAULT_MAX_CORRELATION_FRONTIER, DEFAULT_MAX_CORRELATION_NODES,
    DEFAULT_MAX_CORRELATION_OBSERVATIONS, DEFAULT_MAX_CORRELATION_WORK_ITEMS,
    PathCorrelationDiagnostic, PathCorrelationDiagnosticReason, PathCorrelationError,
    PathCorrelationLimits, R3_PATH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY,
    R3_PATH_CORRELATION_CLASSIFIES_PROVIDER_AUTHORITY, R3_PATH_CORRELATION_CONSUMES_R2_EVIDENCE,
    R3_PATH_CORRELATION_CREATES_FINDINGS, R3_PATH_CORRELATION_EXECUTES_TARGET_CODE,
    R3_PATH_CORRELATION_PERFORMS_NETWORK_ACCESS,
};

pub struct PathCorrelationInputs<'a> {
    pub routes: &'a [RouteObservation],
    pub actors: &'a [ActorContext],
    pub guards: &'a [GuardObservation],
    pub values: &'a [ValueOrigin],
    pub data_operations: &'a [DataOperation],
    pub provider_clients: &'a [ProviderClientAuthority],
    pub links: &'a [CrossLayerLink],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathCorrelationResult {
    paths: Vec<CrossLayerPath>,
    diagnostics: Vec<PathCorrelationDiagnostic>,
    coverage_state: CoverageState,
}

impl PathCorrelationResult {
    #[must_use]
    pub fn paths(&self) -> &[CrossLayerPath] {
        &self.paths
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[PathCorrelationDiagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn coverage_state(&self) -> &CoverageState {
        &self.coverage_state
    }
}

pub fn correlate_cross_layer_paths(
    inputs: PathCorrelationInputs<'_>,
    model_limits: BusinessLogicLimits,
    correlation_limits: PathCorrelationLimits,
) -> Result<PathCorrelationResult, PathCorrelationError> {
    let model_limits = model_limits.validate()?;
    let base_result = base::correlate_cross_layer_paths(
        base::PathCorrelationInputs {
            routes: inputs.routes,
            actors: inputs.actors,
            guards: inputs.guards,
            values: inputs.values,
            data_operations: inputs.data_operations,
            provider_clients: inputs.provider_clients,
            links: inputs.links,
        },
        model_limits,
        correlation_limits,
    )?;

    let routes = inputs
        .routes
        .iter()
        .map(|route| (route.route_id().as_str(), route))
        .collect::<BTreeMap<_, _>>();
    let guards = inputs
        .guards
        .iter()
        .map(|guard| (guard.guard_id().as_str(), guard))
        .collect::<BTreeMap<_, _>>();
    let operations = inputs
        .data_operations
        .iter()
        .map(|operation| (operation.operation_id().as_str(), operation))
        .collect::<BTreeMap<_, _>>();
    let clients = inputs
        .provider_clients
        .iter()
        .map(|client| (client.client_id().as_str(), client))
        .collect::<BTreeMap<_, _>>();

    let mut paths = Vec::with_capacity(base_result.paths().len());
    for path in base_result.paths() {
        let Some(route) = routes.get(path.route_id().as_str()).copied() else {
            paths.push(path.clone());
            continue;
        };
        let Some(operation) = operations.get(path.data_operation_id().as_str()).copied() else {
            paths.push(path.clone());
            continue;
        };
        let role_qualified =
            qualify_required_role_links(path, route, operation, &guards, model_limits)?;
        paths.push(qualify_elevated_client_links(
            &role_qualified,
            route,
            operation,
            &guards,
            &clients,
            model_limits,
        )?);
    }

    Ok(PathCorrelationResult {
        paths,
        diagnostics: base_result.diagnostics().to_vec(),
        coverage_state: base_result.coverage_state().clone(),
    })
}

fn qualify_required_role_links(
    path: &CrossLayerPath,
    route: &RouteObservation,
    operation: &DataOperation,
    guards: &BTreeMap<&str, &GuardObservation>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerPath, PathCorrelationError> {
    if path.path_state() != PathState::Supported {
        return Ok(path.clone());
    }

    let mut authorization_links = Vec::new();
    for guard_id in path.guard_ids() {
        let Some(guard) = guards.get(guard_id.as_str()).copied() else {
            continue;
        };
        if !role_guard_is_qualifiable(guard, operation) {
            continue;
        }
        if !supported_reachable(path, path.route_id(), guard.guard_id())
            || !supported_reachable(path, guard.guard_id(), path.data_operation_id())
        {
            continue;
        }

        let provenance = qualification_provenance(route, guard, operation);
        authorization_links.push(required_role_authorization_link(
            path.route_id(),
            guard.guard_id(),
            R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION,
            provenance.clone(),
            limits,
        )?);
        authorization_links.push(required_role_authorization_link(
            guard.guard_id(),
            path.data_operation_id(),
            R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION,
            provenance,
            limits,
        )?);
    }

    if authorization_links.is_empty() {
        return Ok(path.clone());
    }

    authorization_links.sort();
    authorization_links.dedup();
    let mut links = path.links().to_vec();
    links.extend(authorization_links.iter().cloned());

    let mut identity_parts = Vec::with_capacity(authorization_links.len().saturating_add(1));
    identity_parts.push(format!("base:{}", path.path_id().as_str()));
    for link in &authorization_links {
        identity_parts.push(format!("authorization:{}", link.link_id().as_str()));
    }
    let identity_refs = identity_parts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let path_id =
        StableSemanticId::from_parts("r3-required-role-qualified-path", &identity_refs, limits)?;

    Ok(CrossLayerPath::new(
        path_id,
        path.route_id().clone(),
        path.actor_ids().to_vec(),
        path.guard_ids().to_vec(),
        path.data_operation_id().clone(),
        path.provider_client_id().cloned(),
        links,
        path.r2_evidence_ids().to_vec(),
        path.path_state(),
        path.provenance().to_vec(),
        limits,
    )?)
}

fn qualify_elevated_client_links(
    path: &CrossLayerPath,
    route: &RouteObservation,
    operation: &DataOperation,
    guards: &BTreeMap<&str, &GuardObservation>,
    clients: &BTreeMap<&str, &ProviderClientAuthority>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerPath, PathCorrelationError> {
    if path.path_state() != PathState::Supported {
        return Ok(path.clone());
    }
    let Some(client_id) = path.provider_client_id() else {
        return Ok(path.clone());
    };
    if operation.provider_client() != Some(client_id) {
        return Ok(path.clone());
    }
    let Some(client) = clients.get(client_id.as_str()).copied() else {
        return Ok(path.clone());
    };
    if client.authority_class() != ProviderAuthorityClass::ElevatedSecretOrServiceRole {
        return Ok(path.clone());
    }

    let mut authorization_links = Vec::new();
    for guard_id in path.guard_ids() {
        let Some(guard) = guards.get(guard_id.as_str()).copied() else {
            continue;
        };
        if !application_guard_is_qualifiable(guard, operation) {
            continue;
        }
        if !supported_reachable(path, path.route_id(), guard.guard_id())
            || !supported_reachable(path, guard.guard_id(), path.data_operation_id())
        {
            continue;
        }

        let provenance = qualification_provenance(route, guard, operation);
        authorization_links.push(elevated_client_authorization_link(
            path.route_id(),
            guard.guard_id(),
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
            provenance.clone(),
            limits,
        )?);
        authorization_links.push(elevated_client_authorization_link(
            guard.guard_id(),
            path.data_operation_id(),
            R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            provenance,
            limits,
        )?);
    }

    if authorization_links.is_empty() {
        return Ok(path.clone());
    }

    authorization_links.sort();
    authorization_links.dedup();
    let mut links = path.links().to_vec();
    links.extend(authorization_links.iter().cloned());

    let mut identity_parts = Vec::with_capacity(authorization_links.len().saturating_add(1));
    identity_parts.push(format!("base:{}", path.path_id().as_str()));
    for link in &authorization_links {
        identity_parts.push(format!("authorization:{}", link.link_id().as_str()));
    }
    let identity_refs = identity_parts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let path_id =
        StableSemanticId::from_parts("r3-elevated-client-qualified-path", &identity_refs, limits)?;

    Ok(CrossLayerPath::new(
        path_id,
        path.route_id().clone(),
        path.actor_ids().to_vec(),
        path.guard_ids().to_vec(),
        path.data_operation_id().clone(),
        path.provider_client_id().cloned(),
        links,
        path.r2_evidence_ids().to_vec(),
        path.path_state(),
        path.provenance().to_vec(),
        limits,
    )?)
}

fn role_guard_is_qualifiable(guard: &GuardObservation, operation: &DataOperation) -> bool {
    guard.guard_kind() == GuardKind::RequiredRole
        && !guard.required_values().is_empty()
        && guard.dominance_scope() != DominanceScope::Unknown
        && matches!(
            guard.comparison_shape(),
            ComparisonShape::Equal
                | ComparisonShape::Membership
                | ComparisonShape::ConjunctionSupported
        )
        && guard
            .resource()
            .is_none_or(|resource| resource == operation.resource())
}

fn application_guard_is_qualifiable(guard: &GuardObservation, operation: &DataOperation) -> bool {
    if !supported_application_guard_kind(guard.guard_kind())
        || guard.dominance_scope() == DominanceScope::Unknown
        || guard.comparison_shape() == ComparisonShape::Unknown
        || guard
            .resource()
            .is_some_and(|resource| resource != operation.resource())
    {
        return false;
    }

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

fn supported_reachable(
    path: &CrossLayerPath,
    source: &StableSemanticId,
    target: &StableSemanticId,
) -> bool {
    if source == target {
        return true;
    }

    let mut adjacency = BTreeMap::<&str, Vec<&CrossLayerLink>>::new();
    for link in path.links() {
        if link.confidence_basis() != ConfidenceBasis::Extracted
            || link.basis() == LinkBasis::Unknown
            || is_qualified_authorization_relation(link.relation())
        {
            continue;
        }
        adjacency
            .entry(link.source_semantic_id().as_str())
            .or_default()
            .push(link);
    }

    let mut visited = BTreeSet::new();
    visited.insert(source.as_str());
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

fn is_qualified_authorization_relation(relation: &str) -> bool {
    matches!(
        relation,
        R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION
            | R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION
            | R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
            | R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
    )
}

fn qualification_provenance(
    route: &RouteObservation,
    guard: &GuardObservation,
    operation: &DataOperation,
) -> Vec<SourceLocation> {
    let mut provenance = BTreeSet::new();
    provenance.extend(route.provenance().iter().cloned());
    provenance.extend(guard.provenance().iter().cloned());
    provenance.extend(operation.provenance().iter().cloned());
    provenance.into_iter().collect()
}

fn required_role_authorization_link(
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
    provenance: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerLink, PathCorrelationError> {
    Ok(CrossLayerLink::new(
        StableSemanticId::from_parts(
            "r3-required-role-correlation-link",
            &[source.as_str(), target.as_str(), relation],
            limits,
        )?,
        source.clone(),
        target.clone(),
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        provenance,
        limits,
    )?)
}

fn elevated_client_authorization_link(
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
    provenance: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerLink, PathCorrelationError> {
    Ok(CrossLayerLink::new(
        StableSemanticId::from_parts(
            "r3-elevated-client-correlation-link",
            &[source.as_str(), target.as_str(), relation],
            limits,
        )?,
        source.clone(),
        target.clone(),
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        provenance,
        limits,
    )?)
}
