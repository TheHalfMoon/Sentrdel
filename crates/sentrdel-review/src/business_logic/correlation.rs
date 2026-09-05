//! Deterministic bounded cross-layer correlation for canonical R3-T017.
//!
//! Correlation consumes only already-validated R3 observations and T016 links. It never executes
//! target code, performs network/provider access, receives provider credentials, creates Findings,
//! or upgrades graph/link confidence into stronger epistemic authority. Unresolved or ambiguous
//! identity remains partial/ambiguous instead of becoming a guessed clean path.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use sentrdel_schema::{canonical::content_id, coverage::CoverageState};

use super::model::{
    ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ConfidenceBasis,
    CrossLayerLink, CrossLayerPath, DataOperation, DominanceScope, GuardObservation, LinkBasis,
    ModelError, PathState, ProviderAuthorityClass, ProviderClientAuthority, RouteObservation,
    SourceLocation, StableSemanticId, TrustBasis, ValueOrigin, ValueOriginKind,
};

pub const DEFAULT_MAX_CORRELATION_GRAPH_NODES: usize = 4_096;
pub const DEFAULT_MAX_CORRELATION_GRAPH_EDGES: usize = 8_192;
pub const DEFAULT_MAX_CORRELATION_DEPTH: usize = 32;
pub const DEFAULT_MAX_CORRELATED_OBSERVATIONS: usize = 16_384;
pub const R3_CORRELATION_EXECUTES_TARGET_CODE: bool = false;
pub const R3_CORRELATION_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_CORRELATION_USES_PROVIDER_CREDENTIALS: bool = false;
pub const R3_CORRELATION_CREATES_FINDINGS: bool = false;
pub const R3_CORRELATION_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY: bool = false;

const SAME_HANDLER_RELATION: &str = "same_handler_structural";
const HANDLER_OPERATION_RELATION: &str = "contains_data_operation";
const VALUE_OPERATION_RELATION: &str = "feeds_data_operation";
const VALUE_DERIVATION_RELATION: &str = "derives_value";
const ACTOR_VALUE_RELATION: &str = "sources_value";
const ACTOR_GUARD_RELATION: &str = "subjects_guard";
const GUARD_OPERATION_RELATION: &str = "constrains_operation";
const CLIENT_OPERATION_RELATION: &str = "authorizes_provider_client";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorrelationLimits {
    pub max_graph_nodes: usize,
    pub max_graph_edges: usize,
    pub max_traversal_depth: usize,
    pub max_correlated_observations: usize,
    pub max_candidate_paths: usize,
    pub max_diagnostics: usize,
}

impl Default for CorrelationLimits {
    fn default() -> Self {
        Self {
            max_graph_nodes: DEFAULT_MAX_CORRELATION_GRAPH_NODES,
            max_graph_edges: DEFAULT_MAX_CORRELATION_GRAPH_EDGES,
            max_traversal_depth: DEFAULT_MAX_CORRELATION_DEPTH,
            max_correlated_observations: DEFAULT_MAX_CORRELATED_OBSERVATIONS,
            max_candidate_paths: super::model::DEFAULT_MAX_PATH_CANDIDATES,
            max_diagnostics: super::model::DEFAULT_MAX_DIAGNOSTICS,
        }
    }
}

impl CorrelationLimits {
    fn validate(self, business: BusinessLogicLimits) -> Result<Self, CorrelationError> {
        let business = business.validate()?;
        if self.max_graph_nodes == 0
            || self.max_graph_edges == 0
            || self.max_traversal_depth == 0
            || self.max_correlated_observations == 0
            || self.max_candidate_paths == 0
            || self.max_diagnostics == 0
        {
            return Err(CorrelationError::InvalidLimits);
        }
        Ok(Self {
            max_candidate_paths: self.max_candidate_paths.min(business.max_path_candidates),
            max_diagnostics: self.max_diagnostics.min(business.max_diagnostics),
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CorrelationDiagnosticReason {
    GraphNodeLimitExceeded,
    GraphEdgeLimitExceeded,
    CorrelatedObservationLimitExceeded,
    CandidatePathLimitExceeded,
    DiagnosticLimitExceeded,
    PathLinkLimitExceeded,
    TraversalDepthExceeded,
    MissingOperationHandler,
    UnresolvedRouteForOperation,
    AmbiguousRouteForOperation,
    DuplicateObservationIdentity,
    MissingValueOrigin,
    UnknownValueOrigin,
    MissingActor,
    UnknownActor,
    UnresolvedGuardScope,
    UnknownGuardDominance,
    MissingProviderClient,
    UnknownProviderAuthority,
    AmbiguousLinkPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationDiagnostic {
    reason: CorrelationDiagnosticReason,
    route_id: Option<StableSemanticId>,
    operation_id: Option<StableSemanticId>,
}

impl CorrelationDiagnostic {
    #[must_use]
    pub const fn reason(&self) -> CorrelationDiagnosticReason {
        self.reason
    }

    #[must_use]
    pub fn route_id(&self) -> Option<&StableSemanticId> {
        self.route_id.as_ref()
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<&StableSemanticId> {
        self.operation_id.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorrelationResult {
    paths: Vec<CrossLayerPath>,
    coverage_state: CoverageState,
    diagnostics: Vec<CorrelationDiagnostic>,
}

impl CorrelationResult {
    #[must_use]
    pub fn paths(&self) -> &[CrossLayerPath] {
        &self.paths
    }

    #[must_use]
    pub fn coverage_state(&self) -> &CoverageState {
        &self.coverage_state
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[CorrelationDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Debug)]
pub enum CorrelationError {
    InvalidLimits,
    Model(ModelError),
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("R3 correlation limits must be non-zero"),
            Self::Model(source) => write!(formatter, "R3 correlation model error: {source}"),
        }
    }
}

impl Error for CorrelationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            Self::InvalidLimits => None,
        }
    }
}

impl From<ModelError> for CorrelationError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub struct CorrelationInputs<'a> {
    pub routes: &'a [RouteObservation],
    pub actors: &'a [ActorContext],
    pub guards: &'a [GuardObservation],
    pub values: &'a [ValueOrigin],
    pub operations: &'a [DataOperation],
    pub provider_clients: &'a [ProviderClientAuthority],
    pub links: &'a [CrossLayerLink],
}

#[derive(Clone)]
struct RouteCandidate<'a> {
    route: &'a RouteObservation,
    links: Vec<CrossLayerLink>,
    ambiguous_links: bool,
}

struct LinkTraversal {
    links: Option<Vec<CrossLayerLink>>,
    ambiguous: bool,
    depth_exhausted: bool,
}

pub fn correlate_cross_layer_paths(
    inputs: CorrelationInputs<'_>,
    business_limits: BusinessLogicLimits,
    correlation_limits: CorrelationLimits,
) -> Result<CorrelationResult, CorrelationError> {
    let business_limits = business_limits.validate()?;
    let correlation_limits = correlation_limits.validate(business_limits)?;
    let mut diagnostics = Vec::new();

    if inputs.routes.is_empty() || inputs.operations.is_empty() {
        return Ok(CorrelationResult {
            paths: Vec::new(),
            coverage_state: CoverageState::Unavailable,
            diagnostics,
        });
    }

    let observation_count = inputs
        .routes
        .len()
        .saturating_add(inputs.actors.len())
        .saturating_add(inputs.guards.len())
        .saturating_add(inputs.values.len())
        .saturating_add(inputs.operations.len())
        .saturating_add(inputs.provider_clients.len());
    if observation_count > correlation_limits.max_correlated_observations {
        add_diagnostic(
            &mut diagnostics,
            CorrelationDiagnosticReason::CorrelatedObservationLimitExceeded,
            None,
            None,
            correlation_limits,
        );
        return Ok(partial_result(Vec::new(), diagnostics));
    }
    if inputs.links.len() > correlation_limits.max_graph_edges {
        add_diagnostic(
            &mut diagnostics,
            CorrelationDiagnosticReason::GraphEdgeLimitExceeded,
            None,
            None,
            correlation_limits,
        );
        return Ok(partial_result(Vec::new(), diagnostics));
    }
    if link_graph_nodes(inputs.links).len() > correlation_limits.max_graph_nodes {
        add_diagnostic(
            &mut diagnostics,
            CorrelationDiagnosticReason::GraphNodeLimitExceeded,
            None,
            None,
            correlation_limits,
        );
        return Ok(partial_result(Vec::new(), diagnostics));
    }

    let adjacency = link_adjacency(inputs.links);
    let actors = index_by_id(inputs.actors, ActorContext::actor_id);
    let guards = index_by_id(inputs.guards, GuardObservation::guard_id);
    let values = index_by_id(inputs.values, ValueOrigin::value_id);
    let clients = index_by_id(inputs.provider_clients, ProviderClientAuthority::client_id);
    let mut duplicate_ids = BTreeSet::new();
    collect_duplicate_ids(&actors, &mut duplicate_ids);
    collect_duplicate_ids(&guards, &mut duplicate_ids);
    collect_duplicate_ids(&values, &mut duplicate_ids);
    collect_duplicate_ids(&clients, &mut duplicate_ids);
    collect_sequence_duplicates(
        inputs.routes.iter().map(RouteObservation::route_id),
        &mut duplicate_ids,
    );
    collect_sequence_duplicates(
        inputs.operations.iter().map(DataOperation::operation_id),
        &mut duplicate_ids,
    );
    if !duplicate_ids.is_empty() {
        add_diagnostic(
            &mut diagnostics,
            CorrelationDiagnosticReason::DuplicateObservationIdentity,
            None,
            None,
            correlation_limits,
        );
    }

    let mut paths = Vec::new();
    let mut all_correlated = true;
    let mut all_supported = true;
    let mut operations = inputs.operations.iter().collect::<Vec<_>>();
    operations.sort_by(|left, right| left.operation_id().cmp(right.operation_id()));

    'operations: for operation in operations {
        if duplicate_ids.contains(operation.operation_id().as_str()) {
            all_correlated = false;
            all_supported = false;
            continue;
        }
        let mut candidates = route_candidates(
            operation,
            inputs.routes,
            &adjacency,
            business_limits,
            correlation_limits,
            &mut diagnostics,
        )?;
        candidates.sort_by(|left, right| left.route.route_id().cmp(right.route.route_id()));

        if candidates.is_empty() {
            all_correlated = false;
            all_supported = false;
            add_diagnostic(
                &mut diagnostics,
                if operation.handler_symbol().is_none() {
                    CorrelationDiagnosticReason::MissingOperationHandler
                } else {
                    CorrelationDiagnosticReason::UnresolvedRouteForOperation
                },
                None,
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
            continue;
        }

        let route_ambiguous = candidates.len() > 1;
        if route_ambiguous {
            all_supported = false;
            add_diagnostic(
                &mut diagnostics,
                CorrelationDiagnosticReason::AmbiguousRouteForOperation,
                None,
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
        }

        for candidate in candidates {
            if paths.len() >= correlation_limits.max_candidate_paths {
                all_correlated = false;
                all_supported = false;
                add_diagnostic(
                    &mut diagnostics,
                    CorrelationDiagnosticReason::CandidatePathLimitExceeded,
                    None,
                    Some(operation.operation_id().clone()),
                    correlation_limits,
                );
                break 'operations;
            }
            if duplicate_ids.contains(candidate.route.route_id().as_str()) {
                all_supported = false;
                continue;
            }

            let mut path = assemble_path(
                &candidate,
                operation,
                &actors,
                &guards,
                &values,
                &clients,
                &duplicate_ids,
                business_limits,
                correlation_limits,
                &mut diagnostics,
            )?;
            if route_ambiguous && path.path_state() != PathState::BoundedRejection {
                path = rebuild_path_state(path, PathState::Ambiguous, business_limits)?;
            }
            if path.path_state() != PathState::Supported {
                all_supported = false;
            }
            paths.push(path);
        }
    }

    paths.sort_by(|left, right| left.path_id().cmp(right.path_id()));
    paths.dedup_by(|left, right| left.path_id() == right.path_id());
    let coverage_state = if all_correlated
        && all_supported
        && diagnostics.is_empty()
        && !paths.is_empty()
    {
        CoverageState::Covered
    } else {
        CoverageState::Partial
    };
    Ok(CorrelationResult {
        paths,
        coverage_state,
        diagnostics,
    })
}

fn partial_result(
    paths: Vec<CrossLayerPath>,
    diagnostics: Vec<CorrelationDiagnostic>,
) -> CorrelationResult {
    CorrelationResult {
        paths,
        coverage_state: CoverageState::Partial,
        diagnostics,
    }
}

fn index_by_id<'a, T, F>(items: &'a [T], id: F) -> BTreeMap<String, Vec<&'a T>>
where
    F: Fn(&T) -> &StableSemanticId,
{
    let mut indexed = BTreeMap::<String, Vec<&T>>::new();
    for item in items {
        indexed
            .entry(id(item).as_str().to_owned())
            .or_default()
            .push(item);
    }
    indexed
}

fn collect_duplicate_ids<T>(
    index: &BTreeMap<String, Vec<&T>>,
    duplicates: &mut BTreeSet<String>,
) {
    for (id, observations) in index {
        if observations.len() > 1 {
            duplicates.insert(id.clone());
        }
    }
}

fn collect_sequence_duplicates<'a>(
    ids: impl Iterator<Item = &'a StableSemanticId>,
    duplicates: &mut BTreeSet<String>,
) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str().to_owned()) {
            duplicates.insert(id.as_str().to_owned());
        }
    }
}

fn link_graph_nodes(links: &[CrossLayerLink]) -> BTreeSet<String> {
    let mut nodes = BTreeSet::new();
    for link in links {
        nodes.insert(link.source_semantic_id().as_str().to_owned());
        nodes.insert(link.target_semantic_id().as_str().to_owned());
    }
    nodes
}

fn link_adjacency(links: &[CrossLayerLink]) -> BTreeMap<String, Vec<CrossLayerLink>> {
    let mut adjacency = BTreeMap::<String, Vec<CrossLayerLink>>::new();
    for link in links {
        adjacency
            .entry(link.source_semantic_id().as_str().to_owned())
            .or_default()
            .push(link.clone());
    }
    for outgoing in adjacency.values_mut() {
        outgoing.sort();
        outgoing.dedup();
    }
    adjacency
}

fn route_candidates<'a>(
    operation: &DataOperation,
    routes: &'a [RouteObservation],
    adjacency: &BTreeMap<String, Vec<CrossLayerLink>>,
    business_limits: BusinessLogicLimits,
    correlation_limits: CorrelationLimits,
    diagnostics: &mut Vec<CorrelationDiagnostic>,
) -> Result<Vec<RouteCandidate<'a>>, CorrelationError> {
    let mut candidates = Vec::new();
    if let Some(handler) = operation.handler_symbol() {
        for route in routes {
            let traversal = traverse_links(
                route.route_id(),
                handler,
                adjacency,
                correlation_limits.max_traversal_depth,
            );
            if traversal.depth_exhausted {
                add_diagnostic(
                    diagnostics,
                    CorrelationDiagnosticReason::TraversalDepthExceeded,
                    Some(route.route_id().clone()),
                    Some(operation.operation_id().clone()),
                    correlation_limits,
                );
            }
            let Some(mut links) = traversal.links else {
                continue;
            };
            if traversal.ambiguous {
                add_diagnostic(
                    diagnostics,
                    CorrelationDiagnosticReason::AmbiguousLinkPath,
                    Some(route.route_id().clone()),
                    Some(operation.operation_id().clone()),
                    correlation_limits,
                );
            }
            links.push(correlation_link(
                handler.clone(),
                operation.operation_id().clone(),
                HANDLER_OPERATION_RELATION,
                LinkBasis::ExplicitAdapterLink,
                ConfidenceBasis::Extracted,
                operation.provenance().to_vec(),
                business_limits,
            )?);
            candidates.push(RouteCandidate {
                route,
                links,
                ambiguous_links: traversal.ambiguous,
            });
        }
        return Ok(candidates);
    }

    for route in routes {
        if same_handler_structural(route, operation) {
            candidates.push(RouteCandidate {
                route,
                links: vec![correlation_link(
                    route.route_id().clone(),
                    operation.operation_id().clone(),
                    SAME_HANDLER_RELATION,
                    LinkBasis::SameHandlerStructural,
                    ConfidenceBasis::Inferred,
                    operation.provenance().to_vec(),
                    business_limits,
                )?],
                ambiguous_links: false,
            });
        }
    }
    Ok(candidates)
}

fn same_handler_structural(route: &RouteObservation, operation: &DataOperation) -> bool {
    route.provenance().iter().any(|route_location| {
        operation.provenance().iter().any(|operation_location| {
            route_location.path() == operation_location.path()
                && route_location.start_byte() <= operation_location.start_byte()
                && operation_location.end_byte() <= route_location.end_byte()
        })
    })
}

fn traverse_links(
    source: &StableSemanticId,
    target: &StableSemanticId,
    adjacency: &BTreeMap<String, Vec<CrossLayerLink>>,
    max_depth: usize,
) -> LinkTraversal {
    if source == target {
        return LinkTraversal {
            links: Some(Vec::new()),
            ambiguous: false,
            depth_exhausted: false,
        };
    }
    let mut queue = VecDeque::from([(source.as_str().to_owned(), Vec::<CrossLayerLink>::new())]);
    let mut best_depth = BTreeMap::from([(source.as_str().to_owned(), 0usize)]);
    let mut found: Option<Vec<CrossLayerLink>> = None;
    let mut ambiguous = false;
    let mut depth_exhausted = false;

    while let Some((node, path)) = queue.pop_front() {
        if path.len() >= max_depth {
            if adjacency.get(&node).is_some_and(|outgoing| !outgoing.is_empty()) {
                depth_exhausted = true;
            }
            continue;
        }
        let Some(outgoing) = adjacency.get(&node) else {
            continue;
        };
        for link in outgoing {
            let mut next_path = path.clone();
            next_path.push(link.clone());
            let next = link.target_semantic_id().as_str().to_owned();
            if next == target.as_str() {
                match &found {
                    None => found = Some(next_path),
                    Some(existing) if existing != &next_path => ambiguous = true,
                    Some(_) => {}
                }
                continue;
            }
            if found.is_some() {
                continue;
            }
            let depth = next_path.len();
            if best_depth.get(&next).is_none_or(|best| depth <= *best) {
                best_depth.insert(next.clone(), depth);
                queue.push_back((next, next_path));
            }
        }
    }

    if let Some(links) = &found {
        ambiguous |= links.iter().any(|link| {
            link.basis() == LinkBasis::Unknown
                || link.confidence_basis() == ConfidenceBasis::Ambiguous
        });
    }
    LinkTraversal {
        links: found,
        ambiguous,
        depth_exhausted,
    }
}

#[allow(clippy::too_many_arguments)]
fn assemble_path(
    candidate: &RouteCandidate<'_>,
    operation: &DataOperation,
    actors: &BTreeMap<String, Vec<&ActorContext>>,
    guards: &BTreeMap<String, Vec<&GuardObservation>>,
    values: &BTreeMap<String, Vec<&ValueOrigin>>,
    clients: &BTreeMap<String, Vec<&ProviderClientAuthority>>,
    duplicate_ids: &BTreeSet<String>,
    business_limits: BusinessLogicLimits,
    correlation_limits: CorrelationLimits,
    diagnostics: &mut Vec<CorrelationDiagnostic>,
) -> Result<CrossLayerPath, CorrelationError> {
    let route = candidate.route;
    let mut state = if route.coverage_state() == &CoverageState::Covered
        && operation.coverage_state() == &CoverageState::Covered
        && !candidate.ambiguous_links
    {
        PathState::Supported
    } else if candidate.ambiguous_links {
        PathState::Ambiguous
    } else {
        PathState::Partial
    };
    let mut links = candidate.links.clone();
    let direct_value_ids = direct_operation_value_ids(operation);
    let mut pending_values = direct_value_ids.clone();
    let mut visited_values = BTreeSet::new();
    let mut actor_ids = BTreeSet::<StableSemanticId>::new();

    while let Some(value_id) = pending_values.pop_first() {
        if !visited_values.insert(value_id.clone()) {
            continue;
        }
        if duplicate_ids.contains(&value_id) {
            state = PathState::Ambiguous;
            continue;
        }
        let Some(entries) = values.get(&value_id) else {
            state = degrade_to_partial(state);
            add_diagnostic(
                diagnostics,
                CorrelationDiagnosticReason::MissingValueOrigin,
                Some(route.route_id().clone()),
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
            continue;
        };
        let Some(value) = entries.first().copied() else {
            continue;
        };
        if value.origin_kind() == ValueOriginKind::Unknown {
            state = degrade_to_partial(state);
            add_diagnostic(
                diagnostics,
                CorrelationDiagnosticReason::UnknownValueOrigin,
                Some(route.route_id().clone()),
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
        }
        if direct_value_ids.contains(value.value_id().as_str()) {
            links.push(correlation_link(
                value.value_id().clone(),
                operation.operation_id().clone(),
                VALUE_OPERATION_RELATION,
                LinkBasis::ExplicitAdapterLink,
                ConfidenceBasis::Extracted,
                value.provenance().to_vec(),
                business_limits,
            )?);
        }
        if let Some(actor) = value.source_actor() {
            actor_ids.insert(actor.clone());
            links.push(correlation_link(
                actor.clone(),
                value.value_id().clone(),
                ACTOR_VALUE_RELATION,
                LinkBasis::ExplicitAdapterLink,
                ConfidenceBasis::Extracted,
                value.provenance().to_vec(),
                business_limits,
            )?);
        }
        for input in value.derivation_inputs() {
            pending_values.insert(input.as_str().to_owned());
            links.push(correlation_link(
                input.clone(),
                value.value_id().clone(),
                VALUE_DERIVATION_RELATION,
                LinkBasis::ExplicitAdapterLink,
                ConfidenceBasis::Extracted,
                value.provenance().to_vec(),
                business_limits,
            )?);
        }
    }

    for actor_id in actor_ids.clone() {
        if duplicate_ids.contains(actor_id.as_str()) {
            state = PathState::Ambiguous;
            continue;
        }
        let Some(entries) = actors.get(actor_id.as_str()) else {
            state = degrade_to_partial(state);
            add_diagnostic(
                diagnostics,
                CorrelationDiagnosticReason::MissingActor,
                Some(route.route_id().clone()),
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
            continue;
        };
        if let Some(actor) = entries.first()
            && (actor.identity_kind() == ActorIdentityKind::Unknown
                || actor.source_kind() == ActorSourceKind::Unknown
                || actor.trust_basis() == TrustBasis::Unknown)
        {
            state = degrade_to_partial(state);
            add_diagnostic(
                diagnostics,
                CorrelationDiagnosticReason::UnknownActor,
                Some(route.route_id().clone()),
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
        }
    }

    let reachable = reachable_ids(route.route_id(), &links, correlation_limits.max_traversal_depth);
    let mut guard_ids = BTreeSet::<StableSemanticId>::new();
    let mut unresolved_guard_scope = false;
    for entries in guards.values() {
        if entries.len() != 1 {
            continue;
        }
        let guard = entries[0];
        let subject_is_attached = guard
            .subject_actor()
            .is_some_and(|subject| actor_ids.contains(subject));
        let explicitly_reachable = reachable.contains(guard.guard_id().as_str());
        if subject_is_attached || explicitly_reachable {
            guard_ids.insert(guard.guard_id().clone());
            if let Some(subject) = guard.subject_actor() {
                actor_ids.insert(subject.clone());
                links.push(correlation_link(
                    subject.clone(),
                    guard.guard_id().clone(),
                    ACTOR_GUARD_RELATION,
                    LinkBasis::ExplicitAdapterLink,
                    ConfidenceBasis::Extracted,
                    guard.provenance().to_vec(),
                    business_limits,
                )?);
            }
            if guard.resource().is_some_and(|resource| resource == operation.resource()) {
                links.push(correlation_link(
                    guard.guard_id().clone(),
                    operation.operation_id().clone(),
                    GUARD_OPERATION_RELATION,
                    LinkBasis::SameHandlerStructural,
                    ConfidenceBasis::Inferred,
                    guard.provenance().to_vec(),
                    business_limits,
                )?);
            }
            if guard.dominance_scope() == DominanceScope::Unknown {
                state = degrade_to_partial(state);
                add_diagnostic(
                    diagnostics,
                    CorrelationDiagnosticReason::UnknownGuardDominance,
                    Some(route.route_id().clone()),
                    Some(operation.operation_id().clone()),
                    correlation_limits,
                );
            }
        } else if guard.resource().is_some_and(|resource| resource == operation.resource())
            && shares_path(guard.provenance(), operation.provenance())
        {
            unresolved_guard_scope = true;
        }
    }
    if unresolved_guard_scope {
        state = degrade_to_partial(state);
        add_diagnostic(
            diagnostics,
            CorrelationDiagnosticReason::UnresolvedGuardScope,
            Some(route.route_id().clone()),
            Some(operation.operation_id().clone()),
            correlation_limits,
        );
    }

    let mut provider_client_id = None;
    if let Some(client_id) = operation.provider_client() {
        provider_client_id = Some(client_id.clone());
        if duplicate_ids.contains(client_id.as_str()) {
            state = PathState::Ambiguous;
        } else if let Some(entries) = clients.get(client_id.as_str()) {
            if let Some(client) = entries.first() {
                links.push(correlation_link(
                    client.client_id().clone(),
                    operation.operation_id().clone(),
                    CLIENT_OPERATION_RELATION,
                    LinkBasis::ExplicitAdapterLink,
                    ConfidenceBasis::Extracted,
                    client.provenance().to_vec(),
                    business_limits,
                )?);
                if matches!(
                    client.authority_class(),
                    ProviderAuthorityClass::ServerUnknown | ProviderAuthorityClass::Unknown
                ) {
                    state = degrade_to_partial(state);
                    add_diagnostic(
                        diagnostics,
                        CorrelationDiagnosticReason::UnknownProviderAuthority,
                        Some(route.route_id().clone()),
                        Some(operation.operation_id().clone()),
                        correlation_limits,
                    );
                }
            }
        } else {
            state = degrade_to_partial(state);
            add_diagnostic(
                diagnostics,
                CorrelationDiagnosticReason::MissingProviderClient,
                Some(route.route_id().clone()),
                Some(operation.operation_id().clone()),
                correlation_limits,
            );
        }
    }

    links.sort();
    links.dedup();
    if links.len() > business_limits.max_path_links {
        state = PathState::BoundedRejection;
        add_diagnostic(
            diagnostics,
            CorrelationDiagnosticReason::PathLinkLimitExceeded,
            Some(route.route_id().clone()),
            Some(operation.operation_id().clone()),
            correlation_limits,
        );
        links.truncate(business_limits.max_path_links);
    }

    let actor_ids = actor_ids.into_iter().collect::<Vec<_>>();
    let guard_ids = guard_ids.into_iter().collect::<Vec<_>>();
    let path_id = stable_path_id(
        route.route_id(),
        &actor_ids,
        &guard_ids,
        operation.operation_id(),
        provider_client_id.as_ref(),
        &links,
        business_limits,
    )?;
    CrossLayerPath::new(
        path_id,
        route.route_id().clone(),
        actor_ids,
        guard_ids,
        operation.operation_id().clone(),
        provider_client_id,
        links,
        Vec::new(),
        state,
        minimal_path_provenance(route, operation),
        business_limits,
    )
    .map_err(CorrelationError::from)
}

fn rebuild_path_state(
    path: CrossLayerPath,
    state: PathState,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerPath, CorrelationError> {
    CrossLayerPath::new(
        path.path_id().clone(),
        path.route_id().clone(),
        path.actor_ids().to_vec(),
        path.guard_ids().to_vec(),
        path.data_operation_id().clone(),
        path.provider_client_id().cloned(),
        path.links().to_vec(),
        path.r2_evidence_ids().to_vec(),
        state,
        path.provenance().to_vec(),
        limits,
    )
    .map_err(CorrelationError::from)
}

fn direct_operation_value_ids(operation: &DataOperation) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for filter in operation.filters() {
        values.insert(filter.value_origin().as_str().to_owned());
    }
    for fields in [operation.read_fields(), operation.mutation_fields()]
        .into_iter()
        .flatten()
    {
        for (_, value) in fields.value_origins() {
            values.insert(value.as_str().to_owned());
        }
    }
    values
}

fn reachable_ids(
    source: &StableSemanticId,
    links: &[CrossLayerLink],
    max_depth: usize,
) -> BTreeSet<String> {
    let adjacency = link_adjacency(links);
    let mut reached = BTreeSet::from([source.as_str().to_owned()]);
    let mut queue = VecDeque::from([(source.as_str().to_owned(), 0usize)]);
    while let Some((node, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }
        if let Some(outgoing) = adjacency.get(&node) {
            for link in outgoing {
                let target = link.target_semantic_id().as_str().to_owned();
                if reached.insert(target.clone()) {
                    queue.push_back((target, depth + 1));
                }
            }
        }
    }
    reached
}

fn correlation_link(
    source: StableSemanticId,
    target: StableSemanticId,
    relation: &'static str,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
    provenance: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerLink, CorrelationError> {
    let link_id = StableSemanticId::from_parts(
        "r3-correlation-link",
        &[
            source.as_str(),
            target.as_str(),
            relation,
            link_basis_key(basis),
            confidence_key(confidence),
        ],
        limits,
    )?;
    CrossLayerLink::new(
        link_id,
        source,
        target,
        relation,
        basis,
        confidence,
        provenance,
        limits,
    )
    .map_err(CorrelationError::from)
}

fn stable_path_id(
    route: &StableSemanticId,
    actor_ids: &[StableSemanticId],
    guard_ids: &[StableSemanticId],
    operation: &StableSemanticId,
    provider_client: Option<&StableSemanticId>,
    links: &[CrossLayerLink],
    limits: BusinessLogicLimits,
) -> Result<StableSemanticId, CorrelationError> {
    let components = (
        actor_ids
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        guard_ids
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        provider_client.map(|id| id.as_str().to_owned()),
        links
            .iter()
            .map(|link| {
                (
                    link.source_semantic_id().as_str().to_owned(),
                    link.target_semantic_id().as_str().to_owned(),
                    link.relation().to_owned(),
                    link_basis_key(link.basis()).to_owned(),
                    confidence_key(link.confidence_basis()).to_owned(),
                )
            })
            .collect::<Vec<_>>(),
    );
    let digest = content_id("r3-cross-layer-path-components", &components)
        .map_err(ModelError::from)?;
    StableSemanticId::from_parts(
        "r3-cross-layer-path",
        &[route.as_str(), operation.as_str(), &digest],
        limits,
    )
    .map_err(CorrelationError::from)
}

fn minimal_path_provenance(
    route: &RouteObservation,
    operation: &DataOperation,
) -> Vec<SourceLocation> {
    let mut provenance = Vec::new();
    if let Some(location) = route.provenance().first() {
        provenance.push(location.clone());
    }
    if let Some(location) = operation.provenance().first() {
        provenance.push(location.clone());
    }
    provenance.sort();
    provenance.dedup();
    provenance
}

fn shares_path(left: &[SourceLocation], right: &[SourceLocation]) -> bool {
    left.iter()
        .any(|left| right.iter().any(|right| left.path() == right.path()))
}

fn degrade_to_partial(state: PathState) -> PathState {
    match state {
        PathState::Supported => PathState::Partial,
        other => other,
    }
}

fn add_diagnostic(
    diagnostics: &mut Vec<CorrelationDiagnostic>,
    reason: CorrelationDiagnosticReason,
    route_id: Option<StableSemanticId>,
    operation_id: Option<StableSemanticId>,
    limits: CorrelationLimits,
) {
    let candidate = CorrelationDiagnostic {
        reason,
        route_id,
        operation_id,
    };
    if diagnostics.contains(&candidate) || diagnostics.len() >= limits.max_diagnostics {
        return;
    }
    if diagnostics.len() + 1 == limits.max_diagnostics
        && candidate.reason != CorrelationDiagnosticReason::DiagnosticLimitExceeded
    {
        diagnostics.push(CorrelationDiagnostic {
            reason: CorrelationDiagnosticReason::DiagnosticLimitExceeded,
            route_id: None,
            operation_id: None,
        });
    } else {
        diagnostics.push(candidate);
    }
    diagnostics.sort_by(|left, right| {
        left.reason
            .cmp(&right.reason)
            .then_with(|| left.route_id.cmp(&right.route_id))
            .then_with(|| left.operation_id.cmp(&right.operation_id))
    });
}

const fn link_basis_key(basis: LinkBasis) -> &'static str {
    match basis {
        LinkBasis::SameHandlerStructural => "same-handler-structural",
        LinkBasis::SupportedCallbackChain => "supported-callback-chain",
        LinkBasis::SupportedImportBinding => "supported-import-binding",
        LinkBasis::ScipReference => "scip-reference",
        LinkBasis::ExplicitAdapterLink => "explicit-adapter-link",
        LinkBasis::Unknown => "unknown",
    }
}

const fn confidence_key(confidence: ConfidenceBasis) -> &'static str {
    match confidence {
        ConfidenceBasis::Extracted => "extracted",
        ConfidenceBasis::Inferred => "inferred",
        ConfidenceBasis::Ambiguous => "ambiguous",
    }
}
