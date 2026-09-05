//! Deterministic bounded R3-T017 cross-layer path correlation.
//!
//! This module correlates only normalized R3 observations and explicit semantic links. It never
//! reparses target source, equates lexical names, classifies provider authority, consumes R2
//! evidence, executes target code, performs network access, or creates Findings. Missing,
//! ambiguous, unknown, or bounded-out relationships remain fail-visible coverage gaps.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::link::CALLBACK_CHAIN_RELATION;
use super::model::{
    ActorContext, ActorIdentityKind, BusinessLogicLimits, ComparisonShape, ConfidenceBasis,
    CrossLayerLink, CrossLayerPath, DataOperation, DominanceScope, GuardObservation, LinkBasis,
    ModelError, PathState, ProviderAuthorityClass, ProviderClientAuthority, RouteObservation,
    SourceLocation, StableSemanticId, TrustBasis, ValueOrigin, ValueOriginKind,
};

pub const DEFAULT_MAX_CORRELATION_OBSERVATIONS: usize = 16_384;
pub const DEFAULT_MAX_CORRELATION_NODES: usize = 16_384;
pub const DEFAULT_MAX_CORRELATION_EDGES: usize = 32_768;
pub const DEFAULT_MAX_CORRELATION_DEPTH: usize = 32;
pub const DEFAULT_MAX_CORRELATION_CANDIDATES: usize = 4_096;
pub const DEFAULT_MAX_CORRELATION_DIAGNOSTICS: usize = 1_024;
pub const DEFAULT_MAX_CORRELATION_WORK_ITEMS: usize = 65_536;
pub const DEFAULT_MAX_CORRELATION_FRONTIER: usize = 8_192;

pub const R3_PATH_CORRELATION_EXECUTES_TARGET_CODE: bool = false;
pub const R3_PATH_CORRELATION_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_PATH_CORRELATION_CLASSIFIES_PROVIDER_AUTHORITY: bool = false;
pub const R3_PATH_CORRELATION_CONSUMES_R2_EVIDENCE: bool = false;
pub const R3_PATH_CORRELATION_CREATES_FINDINGS: bool = false;
pub const R3_PATH_CONFIDENCE_GRANTS_EVIDENCE_AUTHORITY: bool = false;

const ACTOR_VALUE_RELATION: &str = "actor_sources_value";
const VALUE_DERIVATION_RELATION: &str = "value_derives_to";
const ACTOR_GUARD_RELATION: &str = "actor_subject_of_guard";
const VALUE_FILTER_RELATION: &str = "value_feeds_filter";
const VALUE_FIELD_RELATION: &str = "value_feeds_field";
const HANDLER_OPERATION_RELATION: &str = "handler_contains_operation";
const OPERATION_CLIENT_RELATION: &str = "operation_uses_provider_client";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathCorrelationLimits {
    pub max_observations: usize,
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_depth: usize,
    pub max_candidate_paths: usize,
    pub max_diagnostics: usize,
    pub max_work_items: usize,
    pub max_frontier: usize,
}

impl Default for PathCorrelationLimits {
    fn default() -> Self {
        Self {
            max_observations: DEFAULT_MAX_CORRELATION_OBSERVATIONS,
            max_nodes: DEFAULT_MAX_CORRELATION_NODES,
            max_edges: DEFAULT_MAX_CORRELATION_EDGES,
            max_depth: DEFAULT_MAX_CORRELATION_DEPTH,
            max_candidate_paths: DEFAULT_MAX_CORRELATION_CANDIDATES,
            max_diagnostics: DEFAULT_MAX_CORRELATION_DIAGNOSTICS,
            max_work_items: DEFAULT_MAX_CORRELATION_WORK_ITEMS,
            max_frontier: DEFAULT_MAX_CORRELATION_FRONTIER,
        }
    }
}

impl PathCorrelationLimits {
    pub fn validate(self) -> Result<Self, PathCorrelationError> {
        if self.max_observations == 0
            || self.max_nodes == 0
            || self.max_edges == 0
            || self.max_depth == 0
            || self.max_candidate_paths == 0
            || self.max_diagnostics == 0
            || self.max_work_items == 0
            || self.max_frontier == 0
        {
            return Err(PathCorrelationError::InvalidLimits);
        }
        Ok(self)
    }
}

pub struct PathCorrelationInputs<'a> {
    pub routes: &'a [RouteObservation],
    pub actors: &'a [ActorContext],
    pub guards: &'a [GuardObservation],
    pub values: &'a [ValueOrigin],
    pub data_operations: &'a [DataOperation],
    pub provider_clients: &'a [ProviderClientAuthority],
    pub links: &'a [CrossLayerLink],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathCorrelationDiagnosticReason {
    NoRoutes,
    NoDataOperations,
    ObservationLimitExceeded,
    AmbiguousSemanticIdentity,
    AmbiguousLinkIdentity,
    DanglingActorReference,
    DanglingValueReference,
    DanglingProviderClientReference,
    IncompleteRouteObservation,
    IncompleteDataOperation,
    MissingRouteDataPath,
    UncorrelatedDataOperation,
    NodeLimitExceeded,
    EdgeLimitExceeded,
    DepthLimitExceeded,
    CandidatePathLimitExceeded,
    TraversalWorkLimitExceeded,
    FrontierLimitExceeded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathCorrelationDiagnostic {
    reason: PathCorrelationDiagnosticReason,
    route_id: Option<StableSemanticId>,
    data_operation_id: Option<StableSemanticId>,
    provenance: Vec<SourceLocation>,
}

impl PathCorrelationDiagnostic {
    #[must_use]
    pub const fn reason(&self) -> PathCorrelationDiagnosticReason {
        self.reason
    }

    #[must_use]
    pub fn route_id(&self) -> Option<&StableSemanticId> {
        self.route_id.as_ref()
    }

    #[must_use]
    pub fn data_operation_id(&self) -> Option<&StableSemanticId> {
        self.data_operation_id.as_ref()
    }

    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
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

#[derive(Debug)]
pub enum PathCorrelationError {
    InvalidLimits,
    TooManyDiagnostics { count: usize, max: usize },
    Model(ModelError),
}

impl fmt::Display for PathCorrelationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("path correlation limits must be non-zero"),
            Self::TooManyDiagnostics { count, max } => {
                write!(
                    formatter,
                    "path correlation diagnostic count {count} exceeds cap {max}"
                )
            }
            Self::Model(source) => write!(
                formatter,
                "path correlation model validation failed: {source}"
            ),
        }
    }
}

impl Error for PathCorrelationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for PathCorrelationError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

#[derive(Clone)]
struct QueueItem {
    node_id: String,
    ordered_links: Vec<CrossLayerLink>,
    visited: BTreeSet<String>,
}

#[allow(clippy::too_many_lines)]
pub fn correlate_cross_layer_paths(
    inputs: PathCorrelationInputs<'_>,
    model_limits: BusinessLogicLimits,
    correlation_limits: PathCorrelationLimits,
) -> Result<PathCorrelationResult, PathCorrelationError> {
    let model_limits = model_limits.validate()?;
    let correlation_limits = correlation_limits.validate()?;
    let mut diagnostics = BTreeMap::new();

    if inputs.routes.is_empty() {
        push_diagnostic(
            &mut diagnostics,
            PathCorrelationDiagnosticReason::NoRoutes,
            None,
            None,
            Vec::new(),
            correlation_limits,
        )?;
    }
    if inputs.data_operations.is_empty() {
        push_diagnostic(
            &mut diagnostics,
            PathCorrelationDiagnosticReason::NoDataOperations,
            None,
            None,
            Vec::new(),
            correlation_limits,
        )?;
    }

    let observation_count = inputs
        .routes
        .len()
        .saturating_add(inputs.actors.len())
        .saturating_add(inputs.guards.len())
        .saturating_add(inputs.values.len())
        .saturating_add(inputs.data_operations.len())
        .saturating_add(inputs.provider_clients.len());
    if observation_count > correlation_limits.max_observations {
        push_diagnostic(
            &mut diagnostics,
            PathCorrelationDiagnosticReason::ObservationLimitExceeded,
            None,
            None,
            Vec::new(),
            correlation_limits,
        )?;
        return Ok(partial_result(Vec::new(), diagnostics));
    }
    if inputs.links.len() > correlation_limits.max_edges {
        push_diagnostic(
            &mut diagnostics,
            PathCorrelationDiagnosticReason::EdgeLimitExceeded,
            None,
            None,
            Vec::new(),
            correlation_limits,
        )?;
        return Ok(partial_result(Vec::new(), diagnostics));
    }

    let mut ambiguous_semantic_ids = BTreeSet::new();
    let mut semantic_kinds = BTreeMap::<String, &'static str>::new();
    let mut nodes = BTreeSet::new();
    let mut routes = BTreeMap::new();
    let mut actors = BTreeMap::new();
    let mut guards = BTreeMap::new();
    let mut values = BTreeMap::new();
    let mut operations = BTreeMap::new();
    let mut clients = BTreeMap::new();

    for value in inputs.routes {
        if !admit_node(&mut nodes, value.route_id(), correlation_limits.max_nodes) {
            return bounded_result(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::NodeLimitExceeded,
                correlation_limits,
            );
        }
        insert_unique_record(
            &mut routes,
            &mut ambiguous_semantic_ids,
            value.route_id().as_str(),
            value,
        );
        register_semantic_kind(
            &mut semantic_kinds,
            &mut ambiguous_semantic_ids,
            value.route_id().as_str(),
            "route",
        );
    }
    for value in inputs.actors {
        if !admit_node(&mut nodes, value.actor_id(), correlation_limits.max_nodes) {
            return bounded_result(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::NodeLimitExceeded,
                correlation_limits,
            );
        }
        insert_unique_record(
            &mut actors,
            &mut ambiguous_semantic_ids,
            value.actor_id().as_str(),
            value,
        );
        register_semantic_kind(
            &mut semantic_kinds,
            &mut ambiguous_semantic_ids,
            value.actor_id().as_str(),
            "actor",
        );
    }
    for value in inputs.guards {
        if !admit_node(&mut nodes, value.guard_id(), correlation_limits.max_nodes) {
            return bounded_result(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::NodeLimitExceeded,
                correlation_limits,
            );
        }
        insert_unique_record(
            &mut guards,
            &mut ambiguous_semantic_ids,
            value.guard_id().as_str(),
            value,
        );
        register_semantic_kind(
            &mut semantic_kinds,
            &mut ambiguous_semantic_ids,
            value.guard_id().as_str(),
            "guard",
        );
    }
    for value in inputs.values {
        if !admit_node(&mut nodes, value.value_id(), correlation_limits.max_nodes) {
            return bounded_result(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::NodeLimitExceeded,
                correlation_limits,
            );
        }
        insert_unique_record(
            &mut values,
            &mut ambiguous_semantic_ids,
            value.value_id().as_str(),
            value,
        );
        register_semantic_kind(
            &mut semantic_kinds,
            &mut ambiguous_semantic_ids,
            value.value_id().as_str(),
            "value",
        );
    }
    for value in inputs.data_operations {
        if !admit_node(
            &mut nodes,
            value.operation_id(),
            correlation_limits.max_nodes,
        ) {
            return bounded_result(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::NodeLimitExceeded,
                correlation_limits,
            );
        }
        insert_unique_record(
            &mut operations,
            &mut ambiguous_semantic_ids,
            value.operation_id().as_str(),
            value,
        );
        register_semantic_kind(
            &mut semantic_kinds,
            &mut ambiguous_semantic_ids,
            value.operation_id().as_str(),
            "data-operation",
        );
    }
    for value in inputs.provider_clients {
        if !admit_node(&mut nodes, value.client_id(), correlation_limits.max_nodes) {
            return bounded_result(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::NodeLimitExceeded,
                correlation_limits,
            );
        }
        insert_unique_record(
            &mut clients,
            &mut ambiguous_semantic_ids,
            value.client_id().as_str(),
            value,
        );
        register_semantic_kind(
            &mut semantic_kinds,
            &mut ambiguous_semantic_ids,
            value.client_id().as_str(),
            "provider-client",
        );
    }

    for id in &ambiguous_semantic_ids {
        push_diagnostic(
            &mut diagnostics,
            PathCorrelationDiagnosticReason::AmbiguousSemanticIdentity,
            None,
            None,
            Vec::new(),
            correlation_limits,
        )?;
        semantic_kinds.remove(id);
    }

    let mut edges = BTreeMap::<String, CrossLayerLink>::new();
    let mut ambiguous_link_ids = BTreeSet::new();
    let mut partial_reference_ids = BTreeSet::new();
    for link in inputs.links {
        if let Some(reason) = insert_unique_link_bounded(
            &mut edges,
            &mut ambiguous_link_ids,
            &mut nodes,
            link.clone(),
            correlation_limits,
        ) {
            return bounded_result(&mut diagnostics, reason, correlation_limits);
        }
    }

    for route in routes.values() {
        if ambiguous_semantic_ids.contains(route.route_id().as_str()) {
            continue;
        }
        let mut source = route.route_id().clone();
        for callback in route.callback_chain() {
            let link = CrossLayerLink::new(
                StableSemanticId::from_parts(
                    "r3-callback-link",
                    &[source.as_str(), callback.as_str()],
                    model_limits,
                )?,
                source,
                callback.clone(),
                CALLBACK_CHAIN_RELATION,
                LinkBasis::SupportedCallbackChain,
                ConfidenceBasis::Extracted,
                route.provenance().to_vec(),
                model_limits,
            )?;
            if let Some(reason) = insert_unique_link_bounded(
                &mut edges,
                &mut ambiguous_link_ids,
                &mut nodes,
                link,
                correlation_limits,
            ) {
                return bounded_result(&mut diagnostics, reason, correlation_limits);
            }
            source = callback.clone();
        }
    }

    for value in values.values() {
        if ambiguous_semantic_ids.contains(value.value_id().as_str()) {
            continue;
        }
        if let Some(actor_id) = value.source_actor() {
            if actors.contains_key(actor_id.as_str())
                && !ambiguous_semantic_ids.contains(actor_id.as_str())
            {
                if let Some(reason) = insert_intrinsic_link_bounded(
                    &mut edges,
                    &mut ambiguous_link_ids,
                    &mut nodes,
                    "r3-path-actor-value",
                    actor_id,
                    value.value_id(),
                    ACTOR_VALUE_RELATION,
                    value.provenance().to_vec(),
                    model_limits,
                    correlation_limits,
                )? {
                    return bounded_result(&mut diagnostics, reason, correlation_limits);
                }
            } else {
                partial_reference_ids.insert(value.value_id().as_str().to_owned());
                push_diagnostic(
                    &mut diagnostics,
                    PathCorrelationDiagnosticReason::DanglingActorReference,
                    None,
                    None,
                    value.provenance().to_vec(),
                    correlation_limits,
                )?;
            }
        }
        for input in value.derivation_inputs() {
            if values.contains_key(input.as_str())
                && !ambiguous_semantic_ids.contains(input.as_str())
            {
                if let Some(reason) = insert_intrinsic_link_bounded(
                    &mut edges,
                    &mut ambiguous_link_ids,
                    &mut nodes,
                    "r3-path-value-derivation",
                    input,
                    value.value_id(),
                    VALUE_DERIVATION_RELATION,
                    value.provenance().to_vec(),
                    model_limits,
                    correlation_limits,
                )? {
                    return bounded_result(&mut diagnostics, reason, correlation_limits);
                }
            } else {
                partial_reference_ids.insert(value.value_id().as_str().to_owned());
                push_diagnostic(
                    &mut diagnostics,
                    PathCorrelationDiagnosticReason::DanglingValueReference,
                    None,
                    None,
                    value.provenance().to_vec(),
                    correlation_limits,
                )?;
            }
        }
    }

    for guard in guards.values() {
        if ambiguous_semantic_ids.contains(guard.guard_id().as_str()) {
            continue;
        }
        if let Some(actor_id) = guard.subject_actor() {
            if actors.contains_key(actor_id.as_str())
                && !ambiguous_semantic_ids.contains(actor_id.as_str())
            {
                if let Some(reason) = insert_intrinsic_link_bounded(
                    &mut edges,
                    &mut ambiguous_link_ids,
                    &mut nodes,
                    "r3-path-actor-guard",
                    actor_id,
                    guard.guard_id(),
                    ACTOR_GUARD_RELATION,
                    guard.provenance().to_vec(),
                    model_limits,
                    correlation_limits,
                )? {
                    return bounded_result(&mut diagnostics, reason, correlation_limits);
                }
            } else {
                partial_reference_ids.insert(guard.guard_id().as_str().to_owned());
                push_diagnostic(
                    &mut diagnostics,
                    PathCorrelationDiagnosticReason::DanglingActorReference,
                    None,
                    None,
                    guard.provenance().to_vec(),
                    correlation_limits,
                )?;
            }
        }
    }

    let mut provider_link_ids = BTreeMap::<String, String>::new();
    let mut partial_operation_ids = BTreeSet::new();
    for operation in operations.values() {
        if ambiguous_semantic_ids.contains(operation.operation_id().as_str()) {
            continue;
        }
        for filter in operation.filters() {
            if values.contains_key(filter.value_origin().as_str())
                && !ambiguous_semantic_ids.contains(filter.value_origin().as_str())
            {
                if let Some(reason) = insert_intrinsic_link_bounded(
                    &mut edges,
                    &mut ambiguous_link_ids,
                    &mut nodes,
                    "r3-path-value-filter",
                    filter.value_origin(),
                    operation.operation_id(),
                    VALUE_FILTER_RELATION,
                    vec![filter.provenance().clone()],
                    model_limits,
                    correlation_limits,
                )? {
                    return bounded_result(&mut diagnostics, reason, correlation_limits);
                }
            } else {
                partial_operation_ids.insert(operation.operation_id().as_str().to_owned());
                push_diagnostic(
                    &mut diagnostics,
                    PathCorrelationDiagnosticReason::DanglingValueReference,
                    None,
                    Some(operation.operation_id()),
                    vec![filter.provenance().clone()],
                    correlation_limits,
                )?;
            }
        }
        for field_set in [operation.read_fields(), operation.mutation_fields()]
            .into_iter()
            .flatten()
        {
            for (_, value_id) in field_set.value_origins() {
                if values.contains_key(value_id.as_str())
                    && !ambiguous_semantic_ids.contains(value_id.as_str())
                {
                    if let Some(reason) = insert_intrinsic_link_bounded(
                        &mut edges,
                        &mut ambiguous_link_ids,
                        &mut nodes,
                        "r3-path-value-field",
                        value_id,
                        operation.operation_id(),
                        VALUE_FIELD_RELATION,
                        vec![field_set.provenance().clone()],
                        model_limits,
                        correlation_limits,
                    )? {
                        return bounded_result(&mut diagnostics, reason, correlation_limits);
                    }
                } else {
                    partial_operation_ids.insert(operation.operation_id().as_str().to_owned());
                    push_diagnostic(
                        &mut diagnostics,
                        PathCorrelationDiagnosticReason::DanglingValueReference,
                        None,
                        Some(operation.operation_id()),
                        vec![field_set.provenance().clone()],
                        correlation_limits,
                    )?;
                }
            }
        }
        if let Some(handler) = operation.handler_symbol() {
            if let Some(reason) = insert_intrinsic_link_bounded(
                &mut edges,
                &mut ambiguous_link_ids,
                &mut nodes,
                "r3-path-handler-operation",
                handler,
                operation.operation_id(),
                HANDLER_OPERATION_RELATION,
                operation.provenance().to_vec(),
                model_limits,
                correlation_limits,
            )? {
                return bounded_result(&mut diagnostics, reason, correlation_limits);
            }
        }
        if let Some(client_id) = operation.provider_client() {
            if clients.contains_key(client_id.as_str())
                && !ambiguous_semantic_ids.contains(client_id.as_str())
            {
                let link = intrinsic_link(
                    "r3-path-operation-client",
                    operation.operation_id(),
                    client_id,
                    OPERATION_CLIENT_RELATION,
                    operation.provenance().to_vec(),
                    model_limits,
                )?;
                let link_id = link.link_id().as_str().to_owned();
                if let Some(reason) = insert_unique_link_bounded(
                    &mut edges,
                    &mut ambiguous_link_ids,
                    &mut nodes,
                    link,
                    correlation_limits,
                ) {
                    return bounded_result(&mut diagnostics, reason, correlation_limits);
                }
                provider_link_ids.insert(operation.operation_id().as_str().to_owned(), link_id);
            } else {
                partial_operation_ids.insert(operation.operation_id().as_str().to_owned());
                push_diagnostic(
                    &mut diagnostics,
                    PathCorrelationDiagnosticReason::DanglingProviderClientReference,
                    None,
                    Some(operation.operation_id()),
                    operation.provenance().to_vec(),
                    correlation_limits,
                )?;
            }
        }
    }

    for id in &ambiguous_link_ids {
        edges.remove(id);
        push_diagnostic(
            &mut diagnostics,
            PathCorrelationDiagnosticReason::AmbiguousLinkIdentity,
            None,
            None,
            Vec::new(),
            correlation_limits,
        )?;
    }

    let mut partial_ids = BTreeSet::new();
    for actor in actors.values() {
        if actor.identity_kind() == ActorIdentityKind::Unknown
            || actor.trust_basis() == TrustBasis::Unknown
        {
            partial_ids.insert(actor.actor_id().as_str().to_owned());
        }
    }
    for guard in guards.values() {
        if guard.dominance_scope() == DominanceScope::Unknown
            || guard.comparison_shape() == ComparisonShape::Unknown
        {
            partial_ids.insert(guard.guard_id().as_str().to_owned());
        }
    }
    for value in values.values() {
        if value.origin_kind() == ValueOriginKind::Unknown {
            partial_ids.insert(value.value_id().as_str().to_owned());
        }
    }
    for client in clients.values() {
        if client.authority_class() == ProviderAuthorityClass::Unknown {
            partial_ids.insert(client.client_id().as_str().to_owned());
        }
    }
    partial_ids.extend(partial_operation_ids);
    partial_ids.extend(partial_reference_ids);

    let mut adjacency = BTreeMap::<String, Vec<CrossLayerLink>>::new();
    for link in edges.values() {
        if ambiguous_semantic_ids.contains(link.source_semantic_id().as_str())
            || ambiguous_semantic_ids.contains(link.target_semantic_id().as_str())
        {
            continue;
        }
        adjacency
            .entry(link.source_semantic_id().as_str().to_owned())
            .or_default()
            .push(link.clone());
    }
    for outgoing in adjacency.values_mut() {
        outgoing.sort_by(|left, right| left.link_id().cmp(right.link_id()));
    }

    let mut paths = BTreeMap::<String, CrossLayerPath>::new();
    let mut reached_operations = BTreeSet::new();
    let mut routes_with_path = BTreeSet::new();
    let mut candidate_paths_seen = 0usize;
    let mut work_items_seen = 0usize;

    for route in routes.values() {
        if ambiguous_semantic_ids.contains(route.route_id().as_str()) {
            continue;
        }
        if route.coverage_state() != &CoverageState::Covered {
            partial_ids.insert(route.route_id().as_str().to_owned());
            push_diagnostic(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::IncompleteRouteObservation,
                Some(route.route_id()),
                None,
                route.provenance().to_vec(),
                correlation_limits,
            )?;
        }

        let mut visited = BTreeSet::new();
        visited.insert(route.route_id().as_str().to_owned());
        let mut queue = VecDeque::from([QueueItem {
            node_id: route.route_id().as_str().to_owned(),
            ordered_links: Vec::new(),
            visited,
        }]);
        let mut route_hit = false;

        while let Some(item) = queue.pop_front() {
            work_items_seen = work_items_seen.saturating_add(1);
            if work_items_seen > correlation_limits.max_work_items {
                push_diagnostic(
                    &mut diagnostics,
                    PathCorrelationDiagnosticReason::TraversalWorkLimitExceeded,
                    Some(route.route_id()),
                    None,
                    route.provenance().to_vec(),
                    correlation_limits,
                )?;
                return Ok(partial_result(Vec::new(), diagnostics));
            }

            if let Some(operation) = operations.get(item.node_id.as_str()) {
                if item.ordered_links.is_empty() {
                    continue;
                }

                let mut ordered_links = item.ordered_links.clone();
                if let Some(provider_link_id) =
                    provider_link_ids.get(operation.operation_id().as_str())
                    && let Some(provider_link) = edges.get(provider_link_id)
                {
                    if ordered_links.len() >= correlation_limits.max_depth {
                        push_diagnostic(
                            &mut diagnostics,
                            PathCorrelationDiagnosticReason::DepthLimitExceeded,
                            Some(route.route_id()),
                            Some(operation.operation_id()),
                            route.provenance().to_vec(),
                            correlation_limits,
                        )?;
                        return Ok(partial_result(Vec::new(), diagnostics));
                    }
                    ordered_links.push(provider_link.clone());
                }

                candidate_paths_seen = candidate_paths_seen.saturating_add(1);
                if candidate_paths_seen > correlation_limits.max_candidate_paths {
                    push_diagnostic(
                        &mut diagnostics,
                        PathCorrelationDiagnosticReason::CandidatePathLimitExceeded,
                        Some(route.route_id()),
                        Some(operation.operation_id()),
                        route.provenance().to_vec(),
                        correlation_limits,
                    )?;
                    return Ok(partial_result(Vec::new(), diagnostics));
                }

                let path = build_path(
                    route,
                    operation,
                    &ordered_links,
                    &item.visited,
                    &actors,
                    &guards,
                    &values,
                    &clients,
                    &partial_ids,
                    model_limits,
                )?;
                reached_operations.insert(operation.operation_id().as_str().to_owned());
                routes_with_path.insert(route.route_id().as_str().to_owned());
                route_hit = true;
                paths.insert(path.path_id().as_str().to_owned(), path);
                continue;
            }

            if item.ordered_links.len() >= correlation_limits.max_depth {
                if adjacency.contains_key(&item.node_id) {
                    push_diagnostic(
                        &mut diagnostics,
                        PathCorrelationDiagnosticReason::DepthLimitExceeded,
                        Some(route.route_id()),
                        None,
                        route.provenance().to_vec(),
                        correlation_limits,
                    )?;
                    return Ok(partial_result(Vec::new(), diagnostics));
                }
                continue;
            }

            let Some(outgoing) = adjacency.get(&item.node_id) else {
                continue;
            };
            for link in outgoing {
                let target = link.target_semantic_id().as_str();
                if item.visited.contains(target) {
                    continue;
                }
                if queue.len() >= correlation_limits.max_frontier {
                    push_diagnostic(
                        &mut diagnostics,
                        PathCorrelationDiagnosticReason::FrontierLimitExceeded,
                        Some(route.route_id()),
                        None,
                        route.provenance().to_vec(),
                        correlation_limits,
                    )?;
                    return Ok(partial_result(Vec::new(), diagnostics));
                }
                let mut visited = item.visited.clone();
                visited.insert(target.to_owned());
                let mut ordered_links = item.ordered_links.clone();
                ordered_links.push(link.clone());
                queue.push_back(QueueItem {
                    node_id: target.to_owned(),
                    ordered_links,
                    visited,
                });
            }
        }

        if !route_hit {
            push_diagnostic(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::MissingRouteDataPath,
                Some(route.route_id()),
                None,
                route.provenance().to_vec(),
                correlation_limits,
            )?;
        }
    }

    for operation in operations.values() {
        if ambiguous_semantic_ids.contains(operation.operation_id().as_str()) {
            continue;
        }
        if operation.coverage_state() != &CoverageState::Covered {
            push_diagnostic(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::IncompleteDataOperation,
                None,
                Some(operation.operation_id()),
                operation.provenance().to_vec(),
                correlation_limits,
            )?;
        }
        if !reached_operations.contains(operation.operation_id().as_str()) {
            push_diagnostic(
                &mut diagnostics,
                PathCorrelationDiagnosticReason::UncorrelatedDataOperation,
                None,
                Some(operation.operation_id()),
                operation.provenance().to_vec(),
                correlation_limits,
            )?;
        }
    }

    let paths = paths.into_values().collect::<Vec<_>>();
    let complete = !paths.is_empty()
        && diagnostics.is_empty()
        && paths
            .iter()
            .all(|path| path.path_state() == PathState::Supported)
        && routes_with_path.len() == routes.len()
        && reached_operations.len() == operations.len();

    Ok(PathCorrelationResult {
        paths,
        diagnostics: diagnostics.into_values().collect(),
        coverage_state: if complete {
            CoverageState::Covered
        } else {
            CoverageState::Partial
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn build_path(
    route: &RouteObservation,
    operation: &DataOperation,
    ordered_links: &[CrossLayerLink],
    visited: &BTreeSet<String>,
    actors: &BTreeMap<String, &ActorContext>,
    guards: &BTreeMap<String, &GuardObservation>,
    values: &BTreeMap<String, &ValueOrigin>,
    clients: &BTreeMap<String, &ProviderClientAuthority>,
    partial_ids: &BTreeSet<String>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerPath, PathCorrelationError> {
    let mut actor_ids = Vec::new();
    let mut guard_ids = Vec::new();
    let mut provenance = BTreeSet::new();
    provenance.extend(route.provenance().iter().cloned());
    provenance.extend(operation.provenance().iter().cloned());

    let mut partial = route.coverage_state() != &CoverageState::Covered
        || operation.coverage_state() != &CoverageState::Covered
        || partial_ids.contains(route.route_id().as_str())
        || partial_ids.contains(operation.operation_id().as_str());
    let mut ambiguous = false;

    for node in visited {
        if let Some(actor) = actors.get(node) {
            actor_ids.push(actor.actor_id().clone());
            provenance.extend(actor.provenance().iter().cloned());
            partial |= partial_ids.contains(node);
        }
        if let Some(guard) = guards.get(node) {
            guard_ids.push(guard.guard_id().clone());
            provenance.extend(guard.provenance().iter().cloned());
            partial |= partial_ids.contains(node);
        }
        if let Some(value) = values.get(node) {
            provenance.extend(value.provenance().iter().cloned());
            partial |= partial_ids.contains(node);
        }
    }

    for link in ordered_links {
        provenance.extend(link.provenance().iter().cloned());
        match (link.basis(), link.confidence_basis()) {
            (LinkBasis::Unknown, _) | (_, ConfidenceBasis::Ambiguous) => ambiguous = true,
            (_, ConfidenceBasis::Inferred) => partial = true,
            _ => {}
        }
    }

    let provider_client_id = operation.provider_client().cloned();
    if let Some(client_id) = provider_client_id.as_ref() {
        if let Some(client) = clients.get(client_id.as_str()) {
            provenance.extend(client.provenance().iter().cloned());
            partial |= partial_ids.contains(client_id.as_str());
        } else {
            partial = true;
        }
    }

    if provenance.len() > limits.max_provenance_per_record {
        return Err(PathCorrelationError::Model(ModelError::TooManyProvenance {
            count: provenance.len(),
            max: limits.max_provenance_per_record,
        }));
    }

    let mut identity_parts = Vec::with_capacity(ordered_links.len().saturating_add(3));
    identity_parts.push(format!("route:{}", route.route_id().as_str()));
    for link in ordered_links {
        identity_parts.push(format!(
            "link:{}:{}:{}",
            link.link_id().as_str(),
            link_basis_key(link.basis()),
            confidence_basis_key(link.confidence_basis())
        ));
    }
    identity_parts.push(format!("operation:{}", operation.operation_id().as_str()));
    if let Some(client_id) = provider_client_id.as_ref() {
        identity_parts.push(format!("client:{}", client_id.as_str()));
    }
    let identity_refs = identity_parts
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let path_id = StableSemanticId::from_parts("r3-cross-layer-path", &identity_refs, limits)?;

    Ok(CrossLayerPath::new(
        path_id,
        route.route_id().clone(),
        actor_ids,
        guard_ids,
        operation.operation_id().clone(),
        provider_client_id,
        ordered_links.to_vec(),
        Vec::new(),
        if ambiguous {
            PathState::Ambiguous
        } else if partial {
            PathState::Partial
        } else {
            PathState::Supported
        },
        provenance.into_iter().collect(),
        limits,
    )?)
}

#[allow(clippy::too_many_arguments)]
fn insert_intrinsic_link_bounded(
    edges: &mut BTreeMap<String, CrossLayerLink>,
    ambiguous: &mut BTreeSet<String>,
    nodes: &mut BTreeSet<String>,
    namespace: &str,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
    provenance: Vec<SourceLocation>,
    model_limits: BusinessLogicLimits,
    correlation_limits: PathCorrelationLimits,
) -> Result<Option<PathCorrelationDiagnosticReason>, PathCorrelationError> {
    let link = intrinsic_link(
        namespace,
        source,
        target,
        relation,
        provenance,
        model_limits,
    )?;
    Ok(insert_unique_link_bounded(
        edges,
        ambiguous,
        nodes,
        link,
        correlation_limits,
    ))
}

fn intrinsic_link(
    namespace: &str,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
    provenance: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerLink, PathCorrelationError> {
    Ok(CrossLayerLink::new(
        StableSemanticId::from_parts(
            namespace,
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

fn insert_unique_link_bounded(
    edges: &mut BTreeMap<String, CrossLayerLink>,
    ambiguous: &mut BTreeSet<String>,
    nodes: &mut BTreeSet<String>,
    link: CrossLayerLink,
    limits: PathCorrelationLimits,
) -> Option<PathCorrelationDiagnosticReason> {
    let key = link.link_id().as_str().to_owned();
    if ambiguous.contains(&key) {
        return None;
    }
    if let Some(existing) = edges.get(&key) {
        if existing != &link {
            edges.remove(&key);
            ambiguous.insert(key);
        }
        return None;
    }
    if edges.len() >= limits.max_edges {
        return Some(PathCorrelationDiagnosticReason::EdgeLimitExceeded);
    }
    for endpoint in [link.source_semantic_id(), link.target_semantic_id()] {
        if !admit_node(nodes, endpoint, limits.max_nodes) {
            return Some(PathCorrelationDiagnosticReason::NodeLimitExceeded);
        }
    }
    edges.insert(key, link);
    None
}

fn admit_node(nodes: &mut BTreeSet<String>, id: &StableSemanticId, max: usize) -> bool {
    if nodes.contains(id.as_str()) {
        return true;
    }
    if nodes.len() >= max {
        return false;
    }
    nodes.insert(id.as_str().to_owned());
    true
}

fn insert_unique_record<'a, T: Eq>(
    records: &mut BTreeMap<String, &'a T>,
    ambiguous: &mut BTreeSet<String>,
    id: &str,
    value: &'a T,
) {
    if ambiguous.contains(id) {
        return;
    }
    if let Some(existing) = records.get(id) {
        if *existing != value {
            records.remove(id);
            ambiguous.insert(id.to_owned());
        }
        return;
    }
    records.insert(id.to_owned(), value);
}

fn register_semantic_kind(
    kinds: &mut BTreeMap<String, &'static str>,
    ambiguous: &mut BTreeSet<String>,
    id: &str,
    kind: &'static str,
) {
    if ambiguous.contains(id) {
        return;
    }
    if let Some(existing) = kinds.get(id) {
        if *existing != kind {
            ambiguous.insert(id.to_owned());
        }
        return;
    }
    kinds.insert(id.to_owned(), kind);
}

fn bounded_result(
    diagnostics: &mut BTreeMap<
        (
            PathCorrelationDiagnosticReason,
            Option<String>,
            Option<String>,
        ),
        PathCorrelationDiagnostic,
    >,
    reason: PathCorrelationDiagnosticReason,
    limits: PathCorrelationLimits,
) -> Result<PathCorrelationResult, PathCorrelationError> {
    push_diagnostic(diagnostics, reason, None, None, Vec::new(), limits)?;
    Ok(partial_result(Vec::new(), std::mem::take(diagnostics)))
}

fn push_diagnostic(
    diagnostics: &mut BTreeMap<
        (
            PathCorrelationDiagnosticReason,
            Option<String>,
            Option<String>,
        ),
        PathCorrelationDiagnostic,
    >,
    reason: PathCorrelationDiagnosticReason,
    route_id: Option<&StableSemanticId>,
    operation_id: Option<&StableSemanticId>,
    mut provenance: Vec<SourceLocation>,
    limits: PathCorrelationLimits,
) -> Result<(), PathCorrelationError> {
    provenance.sort();
    provenance.dedup();
    let key = (
        reason,
        route_id.map(|id| id.as_str().to_owned()),
        operation_id.map(|id| id.as_str().to_owned()),
    );
    if diagnostics.contains_key(&key) {
        return Ok(());
    }
    if diagnostics.len() >= limits.max_diagnostics {
        return Err(PathCorrelationError::TooManyDiagnostics {
            count: diagnostics.len().saturating_add(1),
            max: limits.max_diagnostics,
        });
    }
    diagnostics.insert(
        key,
        PathCorrelationDiagnostic {
            reason,
            route_id: route_id.cloned(),
            data_operation_id: operation_id.cloned(),
            provenance,
        },
    );
    Ok(())
}

fn partial_result(
    paths: Vec<CrossLayerPath>,
    diagnostics: BTreeMap<
        (
            PathCorrelationDiagnosticReason,
            Option<String>,
            Option<String>,
        ),
        PathCorrelationDiagnostic,
    >,
) -> PathCorrelationResult {
    PathCorrelationResult {
        paths,
        diagnostics: diagnostics.into_values().collect(),
        coverage_state: CoverageState::Partial,
    }
}

const fn link_basis_key(value: LinkBasis) -> &'static str {
    match value {
        LinkBasis::SameHandlerStructural => "same-handler-structural",
        LinkBasis::SupportedCallbackChain => "supported-callback-chain",
        LinkBasis::SupportedImportBinding => "supported-import-binding",
        LinkBasis::ScipReference => "scip-reference",
        LinkBasis::ExplicitAdapterLink => "explicit-adapter-link",
        LinkBasis::Unknown => "unknown",
    }
}

const fn confidence_basis_key(value: ConfidenceBasis) -> &'static str {
    match value {
        ConfidenceBasis::Extracted => "extracted",
        ConfidenceBasis::Inferred => "inferred",
        ConfidenceBasis::Ambiguous => "ambiguous",
    }
}
