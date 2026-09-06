#![forbid(unsafe_code)]

use sentrdel_review::{
    business_logic::{
        elevated_client::{
            ElevatedClientError, ElevatedClientInputs,
            R3_ELEVATED_CLIENT_AUTHORITY_ALONE_IS_VIOLATION, R3_ELEVATED_CLIENT_CREATES_FINDINGS,
            R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE, R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            R3_ELEVATED_CLIENT_OPERATION_CLIENT_RELATION,
            R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS,
            R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION,
            R3_ELEVATED_CLIENT_RECEIVES_PROVIDER_CREDENTIALS,
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION, evaluate_elevated_client,
        },
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ComparisonShape,
            ConfidenceBasis, CrossLayerLink, CrossLayerPath, DataOperation, DataOperationKind,
            DominanceScope, FrameworkFamily, GuardKind, GuardObservation, HttpMethod,
            InvariantDefinition, InvariantEvaluationState, InvariantKind, InvariantRequirement,
            InvariantScope, InvariantSource, LinkBasis, PathState, ProviderAuthorityClass,
            ProviderClientAuthority, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
            StableSemanticId, TrustBasis,
        },
    },
    view::NormalizedRepoPath,
};
use sentrdel_schema::coverage::CoverageState;

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/r3-t024.ts", 4_096).expect("normalized path"),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
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

fn route(pattern: &str, coverage: CoverageState) -> RouteObservation {
    RouteObservation::new(
        id("r3.t024.route", pattern),
        FrameworkFamily::SupabaseEdge,
        HttpMethod::Delete,
        pattern,
        Some("handler".to_owned()),
        Vec::new(),
        vec![location(0)],
        coverage,
        limits(),
    )
    .expect("route")
}

fn request_actor(trust: TrustBasis) -> ActorContext {
    ActorContext::new(
        id("r3.t024.actor", "request-id"),
        ActorIdentityKind::RequestControlled,
        ActorSourceKind::RequestParam,
        "request.params.id",
        trust,
        vec![location(20)],
        limits(),
    )
    .expect("actor")
}

fn service_actor() -> ActorContext {
    ActorContext::new(
        id("r3.t024.actor", "service"),
        ActorIdentityKind::Service,
        ActorSourceKind::Constant,
        "server.worker",
        TrustBasis::DirectObservation,
        vec![location(24)],
        limits(),
    )
    .expect("service actor")
}

fn guard(kind: GuardKind, dominance: DominanceScope) -> GuardObservation {
    GuardObservation::new(
        id(
            "r3.t024.guard",
            match kind {
                GuardKind::RequiredRole => "required-role",
                GuardKind::ElevatedClientBoundary => "elevated-boundary",
                _ => "other",
            },
        ),
        kind,
        None,
        Some(resource()),
        if kind == GuardKind::RequiredRole {
            vec!["admin".to_owned()]
        } else {
            Vec::new()
        },
        if kind == GuardKind::RequiredRole {
            ComparisonShape::Equal
        } else {
            ComparisonShape::OtherSupported
        },
        dominance,
        vec![location(40)],
        limits(),
    )
    .expect("guard")
}

fn client(authority: ProviderAuthorityClass) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        id("r3.t024.client", "supabase"),
        "supabase",
        authority,
        vec!["evidence:r2-key-boundary".to_owned()],
        vec![location(60)],
        limits(),
    )
    .expect("provider client")
}

fn operation(client: Option<&ProviderClientAuthority>, coverage: CoverageState) -> DataOperation {
    DataOperation::new(
        id("r3.t024.operation", "delete-account"),
        DataOperationKind::Delete,
        resource(),
        client.map(|value| value.client_id().clone()),
        Vec::new(),
        None,
        None,
        None,
        None,
        vec![location(80)],
        coverage,
        limits(),
    )
    .expect("operation")
}

fn link(
    name: &str,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
) -> CrossLayerLink {
    CrossLayerLink::new(
        id("r3.t024.link", name),
        source.clone(),
        target.clone(),
        relation,
        basis,
        confidence,
        vec![location(100)],
        limits(),
    )
    .expect("link")
}

fn path(
    route: &RouteObservation,
    actors: &[ActorContext],
    guards: &[GuardObservation],
    operation: &DataOperation,
    client: Option<&ProviderClientAuthority>,
    authoritative_guards: bool,
    request_link_confidence: ConfidenceBasis,
) -> CrossLayerPath {
    let mut links = Vec::new();
    for actor in actors {
        links.push(link(
            "route-request",
            route.route_id(),
            actor.actor_id(),
            "route_receives_actor",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ));
        links.push(link(
            "request-operation",
            actor.actor_id(),
            operation.operation_id(),
            "request_actor_feeds_operation",
            LinkBasis::ExplicitAdapterLink,
            request_link_confidence,
        ));
    }
    for guard in guards {
        links.push(link(
            "route-guard",
            route.route_id(),
            guard.guard_id(),
            if authoritative_guards {
                R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION
            } else {
                "unrelated_route_guard"
            },
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ));
        links.push(link(
            "guard-operation",
            guard.guard_id(),
            operation.operation_id(),
            if authoritative_guards {
                R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION
            } else {
                "unrelated_guard_operation"
            },
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ));
    }
    if let Some(client) = client {
        links.push(link(
            "operation-client",
            operation.operation_id(),
            client.client_id(),
            R3_ELEVATED_CLIENT_OPERATION_CLIENT_RELATION,
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        ));
    }

    CrossLayerPath::new(
        id("r3.t024.path", "delete-account"),
        route.route_id().clone(),
        actors
            .iter()
            .map(|actor| actor.actor_id().clone())
            .collect(),
        guards
            .iter()
            .map(|guard| guard.guard_id().clone())
            .collect(),
        operation.operation_id().clone(),
        client.map(|value| value.client_id().clone()),
        links,
        Vec::new(),
        PathState::Supported,
        vec![location(120)],
        limits(),
    )
    .expect("path")
}

fn invariant(
    pattern: &str,
    allowed_contexts: &[&str],
    guards: &[GuardKind],
) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "elevated-client-context"),
        InvariantKind::ElevatedClientContext,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some(pattern.to_owned()),
            vec![HttpMethod::Delete],
            Some(resource()),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::ElevatedClientContext {
            allowed_server_contexts: allowed_contexts
                .iter()
                .map(|context| (*context).to_owned())
                .collect(),
            required_guard_kinds: guards.to_vec(),
        },
        vec![location(140)],
        limits(),
    )
    .expect("invariant")
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    route: &RouteObservation,
    actor_coverage: &CoverageState,
    guard_coverage: &CoverageState,
    actors: &[ActorContext],
    guards: &[GuardObservation],
    clients: &[ProviderClientAuthority],
    operation: &DataOperation,
) -> InvariantEvaluationState {
    evaluate_elevated_client(
        ElevatedClientInputs {
            invariant,
            path,
            route,
            actor_coverage_state: actor_coverage,
            guard_coverage_state: guard_coverage,
            actors,
            guards,
            provider_clients: clients,
            operation,
        },
        limits(),
    )
    .expect("elevated-client evaluation")
    .state()
}

#[test]
fn request_controlled_elevated_operation_with_required_guard_is_satisfied() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let guard = guard(GuardKind::RequiredRole, DominanceScope::SameHandlerPrefix);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        std::slice::from_ref(&guard),
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[guard],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Satisfied
    );
}

#[test]
fn request_controlled_elevated_operation_without_required_guard_is_violated() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn elevated_authority_without_request_controlled_data_path_is_not_a_violation() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = service_actor();
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn non_elevated_client_is_not_applicable_even_on_request_path() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::UserScoped);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn unknown_client_authority_remains_unknown() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::Unknown);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unmodeled_allowlisted_server_context_cannot_prove_safety() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let guard = guard(GuardKind::RequiredRole, DominanceScope::SameHandlerPrefix);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        std::slice::from_ref(&guard),
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant(
        "/internal/accounts/:id",
        &["server"],
        &[GuardKind::RequiredRole],
    );

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[guard],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn non_authoritative_request_link_remains_unknown() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Ambiguous,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unlinked_guard_cannot_satisfy_elevated_boundary() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let guard = guard(GuardKind::RequiredRole, DominanceScope::SameHandlerPrefix);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        std::slice::from_ref(&guard),
        &operation,
        Some(&client),
        false,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);
    let state = evaluate(
        &invariant,
        &path,
        &route,
        &CoverageState::Covered,
        &CoverageState::Covered,
        &[actor],
        &[guard],
        &[client],
        &operation,
    );

    assert_eq!(state, InvariantEvaluationState::Unknown);
    assert_ne!(state, InvariantEvaluationState::Satisfied);
}

#[test]
fn unknown_guard_dominance_cannot_satisfy_elevated_boundary() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let guard = guard(GuardKind::ElevatedClientBoundary, DominanceScope::Unknown);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        std::slice::from_ref(&guard),
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant(
        "/internal/accounts/:id",
        &[],
        &[GuardKind::ElevatedClientBoundary],
    );

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[guard],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn partial_actor_or_guard_coverage_remains_unknown() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Partial,
            &CoverageState::Covered,
            &[actor.clone()],
            &[],
            &[client.clone()],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Partial,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn scope_mismatch_is_not_applicable() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/different/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[client],
            &operation,
        ),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn unresolved_provider_client_reference_remains_unknown() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let actor = request_actor(TrustBasis::DirectObservation);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        std::slice::from_ref(&actor),
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant("/internal/accounts/:id", &[], &[GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &CoverageState::Covered,
            &CoverageState::Covered,
            &[actor],
            &[],
            &[],
            &operation,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn wrong_invariant_kind_is_rejected() {
    let route = route("/internal/accounts/:id", CoverageState::Covered);
    let client = client(ProviderAuthorityClass::ElevatedSecretOrServiceRole);
    let operation = operation(Some(&client), CoverageState::Covered);
    let path = path(
        &route,
        &[],
        &[],
        &operation,
        Some(&client),
        true,
        ConfidenceBasis::Extracted,
    );
    let wrong = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "wrong-kind"),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(None, Vec::new(), None, Vec::new(), Vec::new(), limits())
            .expect("scope"),
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        vec![location(160)],
        limits(),
    )
    .expect("wrong invariant");

    let error = evaluate_elevated_client(
        ElevatedClientInputs {
            invariant: &wrong,
            path: &path,
            route: &route,
            actor_coverage_state: &CoverageState::Covered,
            guard_coverage_state: &CoverageState::Covered,
            actors: &[],
            guards: &[],
            provider_clients: &[client],
            operation: &operation,
        },
        limits(),
    )
    .expect_err("wrong invariant kind must fail");
    assert!(matches!(error, ElevatedClientError::InvalidInvariantKind));
}

#[test]
fn t024_authority_canaries_remain_false() {
    const { assert!(!R3_ELEVATED_CLIENT_CREATES_FINDINGS) };
    const { assert!(!R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_ELEVATED_CLIENT_RECEIVES_PROVIDER_CREDENTIALS) };
    const { assert!(!R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION) };
    const { assert!(!R3_ELEVATED_CLIENT_AUTHORITY_ALONE_IS_VIOLATION) };
}
