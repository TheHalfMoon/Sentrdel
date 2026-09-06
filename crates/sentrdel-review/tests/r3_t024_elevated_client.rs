#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sentrdel_review::{
    business_logic::{
        elevated_client::{
            ElevatedClientError, ElevatedClientInputs,
            R3_ELEVATED_CLIENT_CREATES_FINDINGS, R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE,
            R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS,
            R3_ELEVATED_CLIENT_PROVES_LIVE_PROVIDER_POSTURE,
            R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION,
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
            R3_ELEVATED_CLIENT_TREATS_ELEVATED_AUTHORITY_AS_AUTOMATIC_VIOLATION,
            R3_SERVER_CONTEXT_EXPRESS, evaluate_elevated_client,
        },
        model::{
            BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink, CrossLayerPath,
            DataOperation, DataOperationKind, DominanceScope, FrameworkFamily, GuardKind,
            GuardObservation, HttpMethod, InvariantDefinition, InvariantEvaluationState,
            InvariantKind, InvariantRequirement, InvariantScope, InvariantSource, LinkBasis,
            PathState, ProviderAuthorityClass, ProviderClientAuthority, ResourceKind, ResourceRef,
            RouteObservation, SourceLocation, StableSemanticId,
        },
        r2_support::{R2SupportCorrelation, R2SupportLimits, correlate_supabase_r2_support},
    },
    supabase_integration::SupabaseR2ProviderOutput,
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::{
    SCHEMA_V1,
    coverage::CoverageState,
    evidence::{
        EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, ProducerKind,
    },
};

const CAPTURED_AT: &str = "2026-09-06T14:00:00Z";

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn repo_path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path")
}

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        repo_path("src/r3-t024.ts"),
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

fn route(framework: FrameworkFamily, coverage: CoverageState) -> RouteObservation {
    RouteObservation::new(
        id("r3.t024.route", "accounts"),
        framework,
        HttpMethod::Delete,
        "/accounts/:id",
        Some("deleteAccount".to_owned()),
        Vec::new(),
        vec![location(0)],
        coverage,
        limits(),
    )
    .expect("route")
}

fn client(
    authority: ProviderAuthorityClass,
    evidence_ids: Vec<String>,
    identity: &str,
) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        id("r3.t024.client", identity),
        "supabase",
        authority,
        evidence_ids,
        vec![location(20)],
        limits(),
    )
    .expect("provider client")
}

fn operation(client: &ProviderClientAuthority, coverage: CoverageState) -> DataOperation {
    DataOperation::new(
        id("r3.t024.operation", "delete-account"),
        DataOperationKind::Delete,
        resource(),
        Some(client.client_id().clone()),
        Vec::new(),
        None,
        None,
        None,
        Some(id("r3.t024.handler", "delete-account")),
        vec![location(40)],
        coverage,
        limits(),
    )
    .expect("operation")
}

fn guard(
    kind: GuardKind,
    comparison: ComparisonShape,
    dominance: DominanceScope,
) -> GuardObservation {
    let required_values = match kind {
        GuardKind::RequiredRole => vec!["admin".to_owned()],
        GuardKind::TenantBinding | GuardKind::OwnershipBinding | GuardKind::ObjectMembership => {
            vec!["tenant_id".to_owned()]
        }
        _ => Vec::new(),
    };
    GuardObservation::new(
        id("r3.t024.guard", &format!("{kind:?}")),
        kind,
        None,
        Some(resource()),
        required_values,
        comparison,
        dominance,
        vec![location(60)],
        limits(),
    )
    .expect("guard")
}

fn link(
    namespace: &str,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
) -> CrossLayerLink {
    CrossLayerLink::new(
        id(namespace, relation),
        source.clone(),
        target.clone(),
        relation,
        basis,
        confidence,
        vec![location(80)],
        limits(),
    )
    .expect("cross-layer link")
}

fn guarded_path(
    route: &RouteObservation,
    operation: &DataOperation,
    client: &ProviderClientAuthority,
    guard: &GuardObservation,
    path_state: PathState,
    basis: LinkBasis,
    confidence: ConfidenceBasis,
) -> CrossLayerPath {
    CrossLayerPath::new(
        id("r3.t024.path", "guarded"),
        route.route_id().clone(),
        Vec::new(),
        vec![guard.guard_id().clone()],
        operation.operation_id().clone(),
        Some(client.client_id().clone()),
        vec![
            link(
                "r3.t024.link.route-guard",
                route.route_id(),
                guard.guard_id(),
                R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
                basis,
                confidence,
            ),
            link(
                "r3.t024.link.guard-operation",
                guard.guard_id(),
                operation.operation_id(),
                R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
                basis,
                confidence,
            ),
        ],
        Vec::new(),
        path_state,
        vec![location(100)],
        limits(),
    )
    .expect("path")
}

fn unguarded_path(
    route: &RouteObservation,
    operation: &DataOperation,
    client: &ProviderClientAuthority,
) -> CrossLayerPath {
    CrossLayerPath::new(
        id("r3.t024.path", "unguarded"),
        route.route_id().clone(),
        Vec::new(),
        Vec::new(),
        operation.operation_id().clone(),
        Some(client.client_id().clone()),
        vec![link(
            "r3.t024.link.route-operation",
            route.route_id(),
            operation.operation_id(),
            "supported_route_operation",
            LinkBasis::ExplicitAdapterLink,
            ConfidenceBasis::Extracted,
        )],
        Vec::new(),
        PathState::Supported,
        vec![location(100)],
        limits(),
    )
    .expect("path")
}

fn invariant(contexts: &[&str], required_guard_kinds: Vec<GuardKind>) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "elevated-client-context"),
        InvariantKind::ElevatedClientContext,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/accounts/:id".to_owned()),
            vec![HttpMethod::Delete],
            Some(resource()),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("scope"),
        InvariantRequirement::ElevatedClientContext {
            allowed_server_contexts: contexts.iter().map(|value| (*value).to_owned()).collect(),
            required_guard_kinds,
        },
        vec![location(120)],
        limits(),
    )
    .expect("invariant")
}

fn boundary_evidence() -> Evidence {
    let authority = EvidenceAuthority::from_runtime(
        "sentrdel.supabase.r3-t024-fixture",
        "1",
        ProducerKind::NativeRule,
    )
    .expect("fixture authority");
    authority
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:r3-t024-r2-input".to_owned()],
            observation: "repository-derived elevated key/client boundary".to_owned(),
            security_interpretation: None,
            category: "supabase_elevated_key_client_boundary".to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: Vec::new(),
            locations: vec![EvidenceLocation {
                repo_relative_path: "src/r3-t024.ts".to_owned(),
                start_line: Some(1),
                start_column: Some(1),
                end_line: Some(1),
                end_column: Some(16),
                symbol: None,
                content_digest: Some("sha256:r3-t024-r2-input".to_owned()),
            }],
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: CAPTURED_AT.to_owned(),
        })
        .expect("sealed evidence")
}

fn r2_support(client: &ProviderClientAuthority, evidence: Vec<Evidence>) -> R2SupportCorrelation {
    let provider = SupabaseR2ProviderOutput::new(evidence, Vec::new()).expect("provider output");
    correlate_supabase_r2_support(
        &provider,
        &[],
        std::slice::from_ref(client),
        R2SupportLimits::default(),
    )
    .expect("R2 support")
}

fn elevated_client_with_support() -> (ProviderClientAuthority, R2SupportCorrelation) {
    let evidence = boundary_evidence();
    let client = client(
        ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        vec![evidence.evidence_id().to_owned()],
        "elevated",
    );
    let support = r2_support(&client, vec![evidence]);
    (client, support)
}

fn evaluate(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    route: &RouteObservation,
    guards: &[GuardObservation],
    operation: &DataOperation,
    client: &ProviderClientAuthority,
    support: &R2SupportCorrelation,
    guard_coverage_state: CoverageState,
) -> InvariantEvaluationState {
    evaluate_elevated_client(
        ElevatedClientInputs {
            invariant,
            path,
            route,
            guard_coverage_state: &guard_coverage_state,
            guards,
            operation,
            client,
            r2_support: support,
        },
        limits(),
    )
    .expect("elevated-client evaluation")
    .state()
}

#[test]
fn supported_elevated_client_with_required_role_guard_is_satisfied() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let guard = guard(
        GuardKind::RequiredRole,
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
    );
    let path = guarded_path(
        &route,
        &operation,
        &client,
        &guard,
        PathState::Supported,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Satisfied
    );
}

#[test]
fn elevated_client_without_required_application_guard_is_violated() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let path = unguarded_path(&route, &operation, &client);
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &[],
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn elevated_client_outside_allowed_server_context_is_violated() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::NextApp, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let guard = guard(
        GuardKind::RequiredRole,
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
    );
    let path = guarded_path(
        &route,
        &operation,
        &client,
        &guard,
        PathState::Supported,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Violated
    );
}

#[test]
fn non_elevated_client_is_not_applicable_not_a_false_violation() {
    let evidence = boundary_evidence();
    let client = client(
        ProviderAuthorityClass::PublishableOrAnon,
        vec![evidence.evidence_id().to_owned()],
        "anon",
    );
    let support = r2_support(&client, vec![evidence]);
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let path = unguarded_path(&route, &operation, &client);
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &[],
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::NotApplicable
    );
}

#[test]
fn elevated_client_without_exact_r2_boundary_match_is_unknown() {
    let client = client(
        ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        vec!["evidence:not-present".to_owned()],
        "elevated",
    );
    let support = r2_support(&client, Vec::new());
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let path = unguarded_path(&route, &operation, &client);
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &[],
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unknown_guard_dominance_remains_unknown_not_satisfied() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let guard = guard(
        GuardKind::RequiredRole,
        ComparisonShape::Equal,
        DominanceScope::Unknown,
    );
    let path = guarded_path(
        &route,
        &operation,
        &client,
        &guard,
        PathState::Supported,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
    );
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn non_authoritative_path_link_remains_unknown_not_satisfied() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let guard = guard(
        GuardKind::RequiredRole,
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
    );
    let path = guarded_path(
        &route,
        &operation,
        &client,
        &guard,
        PathState::Supported,
        LinkBasis::SameHandlerStructural,
        ConfidenceBasis::Inferred,
    );
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            std::slice::from_ref(&guard),
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn incomplete_guard_coverage_remains_unknown() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let path = unguarded_path(&route, &operation, &client);
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &[],
            &operation,
            &client,
            &support,
            CoverageState::Partial,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn unsupported_server_context_remains_unknown() {
    let (client, support) = elevated_client_with_support();
    let route = route(FrameworkFamily::OtherSupported, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let path = unguarded_path(&route, &operation, &client);
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    assert_eq!(
        evaluate(
            &invariant,
            &path,
            &route,
            &[],
            &operation,
            &client,
            &support,
            CoverageState::Covered,
        ),
        InvariantEvaluationState::Unknown
    );
}

#[test]
fn mismatched_provider_client_identity_is_rejected() {
    let (client, support) = elevated_client_with_support();
    let other = client(
        ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        client.source_evidence_ids().to_vec(),
        "other",
    );
    let route = route(FrameworkFamily::Express, CoverageState::Covered);
    let operation = operation(&client, CoverageState::Covered);
    let path = unguarded_path(&route, &operation, &client);
    let invariant = invariant(&[R3_SERVER_CONTEXT_EXPRESS], vec![GuardKind::RequiredRole]);

    let error = evaluate_elevated_client(
        ElevatedClientInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: &[],
            operation: &operation,
            client: &other,
            r2_support: &support,
        },
        limits(),
    )
    .expect_err("mismatched provider client must be rejected");

    assert!(matches!(error, ElevatedClientError::OperationClientMismatch));
}

#[test]
fn t024_evaluator_has_no_execution_network_finding_live_or_automatic_violation_authority() {
    const { assert!(!R3_ELEVATED_CLIENT_CREATES_FINDINGS) };
    const { assert!(!R3_ELEVATED_CLIENT_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_ELEVATED_CLIENT_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_ELEVATED_CLIENT_PROVES_RUNTIME_AUTHORIZATION) };
    const { assert!(!R3_ELEVATED_CLIENT_PROVES_LIVE_PROVIDER_POSTURE) };
    const { assert!(!R3_ELEVATED_CLIENT_TREATS_ELEVATED_AUTHORITY_AS_AUTOMATIC_VIOLATION) };
}
