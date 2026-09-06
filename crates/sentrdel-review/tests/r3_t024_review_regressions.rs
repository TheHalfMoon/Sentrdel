#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sentrdel_review::{
    business_logic::{
        elevated_client::{
            ElevatedClientInputs, R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION, R3_SERVER_CONTEXT_EXPRESS,
            evaluate_elevated_client,
        },
        model::{
            BusinessLogicLimits, ComparisonShape, ConfidenceBasis, CrossLayerLink, CrossLayerPath,
            DataOperation, DataOperationKind, DominanceScope, FrameworkFamily, GuardKind,
            GuardObservation, HttpMethod, InvariantDefinition, InvariantEvaluationState,
            InvariantKind, InvariantRequirement, InvariantScope, InvariantSource, LinkBasis,
            PathState, ProviderAuthorityClass, ProviderClientAuthority, ResourceKind, ResourceRef,
            RouteObservation, SourceLocation, StableSemanticId,
        },
        path::{PathCorrelationInputs, PathCorrelationLimits, correlate_cross_layer_paths},
        r2_support::{R2SupportCorrelation, R2SupportLimits, correlate_supabase_r2_support},
        required_role::{RequiredRoleInputs, evaluate_required_role},
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

const CAPTURED_AT: &str = "2026-09-06T14:45:00Z";

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn location(start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/r3-t024-review.ts", DEFAULT_MAX_REPO_PATH_BYTES)
            .expect("normalized path"),
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

fn route() -> RouteObservation {
    RouteObservation::new(
        id("r3.t024.review.route", "delete-account"),
        FrameworkFamily::Express,
        HttpMethod::Delete,
        "/accounts/:id",
        Some("deleteAccount".to_owned()),
        Vec::new(),
        vec![location(0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("route")
}

fn client(authority: ProviderAuthorityClass, evidence_ids: Vec<String>) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        id("r3.t024.review.client", "supabase"),
        "supabase",
        authority,
        evidence_ids,
        vec![location(20)],
        limits(),
    )
    .expect("provider client")
}

fn operation(client: &ProviderClientAuthority) -> DataOperation {
    DataOperation::new(
        id("r3.t024.review.operation", "delete-account"),
        DataOperationKind::Delete,
        resource(),
        Some(client.client_id().clone()),
        Vec::new(),
        None,
        None,
        None,
        Some(id("r3.t024.review.handler", "delete-account")),
        vec![location(40)],
        CoverageState::Covered,
        limits(),
    )
    .expect("operation")
}

fn guard(kind: GuardKind, comparison: ComparisonShape) -> GuardObservation {
    let required_values = match kind {
        GuardKind::RequiredRole => vec!["admin".to_owned()],
        GuardKind::TenantBinding | GuardKind::OwnershipBinding | GuardKind::ObjectMembership => {
            vec!["tenant_id".to_owned()]
        }
        _ => Vec::new(),
    };
    GuardObservation::new(
        id("r3.t024.review.guard", &format!("{kind:?}-{comparison:?}")),
        kind,
        None,
        Some(resource()),
        required_values,
        comparison,
        DominanceScope::SameHandlerPrefix,
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
) -> CrossLayerLink {
    CrossLayerLink::new(
        id(namespace, relation),
        source.clone(),
        target.clone(),
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![location(80)],
        limits(),
    )
    .expect("link")
}

fn elevated_boundary_evidence() -> Evidence {
    EvidenceAuthority::from_runtime(
        "sentrdel.supabase.r3-t024-review-fixture",
        "1",
        ProducerKind::NativeRule,
    )
    .expect("fixture authority")
    .seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec!["sha256:r3-t024-review-input".to_owned()],
        observation: "repository-derived elevated key/client boundary".to_owned(),
        security_interpretation: None,
        category: "supabase_elevated_key_client_boundary".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: Vec::new(),
        locations: vec![EvidenceLocation {
            repo_relative_path: "src/r3-t024-review.ts".to_owned(),
            start_line: Some(1),
            start_column: Some(1),
            end_line: Some(1),
            end_column: Some(16),
            symbol: None,
            content_digest: Some("sha256:r3-t024-review-input".to_owned()),
        }],
        attributes: BTreeMap::new(),
        reproduction: None,
        captured_at: CAPTURED_AT.to_owned(),
    })
    .expect("sealed evidence")
}

fn elevated_client_with_support() -> (ProviderClientAuthority, R2SupportCorrelation) {
    let evidence = elevated_boundary_evidence();
    let client = client(
        ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        vec![evidence.evidence_id().to_owned()],
    );
    let provider = SupabaseR2ProviderOutput::new(vec![evidence], Vec::new())
        .expect("validated provider output");
    let support = correlate_supabase_r2_support(
        &provider,
        &[],
        std::slice::from_ref(&client),
        R2SupportLimits::default(),
    )
    .expect("R2 support");
    (client, support)
}

fn elevated_invariant(required_guard: GuardKind) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "elevated-client-review"),
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
            allowed_server_contexts: vec![R3_SERVER_CONTEXT_EXPRESS.to_owned()],
            required_guard_kinds: vec![required_guard],
        },
        vec![location(100)],
        limits(),
    )
    .expect("elevated-client invariant")
}

fn manual_t024_path(
    route: &RouteObservation,
    operation: &DataOperation,
    client: &ProviderClientAuthority,
    guard: &GuardObservation,
) -> CrossLayerPath {
    CrossLayerPath::new(
        id("r3.t024.review.path", &format!("{:?}", guard.guard_kind())),
        route.route_id().clone(),
        Vec::new(),
        vec![guard.guard_id().clone()],
        operation.operation_id().clone(),
        Some(client.client_id().clone()),
        vec![
            link(
                "r3.t024.review.manual.route-guard",
                route.route_id(),
                guard.guard_id(),
                R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
            ),
            link(
                "r3.t024.review.manual.guard-operation",
                guard.guard_id(),
                operation.operation_id(),
                R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            ),
        ],
        Vec::new(),
        PathState::Supported,
        vec![location(120)],
        limits(),
    )
    .expect("manual T024 path")
}

#[test]
fn unsupported_guard_kind_comparison_pairs_remain_unknown_even_with_manual_t024_links() {
    let rejected = [
        (GuardKind::RequiredRole, ComparisonShape::ExplicitAllowlist),
        (GuardKind::RequiredRole, ComparisonShape::OtherSupported),
        (GuardKind::TenantBinding, ComparisonShape::ExplicitAllowlist),
        (
            GuardKind::OwnershipBinding,
            ComparisonShape::ExplicitAllowlist,
        ),
        (
            GuardKind::ObjectMembership,
            ComparisonShape::ExplicitAllowlist,
        ),
        (GuardKind::ElevatedClientBoundary, ComparisonShape::Equal),
        (
            GuardKind::ElevatedClientBoundary,
            ComparisonShape::Membership,
        ),
        (
            GuardKind::ElevatedClientBoundary,
            ComparisonShape::ConjunctionSupported,
        ),
        (
            GuardKind::ElevatedClientBoundary,
            ComparisonShape::ExplicitAllowlist,
        ),
    ];

    for (kind, comparison) in rejected {
        let (client, support) = elevated_client_with_support();
        let route = route();
        let operation = operation(&client);
        let guard = guard(kind, comparison);
        let path = manual_t024_path(&route, &operation, &client, &guard);
        let invariant = elevated_invariant(kind);

        let result = evaluate_elevated_client(
            ElevatedClientInputs {
                invariant: &invariant,
                path: &path,
                route: &route,
                guard_coverage_state: &CoverageState::Covered,
                guards: std::slice::from_ref(&guard),
                operation: &operation,
                client: &client,
                r2_support: &support,
            },
            limits(),
        )
        .expect("evaluation");

        assert_eq!(
            result.state(),
            InvariantEvaluationState::Unknown,
            "unsupported {kind:?}/{comparison:?} must not satisfy T024"
        );
    }
}

fn raw_correlation_links(
    route: &RouteObservation,
    guard: &GuardObservation,
    operation: &DataOperation,
) -> Vec<CrossLayerLink> {
    vec![
        link(
            "r3.t024.review.raw.route-guard",
            route.route_id(),
            guard.guard_id(),
            "supported_route_guard",
        ),
        link(
            "r3.t024.review.raw.guard-operation",
            guard.guard_id(),
            operation.operation_id(),
            "supported_guard_operation",
        ),
    ]
}

fn correlate_path(
    route: &RouteObservation,
    guard: &GuardObservation,
    operation: &DataOperation,
    client: &ProviderClientAuthority,
    links: &[CrossLayerLink],
) -> CrossLayerPath {
    correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: std::slice::from_ref(route),
            actors: &[],
            guards: std::slice::from_ref(guard),
            values: &[],
            data_operations: std::slice::from_ref(operation),
            provider_clients: std::slice::from_ref(client),
            links,
        },
        limits(),
        PathCorrelationLimits::default(),
    )
    .expect("correlation")
    .paths()
    .first()
    .expect("correlated path")
    .clone()
}

fn required_role_invariant() -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "required-role-t024-compat"),
        InvariantKind::RequiredRole,
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
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        vec![location(140)],
        limits(),
    )
    .expect("required-role invariant")
}

#[test]
fn t024_augmentation_preserves_t022_path_and_evaluation_identity() {
    let route = route();
    let guard = guard(GuardKind::RequiredRole, ComparisonShape::Equal);

    let non_elevated = client(ProviderAuthorityClass::PublishableOrAnon, Vec::new());
    let non_elevated_operation = operation(&non_elevated);
    let non_elevated_links = raw_correlation_links(&route, &guard, &non_elevated_operation);
    let t022_only_path = correlate_path(
        &route,
        &guard,
        &non_elevated_operation,
        &non_elevated,
        &non_elevated_links,
    );

    let elevated = client(
        ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        Vec::new(),
    );
    assert_eq!(non_elevated.client_id(), elevated.client_id());
    let elevated_operation = operation(&elevated);
    assert_eq!(
        non_elevated_operation.operation_id(),
        elevated_operation.operation_id()
    );
    let elevated_links = raw_correlation_links(&route, &guard, &elevated_operation);
    let t022_plus_t024_path = correlate_path(
        &route,
        &guard,
        &elevated_operation,
        &elevated,
        &elevated_links,
    );

    assert!(
        t022_plus_t024_path
            .links()
            .iter()
            .any(|link| { link.relation() == R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION })
    );
    assert_eq!(t022_only_path.path_id(), t022_plus_t024_path.path_id());

    let invariant = required_role_invariant();
    let t022_only_evaluation = evaluate_required_role(
        RequiredRoleInputs {
            invariant: &invariant,
            path: &t022_only_path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: std::slice::from_ref(&guard),
            operation: &non_elevated_operation,
        },
        limits(),
    )
    .expect("T022-only evaluation");
    let t022_plus_t024_evaluation = evaluate_required_role(
        RequiredRoleInputs {
            invariant: &invariant,
            path: &t022_plus_t024_path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: std::slice::from_ref(&guard),
            operation: &elevated_operation,
        },
        limits(),
    )
    .expect("T022+T024 evaluation");

    assert_eq!(
        t022_only_evaluation.state(),
        InvariantEvaluationState::Satisfied
    );
    assert_eq!(
        t022_plus_t024_evaluation.state(),
        InvariantEvaluationState::Satisfied
    );
    assert_eq!(
        t022_only_evaluation.evaluation_id(),
        t022_plus_t024_evaluation.evaluation_id()
    );
    assert_eq!(
        t022_only_evaluation.path_id(),
        t022_plus_t024_evaluation.path_id()
    );
}
