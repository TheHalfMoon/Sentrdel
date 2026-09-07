#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use sentrdel_review::{
    TARGET_BUILD_EXECUTION_ALLOWED,
    business_logic::{
        R3_DIRECT_FINDING_CREATION_ALLOWED, R3_PROVIDER_CREDENTIALS_ALLOWED,
        R3_TARGET_EXECUTION_ALLOWED,
        elevated_client::{
            ElevatedClientInputs, R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
            R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION, R3_SERVER_CONTEXT_EXPRESS,
            evaluate_elevated_client,
        },
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicCoverage,
            BusinessLogicCoverageArea, BusinessLogicLimits, ComparisonShape, ConfidenceBasis,
            CrossLayerLink, CrossLayerPath, DataOperation, DataOperationKind, DominanceScope,
            FieldSet, FieldSetMode, FilterOperator, FilterPredicate, FrameworkFamily, GuardKind,
            GuardObservation, HttpMethod, InvariantDefinition, InvariantEvaluation,
            InvariantEvaluationState, InvariantKind, InvariantRequirement, InvariantScope,
            InvariantSource, LinkBasis, PathState, ProviderAuthorityClass,
            ProviderClientAuthority, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
            StableSemanticId, TrustBasis, ValueOrigin, ValueOriginKind,
        },
        producer::{
            R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY, R3_BUSINESS_LOGIC_CREATES_FINDINGS,
            R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE, R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS,
            R3_BUSINESS_LOGIC_PRODUCER_ID, R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS,
            produce_business_logic_outputs,
        },
        protected_properties::{ProtectedPropertiesInputs, evaluate_protected_properties},
        r2_support::{R2SupportCorrelation, R2SupportLimits, correlate_supabase_r2_support},
        required_role::{
            R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION, R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION,
            RequiredRoleInputs, evaluate_required_role,
        },
        tenant_binding::{
            R3_TENANT_ACTOR_VALUE_RELATION, R3_TENANT_VALUE_OPERATION_RELATION,
            TenantBindingInputs, evaluate_tenant_binding,
        },
    },
    supabase_integration::SupabaseR2ProviderOutput,
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::{
    SCHEMA_V1,
    coverage::CoverageState,
    evidence::{EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, ProducerKind},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const CAPTURED_AT: &str = "2026-09-07T18:05:00Z";
const SUITE_BYTES: &[u8] = include_bytes!("../../../tests/benchmark/r3-release-suite.json");
const PHASE1_BYTES: &[u8] = include_bytes!(
    "../../../tests/benchmark/development-evaluation/r3-phase1-holdout-eligibility.json"
);
const HOLDOUT_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/protected-holdout/manifest.json");

#[derive(Clone, Debug, Deserialize)]
struct ReleaseSuite {
    suite_version: String,
    corpus_class: String,
    candidate_identity: String,
    release_gating: bool,
    evaluation_boundary: String,
    clean_case_false_positive_gate: CleanCaseGate,
    known_ground_truth: KnownGroundTruth,
    coverage: CoverageContract,
    authority_assertions: Vec<String>,
    inputs: ReleaseInputs,
    protected_holdout: DeferredGate,
    performance: DeferredPerformance,
}

#[derive(Clone, Debug, Deserialize)]
struct CleanCaseGate {
    max_false_positive_clean_cases: u64,
    per_clean_cases: u64,
    sample_state: String,
}

#[derive(Clone, Debug, Deserialize)]
struct KnownGroundTruth {
    required_violated_invariant_groups: Vec<String>,
    max_known_misses: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct CoverageContract {
    required_covered_areas: Vec<String>,
    required_explicit_gap_areas: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseInputs {
    phase1_eligibility: String,
    protected_holdout_manifest: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeferredGate {
    state: String,
    reason: String,
    candidate_expected_output_access: String,
}

#[derive(Clone, Debug, Deserialize)]
struct DeferredPerformance {
    state: String,
    owner_task: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct R3ReleaseRun {
    suite_version: String,
    corpus_class: String,
    candidate_identity: String,
    evaluation_boundary: String,
    clean_cases_evaluated: u64,
    clean_false_positives: u64,
    clean_non_satisfied: u64,
    clean_case_fp_gate_passed: bool,
    required_violated_invariant_groups: Vec<String>,
    detected_violated_invariant_groups: Vec<String>,
    known_misses: u64,
    known_miss_gate_passed: bool,
    required_covered_areas: Vec<String>,
    explicit_gap_areas: Vec<String>,
    evidence_count: u64,
    evidence_identity_failures: u64,
    explanation_records: u64,
    explanation_correctness_passed: bool,
    authority_assertions_passed: Vec<String>,
    protected_holdout_state: String,
    protected_label_isolation_passed: bool,
    deterministic_replay: String,
    performance_state: String,
}

struct EvaluatedCase {
    group: &'static str,
    clean: bool,
    evaluation: InvariantEvaluation,
}

fn limits() -> BusinessLogicLimits {
    BusinessLogicLimits::default()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], limits()).expect("stable semantic id")
}

fn repo_path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized repo path")
}

fn location(tag: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        repo_path(&format!("tests/benchmark/r3-t031/{tag}.ts")),
        start,
        start + 8,
        format!("sha256:{:064x}", start + tag.len()),
    )
    .expect("source location")
}

fn resource(name: &str) -> ResourceRef {
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some("public".to_owned()),
        name,
        ResourceKind::Table,
        None,
        limits(),
    )
    .expect("resource")
}

fn link(
    tag: &str,
    source: &StableSemanticId,
    target: &StableSemanticId,
    relation: &str,
) -> CrossLayerLink {
    CrossLayerLink::new(
        id("r3.t031.link", tag),
        source.clone(),
        target.clone(),
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![location(tag, 80)],
        limits(),
    )
    .expect("cross-layer link")
}

fn tenant_case(clean: bool) -> EvaluatedCase {
    let tag = if clean { "tenant-safe" } else { "tenant-vulnerable" };
    let actor = ActorContext::new(
        id("r3.t031.tenant.actor", tag),
        ActorIdentityKind::AuthenticatedUser,
        ActorSourceKind::VerifiedAuthAdapter,
        "auth.user.id",
        TrustBasis::DirectObservation,
        vec![location(tag, 10)],
        limits(),
    )
    .expect("tenant actor");
    let value = ValueOrigin::new(
        id("r3.t031.tenant.value", tag),
        if clean {
            ValueOriginKind::AuthenticatedUserId
        } else {
            ValueOriginKind::RequestPath
        },
        if clean { "auth.user.id" } else { "request.params.user_id" },
        clean.then(|| actor.actor_id().clone()),
        Vec::new(),
        0,
        vec![location(tag, 20)],
        limits(),
    )
    .expect("tenant value");
    let filter = FilterPredicate::new(
        "user_id",
        FilterOperator::Eq,
        value.value_id().clone(),
        location(tag, 30),
        limits(),
    )
    .expect("tenant filter");
    let operation = DataOperation::new(
        id("r3.t031.tenant.operation", tag),
        DataOperationKind::Read,
        resource("accounts"),
        None,
        vec![filter],
        None,
        None,
        None,
        None,
        vec![location(tag, 40)],
        CoverageState::Covered,
        limits(),
    )
    .expect("tenant operation");
    let route = RouteObservation::new(
        id("r3.t031.tenant.route", tag),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/accounts/:id",
        Some("getAccount".to_owned()),
        Vec::new(),
        vec![location(tag, 0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("tenant route");
    let mut links = vec![link(
        &format!("{tag}-value-operation"),
        value.value_id(),
        operation.operation_id(),
        R3_TENANT_VALUE_OPERATION_RELATION,
    )];
    if clean {
        links.push(link(
            &format!("{tag}-actor-value"),
            actor.actor_id(),
            value.value_id(),
            R3_TENANT_ACTOR_VALUE_RELATION,
        ));
    }
    let path = CrossLayerPath::new(
        id("r3.t031.tenant.path", tag),
        route.route_id().clone(),
        vec![actor.actor_id().clone()],
        Vec::new(),
        operation.operation_id().clone(),
        None,
        links,
        Vec::new(),
        PathState::Supported,
        vec![location(tag, 50)],
        limits(),
    )
    .expect("tenant path");
    let invariant = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant.tenant-binding", tag),
        InvariantKind::TenantBinding,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/accounts/:id".to_owned()),
            vec![HttpMethod::Get],
            Some(resource("accounts")),
            vec![DataOperationKind::Read],
            Vec::new(),
            limits(),
        )
        .expect("tenant scope"),
        InvariantRequirement::TenantBinding {
            resource_tenant_field: "user_id".to_owned(),
            required_actor_identity: ActorIdentityKind::AuthenticatedUser,
        },
        vec![location(tag, 60)],
        limits(),
    )
    .expect("tenant invariant");
    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        limits(),
    )
    .expect("tenant evaluation");
    EvaluatedCase {
        group: "TENANT_BINDING",
        clean,
        evaluation,
    }
}

fn role_case(clean: bool) -> EvaluatedCase {
    let tag = if clean { "role-safe" } else { "role-vulnerable" };
    let route = RouteObservation::new(
        id("r3.t031.role.route", tag),
        FrameworkFamily::NextApp,
        HttpMethod::Delete,
        "/admin/accounts/:id",
        Some("DELETE".to_owned()),
        Vec::new(),
        vec![location(tag, 0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("role route");
    let operation = DataOperation::new(
        id("r3.t031.role.operation", tag),
        DataOperationKind::Delete,
        resource("accounts"),
        None,
        Vec::new(),
        None,
        None,
        None,
        None,
        vec![location(tag, 20)],
        CoverageState::Covered,
        limits(),
    )
    .expect("role operation");
    let guard = clean.then(|| {
        GuardObservation::new(
            id("r3.t031.role.guard", tag),
            GuardKind::RequiredRole,
            None,
            Some(resource("accounts")),
            vec!["admin".to_owned()],
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            vec![location(tag, 40)],
            limits(),
        )
        .expect("role guard")
    });
    let (guard_ids, links) = if let Some(guard) = &guard {
        (
            vec![guard.guard_id().clone()],
            vec![
                link(
                    &format!("{tag}-route-guard"),
                    route.route_id(),
                    guard.guard_id(),
                    R3_REQUIRED_ROLE_ROUTE_GUARD_RELATION,
                ),
                link(
                    &format!("{tag}-guard-operation"),
                    guard.guard_id(),
                    operation.operation_id(),
                    R3_REQUIRED_ROLE_GUARD_OPERATION_RELATION,
                ),
            ],
        )
    } else {
        (
            Vec::new(),
            vec![link(
                &format!("{tag}-route-operation"),
                route.route_id(),
                operation.operation_id(),
                "supported_privileged_path",
            )],
        )
    };
    let path = CrossLayerPath::new(
        id("r3.t031.role.path", tag),
        route.route_id().clone(),
        Vec::new(),
        guard_ids,
        operation.operation_id().clone(),
        None,
        links,
        Vec::new(),
        PathState::Supported,
        vec![location(tag, 60)],
        limits(),
    )
    .expect("role path");
    let invariant = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant.required-role", tag),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/admin/accounts/:id".to_owned()),
            vec![HttpMethod::Delete],
            Some(resource("accounts")),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("role scope"),
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        vec![location(tag, 70)],
        limits(),
    )
    .expect("role invariant");
    let guards = guard.into_iter().collect::<Vec<_>>();
    let evaluation = evaluate_required_role(
        RequiredRoleInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: &guards,
            operation: &operation,
        },
        limits(),
    )
    .expect("required-role evaluation");
    EvaluatedCase {
        group: "REQUIRED_ROLE",
        clean,
        evaluation,
    }
}

fn protected_properties_case(clean: bool) -> EvaluatedCase {
    let tag = if clean {
        "properties-safe"
    } else {
        "properties-vulnerable"
    };
    let route = RouteObservation::new(
        id("r3.t031.properties.route", tag),
        FrameworkFamily::Express,
        HttpMethod::Patch,
        "/profiles/:id",
        Some("updateProfile".to_owned()),
        Vec::new(),
        vec![location(tag, 0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("properties route");
    let field_set = FieldSet::new(
        if clean {
            FieldSetMode::Explicit
        } else {
            FieldSetMode::BroadRequestObject
        },
        if clean {
            vec!["display_name".to_owned(), "timezone".to_owned()]
        } else {
            Vec::new()
        },
        Vec::new(),
        location(tag, 20),
        limits(),
    )
    .expect("mutation field set");
    let operation = DataOperation::new(
        id("r3.t031.properties.operation", tag),
        DataOperationKind::Update,
        resource("profiles"),
        None,
        Vec::new(),
        None,
        Some(field_set),
        None,
        None,
        vec![location(tag, 30)],
        CoverageState::Covered,
        limits(),
    )
    .expect("properties operation");
    let path = CrossLayerPath::new(
        id("r3.t031.properties.path", tag),
        route.route_id().clone(),
        Vec::new(),
        Vec::new(),
        operation.operation_id().clone(),
        None,
        vec![link(
            &format!("{tag}-route-operation"),
            route.route_id(),
            operation.operation_id(),
            "supported_route_operation",
        )],
        Vec::new(),
        PathState::Supported,
        vec![location(tag, 40)],
        limits(),
    )
    .expect("properties path");
    let invariant = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant.protected-properties", tag),
        InvariantKind::ProtectedProperties,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/profiles/:id".to_owned()),
            vec![HttpMethod::Patch],
            Some(resource("profiles")),
            Vec::new(),
            Vec::new(),
            limits(),
        )
        .expect("properties scope"),
        InvariantRequirement::ProtectedProperties {
            protected_properties: vec![
                "role".to_owned(),
                "is_admin".to_owned(),
                "tenant_id".to_owned(),
            ],
            mutation_operations: vec![DataOperationKind::Update, DataOperationKind::Upsert],
        },
        vec![location(tag, 50)],
        limits(),
    )
    .expect("properties invariant");
    let evaluation = evaluate_protected_properties(
        ProtectedPropertiesInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            operation: &operation,
        },
        limits(),
    )
    .expect("protected-properties evaluation");
    EvaluatedCase {
        group: "PROTECTED_PROPERTIES",
        clean,
        evaluation,
    }
}

fn boundary_evidence(tag: &str) -> Evidence {
    let authority = EvidenceAuthority::from_runtime(
        "sentrdel.supabase.r3-t031-fixture",
        "1",
        ProducerKind::NativeRule,
    )
    .expect("fixture evidence authority");
    authority
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec![format!("sha256:r3-t031-r2-input-{tag}")],
            observation: "repository-derived elevated key/client boundary".to_owned(),
            security_interpretation: None,
            category: "supabase_elevated_key_client_boundary".to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: Vec::new(),
            locations: vec![EvidenceLocation {
                repo_relative_path: format!("tests/benchmark/r3-t031/{tag}.ts"),
                start_line: Some(1),
                start_column: Some(1),
                end_line: Some(1),
                end_column: Some(16),
                symbol: None,
                content_digest: Some(format!("sha256:r3-t031-r2-input-{tag}")),
            }],
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: CAPTURED_AT.to_owned(),
        })
        .expect("sealed boundary evidence")
}

fn elevated_support(
    tag: &str,
) -> (ProviderClientAuthority, R2SupportCorrelation) {
    let evidence = boundary_evidence(tag);
    let client = ProviderClientAuthority::new(
        id("r3.t031.elevated.client", tag),
        "supabase",
        ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        vec![evidence.evidence_id().to_owned()],
        vec![location(tag, 20)],
        limits(),
    )
    .expect("elevated client");
    let provider =
        SupabaseR2ProviderOutput::new(vec![evidence], Vec::new()).expect("R2 provider output");
    let support = correlate_supabase_r2_support(
        &provider,
        &[],
        std::slice::from_ref(&client),
        R2SupportLimits::default(),
    )
    .expect("R2 support correlation");
    (client, support)
}

fn elevated_client_case(clean: bool) -> EvaluatedCase {
    let tag = if clean { "elevated-safe" } else { "elevated-vulnerable" };
    let (client, support) = elevated_support(tag);
    let route = RouteObservation::new(
        id("r3.t031.elevated.route", tag),
        FrameworkFamily::Express,
        HttpMethod::Delete,
        "/accounts/:id",
        Some("deleteAccount".to_owned()),
        Vec::new(),
        vec![location(tag, 0)],
        CoverageState::Covered,
        limits(),
    )
    .expect("elevated route");
    let operation = DataOperation::new(
        id("r3.t031.elevated.operation", tag),
        DataOperationKind::Delete,
        resource("accounts"),
        Some(client.client_id().clone()),
        Vec::new(),
        None,
        None,
        None,
        Some(id("r3.t031.elevated.handler", tag)),
        vec![location(tag, 30)],
        CoverageState::Covered,
        limits(),
    )
    .expect("elevated operation");
    let guard = clean.then(|| {
        GuardObservation::new(
            id("r3.t031.elevated.guard", tag),
            GuardKind::RequiredRole,
            None,
            Some(resource("accounts")),
            vec!["admin".to_owned()],
            ComparisonShape::Equal,
            DominanceScope::SameHandlerPrefix,
            vec![location(tag, 40)],
            limits(),
        )
        .expect("elevated guard")
    });
    let (guard_ids, links) = if let Some(guard) = &guard {
        (
            vec![guard.guard_id().clone()],
            vec![
                link(
                    &format!("{tag}-route-guard"),
                    route.route_id(),
                    guard.guard_id(),
                    R3_ELEVATED_CLIENT_ROUTE_GUARD_RELATION,
                ),
                link(
                    &format!("{tag}-guard-operation"),
                    guard.guard_id(),
                    operation.operation_id(),
                    R3_ELEVATED_CLIENT_GUARD_OPERATION_RELATION,
                ),
            ],
        )
    } else {
        (
            Vec::new(),
            vec![link(
                &format!("{tag}-route-operation"),
                route.route_id(),
                operation.operation_id(),
                "supported_route_operation",
            )],
        )
    };
    let path = CrossLayerPath::new(
        id("r3.t031.elevated.path", tag),
        route.route_id().clone(),
        Vec::new(),
        guard_ids,
        operation.operation_id().clone(),
        Some(client.client_id().clone()),
        links,
        Vec::new(),
        PathState::Supported,
        vec![location(tag, 50)],
        limits(),
    )
    .expect("elevated path");
    let invariant = InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant.elevated-client", tag),
        InvariantKind::ElevatedClientContext,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some("/accounts/:id".to_owned()),
            vec![HttpMethod::Delete],
            Some(resource("accounts")),
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits(),
        )
        .expect("elevated scope"),
        InvariantRequirement::ElevatedClientContext {
            allowed_server_contexts: vec![R3_SERVER_CONTEXT_EXPRESS.to_owned()],
            required_guard_kinds: vec![GuardKind::RequiredRole],
        },
        vec![location(tag, 60)],
        limits(),
    )
    .expect("elevated invariant");
    let guards = guard.into_iter().collect::<Vec<_>>();
    let evaluation = evaluate_elevated_client(
        ElevatedClientInputs {
            invariant: &invariant,
            path: &path,
            route: &route,
            guard_coverage_state: &CoverageState::Covered,
            guards: &guards,
            operation: &operation,
            client: &client,
            r2_support: &support,
        },
        limits(),
    )
    .expect("elevated-client evaluation");
    EvaluatedCase {
        group: "ELEVATED_CLIENT_CONTEXT",
        clean,
        evaluation,
    }
}

fn coverage_area_name(area: BusinessLogicCoverageArea) -> &'static str {
    match area {
        BusinessLogicCoverageArea::Routes => "ROUTES",
        BusinessLogicCoverageArea::ActorIdentity => "ACTOR_IDENTITY",
        BusinessLogicCoverageArea::Guards => "GUARDS",
        BusinessLogicCoverageArea::ValueOrigins => "VALUE_ORIGINS",
        BusinessLogicCoverageArea::DataOperations => "DATA_OPERATIONS",
        BusinessLogicCoverageArea::LocalLinking => "LOCAL_LINKING",
        BusinessLogicCoverageArea::SemanticLinking => "SEMANTIC_LINKING",
        BusinessLogicCoverageArea::R2ProviderCorrelation => "R2_PROVIDER_CORRELATION",
        BusinessLogicCoverageArea::ProjectInvariants => "PROJECT_INVARIANTS",
        BusinessLogicCoverageArea::InvariantEvaluation => "INVARIANT_EVALUATION",
    }
}

fn coverage_matrix() -> Vec<BusinessLogicCoverage> {
    use BusinessLogicCoverageArea as Area;
    [
        Area::Routes,
        Area::ActorIdentity,
        Area::Guards,
        Area::ValueOrigins,
        Area::DataOperations,
        Area::LocalLinking,
        Area::SemanticLinking,
        Area::R2ProviderCorrelation,
        Area::ProjectInvariants,
        Area::InvariantEvaluation,
    ]
    .into_iter()
    .map(|area| {
        let is_explicit_gap = matches!(area, Area::SemanticLinking | Area::ProjectInvariants);
        BusinessLogicCoverage::new(
            area,
            if is_explicit_gap {
                CoverageState::Partial
            } else {
                CoverageState::Covered
            },
            if area == Area::SemanticLinking {
                "R3_T031_NORMALIZED_IR_GATE_DOES_NOT_REQUIRE_SEMANTIC_INDEX"
            } else if area == Area::ProjectInvariants {
                "R3_T031_INITIAL_GATE_COVERS_BUILTIN_INVARIANTS_ONLY"
            } else {
                "R3_T031_RELEASE_GATE_COVERED"
            },
            "r3-t031-release-benchmark",
            vec!["sha256:r3-t031-release-input".to_owned()],
            R3_BUSINESS_LOGIC_PRODUCER_ID,
            limits(),
        )
        .expect("R3 coverage entry")
    })
    .collect()
}

fn protected_label_isolation(suite: &ReleaseSuite) -> bool {
    let manifest: Value = serde_json::from_slice(HOLDOUT_BYTES).expect("protected holdout manifest");
    manifest["corpus_class"] == "PROTECTED_HOLDOUT"
        && manifest["case_material_location"] == "EXTERNAL_ONLY"
        && manifest["expected_outputs_location"] == "EXTERNAL_ONLY"
        && manifest["candidate_generation_expected_output_access"] == "DENIED"
        && manifest["repository_committed_case_count"] == 0
        && manifest["repository_committed_expected_output_count"] == 0
        && suite.protected_holdout.state == "NOT_MEASURED"
        && suite.protected_holdout.candidate_expected_output_access == "DENIED"
        && suite
            .protected_holdout
            .reason
            .contains("NO_QUALIFICATION_RECEIPT")
}

fn explanation_correct(evidence: &[Evidence], expected_evaluations: usize) -> (u64, bool) {
    let interpretations = evidence
        .iter()
        .filter(|item| item.claim().category == "business_logic_invariant_interpretation")
        .collect::<Vec<_>>();
    let passed = interpretations.len() == expected_evaluations
        && interpretations.iter().all(|item| {
            item.claim()
                .attributes
                .get("path_id")
                .and_then(Value::as_str)
                .is_some_and(|value| value.starts_with("sha256:"))
                && item
                    .claim()
                    .attributes
                    .get("evaluation_state")
                    .and_then(Value::as_str)
                    .is_some()
                && item
                    .claim()
                    .attributes
                    .get("provenance_byte_ranges")
                    .and_then(Value::as_array)
                    .is_some_and(|ranges| !ranges.is_empty())
                && item.claim().security_interpretation.as_ref().is_some_and(|text| {
                    text.contains("bounded static scope") && !text.contains("runtime exploitability is proven")
                })
        });
    (interpretations.len() as u64, passed)
}

fn evaluate_once() -> R3ReleaseRun {
    let suite: ReleaseSuite = serde_json::from_slice(SUITE_BYTES).expect("R3 release suite");
    let phase1: Value = serde_json::from_slice(PHASE1_BYTES).expect("R3 Phase 1 eligibility");

    assert!(suite.release_gating);
    assert_eq!(suite.corpus_class, "DEVELOPMENT_EVALUATION");
    assert_eq!(suite.evaluation_boundary, "NORMALIZED_SUPPORTED_R3_IR");
    assert_eq!(phase1["release_gating"], Value::Bool(false));
    assert_eq!(
        phase1["protected_holdout_status"],
        "NOT_ELIGIBLE_PRE_RELEASE_GATING"
    );
    for requirement in [
        "implemented-supported-detector-scope",
        "clean-case-false-positive-gate",
        "declared-scope-known-miss-recall-gate",
        "deterministic-replay",
        "coverage-and-provenance-gates",
        "authority-contract-pass",
        "protected-label-isolation",
    ] {
        assert!(
            phase1["promotion_requires"]
                .as_array()
                .expect("promotion requirements")
                .iter()
                .any(|value| value == requirement),
            "missing frozen Phase 1 promotion requirement: {requirement}"
        );
    }
    assert_eq!(
        suite.inputs.phase1_eligibility,
        "tests/benchmark/development-evaluation/r3-phase1-holdout-eligibility.json"
    );
    assert_eq!(
        suite.inputs.protected_holdout_manifest,
        "tests/benchmark/protected-holdout/manifest.json"
    );

    let cases = vec![
        tenant_case(true),
        tenant_case(false),
        role_case(true),
        role_case(false),
        protected_properties_case(true),
        protected_properties_case(false),
        elevated_client_case(true),
        elevated_client_case(false),
    ];

    for case in &cases {
        let expected = if case.clean {
            InvariantEvaluationState::Satisfied
        } else {
            InvariantEvaluationState::Violated
        };
        assert_eq!(
            case.evaluation.state(),
            expected,
            "unexpected release-gate state for {} clean={}",
            case.group,
            case.clean
        );
    }

    let clean_cases = cases.iter().filter(|case| case.clean).collect::<Vec<_>>();
    let clean_false_positives = clean_cases
        .iter()
        .filter(|case| case.evaluation.state() == InvariantEvaluationState::Violated)
        .count() as u64;
    let clean_non_satisfied = clean_cases
        .iter()
        .filter(|case| case.evaluation.state() != InvariantEvaluationState::Satisfied)
        .count() as u64;
    let clean_cases_evaluated = clean_cases.len() as u64;
    assert_eq!(suite.clean_case_false_positive_gate.sample_state, "INITIAL_FOUR_CASE_STRICT_ZERO");
    assert_eq!(suite.clean_case_false_positive_gate.max_false_positive_clean_cases, 1);
    assert_eq!(suite.clean_case_false_positive_gate.per_clean_cases, 5);
    let clean_case_fp_gate_passed = if clean_cases_evaluated
        < suite.clean_case_false_positive_gate.per_clean_cases
    {
        clean_false_positives == 0 && clean_non_satisfied == 0
    } else {
        clean_non_satisfied == 0
            && clean_false_positives
                .checked_mul(suite.clean_case_false_positive_gate.per_clean_cases)
                .is_some_and(|scaled| {
                    scaled
                        <= suite
                            .clean_case_false_positive_gate
                            .max_false_positive_clean_cases
                            .saturating_mul(clean_cases_evaluated)
                })
    };

    let required = suite
        .known_ground_truth
        .required_violated_invariant_groups
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let detected = cases
        .iter()
        .filter(|case| !case.clean && case.evaluation.state() == InvariantEvaluationState::Violated)
        .map(|case| case.group.to_owned())
        .collect::<BTreeSet<_>>();
    let known_misses = required.difference(&detected).count() as u64;

    let coverage = coverage_matrix();
    let covered_areas = coverage
        .iter()
        .filter(|entry| entry.state() == &CoverageState::Covered)
        .map(|entry| coverage_area_name(entry.area()).to_owned())
        .collect::<BTreeSet<_>>();
    let explicit_gap_areas = coverage
        .iter()
        .filter(|entry| entry.state() != &CoverageState::Covered)
        .map(|entry| coverage_area_name(entry.area()).to_owned())
        .collect::<BTreeSet<_>>();
    let required_covered = suite
        .coverage
        .required_covered_areas
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let required_gaps = suite
        .coverage
        .required_explicit_gap_areas
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert!(required_covered.is_subset(&covered_areas));
    assert_eq!(required_gaps, explicit_gap_areas);

    let evaluations = cases
        .iter()
        .map(|case| case.evaluation.clone())
        .collect::<Vec<_>>();
    let output = produce_business_logic_outputs(&evaluations, &coverage, CAPTURED_AT)
        .expect("R3 Evidence/Coverage output");
    let evidence_identity_failures = output
        .evidence()
        .iter()
        .filter(|item| !item.verify_identity().unwrap_or(false))
        .count() as u64;
    let (explanation_records, explanation_correctness_passed) =
        explanation_correct(output.evidence(), evaluations.len());

    const { assert!(!TARGET_BUILD_EXECUTION_ALLOWED) };
    const { assert!(!R3_TARGET_EXECUTION_ALLOWED) };
    const { assert!(!R3_PROVIDER_CREDENTIALS_ALLOWED) };
    const { assert!(!R3_DIRECT_FINDING_CREATION_ALLOWED) };
    const { assert!(!R3_BUSINESS_LOGIC_CREATES_FINDINGS) };
    const { assert!(!R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS) };
    const { assert!(!R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY) };

    let holdout_isolation = protected_label_isolation(&suite);
    let output_is_evidence_or_coverage_only = output.evidence().len() == evaluations.len() * 2
        && output.coverage().len() == coverage.len() + 2
        && evidence_identity_failures == 0;
    let authority_results = BTreeMap::from([
        ("r3-output-is-evidence-or-coverage-only", output_is_evidence_or_coverage_only),
        (
            "no-direct-finding-authority",
            !R3_DIRECT_FINDING_CREATION_ALLOWED && !R3_BUSINESS_LOGIC_CREATES_FINDINGS,
        ),
        (
            "no-target-execution",
            !TARGET_BUILD_EXECUTION_ALLOWED
                && !R3_TARGET_EXECUTION_ALLOWED
                && !R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE,
        ),
        ("no-network-access", !R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS),
        (
            "no-provider-credentials",
            !R3_PROVIDER_CREDENTIALS_ALLOWED && !R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS,
        ),
        (
            "no-runtime-exploitability-claim",
            !R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY,
        ),
        ("protected-label-isolation", holdout_isolation),
    ]);
    let authority_assertions_passed = suite
        .authority_assertions
        .iter()
        .filter(|id| authority_results.get(id.as_str()).copied() == Some(true))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(authority_assertions_passed.len(), suite.authority_assertions.len());

    assert_eq!(suite.performance.state, "NOT_MEASURED");
    assert_eq!(suite.performance.owner_task, "R3-T032");

    R3ReleaseRun {
        suite_version: suite.suite_version,
        corpus_class: suite.corpus_class,
        candidate_identity: suite.candidate_identity,
        evaluation_boundary: suite.evaluation_boundary,
        clean_cases_evaluated,
        clean_false_positives,
        clean_non_satisfied,
        clean_case_fp_gate_passed,
        required_violated_invariant_groups: required.into_iter().collect(),
        detected_violated_invariant_groups: detected.into_iter().collect(),
        known_misses,
        known_miss_gate_passed: known_misses <= suite.known_ground_truth.max_known_misses,
        required_covered_areas: required_covered.into_iter().collect(),
        explicit_gap_areas: explicit_gap_areas.into_iter().collect(),
        evidence_count: output.evidence().len() as u64,
        evidence_identity_failures,
        explanation_records,
        explanation_correctness_passed,
        authority_assertions_passed,
        protected_holdout_state: suite.protected_holdout.state,
        protected_label_isolation_passed: holdout_isolation,
        deterministic_replay: "REPLAY_EQUAL".to_owned(),
        performance_state: suite.performance.state,
    }
}

#[test]
fn r3_initial_release_gate_meets_sentrdelbench_quality_contract() {
    let first = evaluate_once();
    let replay = evaluate_once();
    assert_eq!(first, replay);
    assert!(first.clean_case_fp_gate_passed);
    assert_eq!(first.clean_false_positives, 0);
    assert_eq!(first.clean_non_satisfied, 0);
    assert!(first.known_miss_gate_passed);
    assert_eq!(first.known_misses, 0);
    assert_eq!(
        first.required_violated_invariant_groups,
        first.detected_violated_invariant_groups
    );
    assert_eq!(first.evidence_identity_failures, 0);
    assert_eq!(first.explanation_records, 8);
    assert!(first.explanation_correctness_passed);
    assert!(first.protected_label_isolation_passed);
    assert_eq!(first.protected_holdout_state, "NOT_MEASURED");
    assert_eq!(first.deterministic_replay, "REPLAY_EQUAL");
    assert_eq!(first.performance_state, "NOT_MEASURED");
}
