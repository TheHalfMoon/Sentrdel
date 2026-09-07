#![forbid(unsafe_code)]

use super::{
    explain::{ExplainOutput, ImpactComponents},
    explain_business_logic::{
        BusinessLogicExplainContext, render_explain_human_with_business_logic_context,
    },
};
use sentrdel_cli::{
    CliDecision, CliRepository, CliTiming, init::build_init_output, review::ReviewOutput,
};
use sentrdel_review::{
    TARGET_BUILD_EXECUTION_ALLOWED,
    business_logic::{
        R3_BUSINESS_LOGIC_PROVIDER,
        actor::extract_actor_contexts,
        coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS,
        data::extract_supabase_data_operations,
        invariant::ProjectInvariantLimits,
        model::{
            ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicCoverage,
            BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, CrossLayerPath, DataOperation,
            DataOperationKind, FilterOperator, FilterPredicate, InvariantDefinition,
            InvariantEvaluation, InvariantEvaluationState, InvariantKind, InvariantRequirement,
            InvariantScope, InvariantSource, LinkBasis, PathState, ResourceKind, ResourceRef,
            RouteObservation, SourceLocation, StableSemanticId, TrustBasis, ValueOrigin,
            ValueOriginKind,
        },
        path::{PathCorrelationInputs, PathCorrelationLimits, correlate_cross_layer_paths},
        producer::{
            BusinessLogicProducerOutput, R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY,
            R3_BUSINESS_LOGIC_CREATES_FINDINGS, R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE,
            R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS, R3_BUSINESS_LOGIC_PRODUCER_ID,
            R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS, produce_business_logic_outputs,
        },
        project_invariant::{
            PROJECT_INVARIANT_CAN_WEAKEN_BUILTINS, PROJECT_INVARIANT_CREATES_FINDINGS,
            PROJECT_INVARIANT_EXECUTES_TARGET_CODE,
            PROJECT_INVARIANT_PARSE_FAILURE_DISABLES_BUILTINS, PROJECT_INVARIANT_PATH,
            PROJECT_INVARIANT_PERFORMS_NETWORK_ACCESS,
            PROJECT_INVARIANT_REQUESTS_PROVIDER_CREDENTIALS, ProjectInvariantLoadState,
            load_project_invariants,
        },
        register_r3_pack,
        route::{RouteAdapter, RouteCoverageGapReason, extract_routes},
        tenant_binding::{TenantBindingInputs, evaluate_tenant_binding},
        value::extract_value_origins,
    },
    config_detection::CiMcpConfigDetection,
    pack_registry::{PackCoverageDimension, SecurityPackRegistry},
    profile::{ProjectCoverageSubjectKind, build_project_profile_snapshot},
    project_detection::{DetectionLimits, LanguageEcosystemDetection},
    reconcile::{ReconciliationRule, reconcile_evidence},
    stack_detection::{PathMatchRule, StackDetectorRegistry, StackDetectorSpec, StackKind},
    structural::StructuralLanguage,
    supabase_detection::detect_supabase,
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::{
    coverage::CoverageState,
    evidence::Evidence,
    finding::{Finding, ReconcilerAuthority, Severity},
};

const OBSERVED_AT: &str = "2026-09-07T15:00:00Z";
const EXPRESS_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/safe-tenant/src/routes/accounts.js"
);
const EXPRESS_UNSAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/unsafe-tenant/src/routes/accounts.js"
);
const NEXT_PAGES_UNKNOWN: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-pages/unknown-dynamic-guard/pages/api/accounts/[id].js"
);
const DYNAMIC_UNSUPPORTED: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/dynamic-unsupported/src/dynamic.js"
);
const UNSUPPORTED_FRAMEWORK: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/unsupported-framework/src/routes.js"
);
const HOSTILE_README: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/hostile-repository/README.md"
);
const FORBIDDEN_AUTHORITY_INVARIANTS: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/project-invariants/forbidden-authority/.sentrdel/invariants.toml"
);

const FASTIFY_RULES: &[PathMatchRule] = &[PathMatchRule::Basename("routes.js")];
const STACK_SPECS: &[StackDetectorSpec] = &[StackDetectorSpec::new(
    "fastify",
    StackKind::Framework,
    FASTIFY_RULES,
)];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureCase {
    Safe,
    Vulnerable,
    ContradictoryUnknown,
    UnsupportedSemanticLink,
    UnsupportedFramework,
    HostileRepository,
}

impl FixtureCase {
    const ALL: [Self; 6] = [
        Self::Safe,
        Self::Vulnerable,
        Self::ContradictoryUnknown,
        Self::UnsupportedSemanticLink,
        Self::UnsupportedFramework,
        Self::HostileRepository,
    ];

    const fn slug(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Vulnerable => "vulnerable",
            Self::ContradictoryUnknown => "contradictory-unknown",
            Self::UnsupportedSemanticLink => "unsupported-semantic-link",
            Self::UnsupportedFramework => "unsupported-framework",
            Self::HostileRepository => "hostile-repository",
        }
    }

    const fn source(self) -> &'static str {
        match self {
            Self::Safe => EXPRESS_SAFE,
            Self::Vulnerable => EXPRESS_UNSAFE,
            Self::ContradictoryUnknown => NEXT_PAGES_UNKNOWN,
            Self::UnsupportedSemanticLink => DYNAMIC_UNSUPPORTED,
            Self::UnsupportedFramework => UNSUPPORTED_FRAMEWORK,
            Self::HostileRepository => HOSTILE_README,
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Safe | Self::Vulnerable => "src/routes/accounts.js",
            Self::ContradictoryUnknown => "pages/api/accounts/[id].js",
            Self::UnsupportedSemanticLink => "src/dynamic.js",
            Self::UnsupportedFramework => "src/routes.js",
            Self::HostileRepository => "README.md",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SourceFixtureSnapshot {
    routes: Vec<RouteObservation>,
    route_gap_reasons: Vec<RouteCoverageGapReason>,
    actor_identities: Vec<ActorIdentityKind>,
    value_kinds: Vec<ValueOriginKind>,
    data_states: Vec<CoverageState>,
    data_filter_counts: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq)]
struct FixtureAnalysis {
    source: SourceFixtureSnapshot,
    paths: Vec<CrossLayerPath>,
    evaluations: Vec<InvariantEvaluation>,
    producer: BusinessLogicProducerOutput,
}

fn normalized_path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).unwrap()
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default()).unwrap()
}

fn semantic_location(case: FixtureCase, start: usize) -> SourceLocation {
    SourceLocation::new(
        normalized_path(case.path()),
        start,
        start + 8,
        format!("sha256:{:064x}", start.saturating_add(1)),
    )
    .unwrap()
}

fn source_fixture_snapshot(case: FixtureCase) -> SourceFixtureSnapshot {
    if case == FixtureCase::UnsupportedFramework {
        assert!(case.source().contains("fastify.route"));
        return SourceFixtureSnapshot {
            routes: Vec::new(),
            route_gap_reasons: Vec::new(),
            actor_identities: Vec::new(),
            value_kinds: Vec::new(),
            data_states: Vec::new(),
            data_filter_counts: Vec::new(),
        };
    }
    if case == FixtureCase::HostileRepository {
        assert!(case.source().contains("SENTRDEL_CANARY"));
        return SourceFixtureSnapshot {
            routes: Vec::new(),
            route_gap_reasons: Vec::new(),
            actor_identities: Vec::new(),
            value_kinds: Vec::new(),
            data_states: Vec::new(),
            data_filter_counts: Vec::new(),
        };
    }

    let (adapter, language) = match case {
        FixtureCase::Safe | FixtureCase::Vulnerable | FixtureCase::UnsupportedSemanticLink => {
            (RouteAdapter::Express, StructuralLanguage::JavaScript)
        }
        FixtureCase::ContradictoryUnknown => {
            (RouteAdapter::NextPagesApi, StructuralLanguage::JavaScript)
        }
        FixtureCase::UnsupportedFramework | FixtureCase::HostileRepository => unreachable!(),
    };
    let path = normalized_path(case.path());
    let routes = extract_routes(
        adapter,
        language,
        &path,
        case.source().as_bytes(),
        BusinessLogicLimits::default(),
    )
    .unwrap();

    if case == FixtureCase::UnsupportedSemanticLink {
        assert!(routes.routes().is_empty());
        assert!(routes.gaps().iter().any(|gap| {
            gap.reason() == RouteCoverageGapReason::DynamicRegistration
                || gap.reason() == RouteCoverageGapReason::DynamicRoutePattern
        }));
    } else {
        assert_eq!(routes.routes().len(), 1, "{} route count", case.slug());
    }

    let mut actor_identities = Vec::new();
    let mut value_kinds = Vec::new();
    let mut data_states = Vec::new();
    let mut data_filter_counts = Vec::new();
    if matches!(case, FixtureCase::Safe | FixtureCase::Vulnerable) {
        let actors = extract_actor_contexts(
            adapter,
            language,
            &path,
            case.source().as_bytes(),
            BusinessLogicLimits::default(),
        )
        .unwrap();
        actor_identities = actors
            .actors()
            .iter()
            .map(ActorContext::identity_kind)
            .collect();

        let values = extract_value_origins(
            adapter,
            language,
            &path,
            case.source().as_bytes(),
            BusinessLogicLimits::default(),
        )
        .unwrap();
        value_kinds = values
            .values()
            .iter()
            .map(ValueOrigin::origin_kind)
            .collect();

        let data = extract_supabase_data_operations(
            adapter,
            language,
            &path,
            case.source().as_bytes(),
            BusinessLogicLimits::default(),
        )
        .unwrap();
        data_states = data
            .operations()
            .iter()
            .map(|operation| operation.coverage_state().clone())
            .collect();
        data_filter_counts = data
            .operations()
            .iter()
            .map(|operation| operation.filters().len())
            .collect();
    }

    SourceFixtureSnapshot {
        routes: routes.routes().to_vec(),
        route_gap_reasons: routes.gaps().iter().map(|gap| gap.reason()).collect(),
        actor_identities,
        value_kinds,
        data_states,
        data_filter_counts,
    }
}

fn admitted_actor(case: FixtureCase) -> ActorContext {
    ActorContext::new(
        id("r3.t030.surface.actor", case.slug()),
        ActorIdentityKind::AuthenticatedUser,
        ActorSourceKind::VerifiedAuthAdapter,
        "auth.user.id",
        TrustBasis::DirectObservation,
        vec![semantic_location(case, 20)],
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn admitted_value(case: FixtureCase, actor: &ActorContext) -> ValueOrigin {
    let (kind, source_actor) = match case {
        FixtureCase::Safe | FixtureCase::ContradictoryUnknown => (
            ValueOriginKind::AuthenticatedUserId,
            Some(actor.actor_id().clone()),
        ),
        FixtureCase::Vulnerable => (ValueOriginKind::RequestPath, None),
        FixtureCase::UnsupportedSemanticLink
        | FixtureCase::UnsupportedFramework
        | FixtureCase::HostileRepository => unreachable!(),
    };
    ValueOrigin::new(
        id("r3.t030.surface.value", case.slug()),
        kind,
        format!("surface.value.{}", case.slug()),
        source_actor,
        Vec::new(),
        0,
        vec![semantic_location(case, 40)],
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn admitted_resource() -> ResourceRef {
    ResourceRef::new(
        None,
        None,
        "accounts",
        ResourceKind::Table,
        None,
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn admitted_operation(case: FixtureCase, value: &ValueOrigin) -> DataOperation {
    let field = if case == FixtureCase::Vulnerable {
        "id"
    } else {
        "user_id"
    };
    let filter = FilterPredicate::new(
        field,
        FilterOperator::Eq,
        value.value_id().clone(),
        semantic_location(case, 80),
        BusinessLogicLimits::default(),
    )
    .unwrap();
    DataOperation::new(
        id("r3.t030.surface.operation", case.slug()),
        DataOperationKind::Read,
        admitted_resource(),
        None,
        vec![filter],
        None,
        None,
        None,
        None,
        vec![semantic_location(case, 100)],
        if case == FixtureCase::ContradictoryUnknown {
            CoverageState::Partial
        } else {
            CoverageState::Covered
        },
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn admitted_link(
    case: FixtureCase,
    route: &RouteObservation,
    target: StableSemanticId,
    relation: &str,
    start: usize,
) -> CrossLayerLink {
    CrossLayerLink::new(
        StableSemanticId::from_parts(
            "r3.t030.surface.link",
            &[route.route_id().as_str(), target.as_str(), relation],
            BusinessLogicLimits::default(),
        )
        .unwrap(),
        route.route_id().clone(),
        target,
        relation,
        LinkBasis::ExplicitAdapterLink,
        ConfidenceBasis::Extracted,
        vec![semantic_location(case, start)],
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn admitted_invariant(case: FixtureCase, route: &RouteObservation) -> InvariantDefinition {
    InvariantDefinition::new(
        id("sentrdel.r3.builtin-invariant", "tenant-binding"),
        InvariantKind::TenantBinding,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            Some(route.route_pattern().to_owned()),
            vec![route.method()],
            Some(admitted_resource()),
            vec![DataOperationKind::Read],
            Vec::new(),
            BusinessLogicLimits::default(),
        )
        .unwrap(),
        InvariantRequirement::TenantBinding {
            resource_tenant_field: "user_id".to_owned(),
            required_actor_identity: ActorIdentityKind::AuthenticatedUser,
        },
        vec![semantic_location(case, 140)],
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

/// Build already-admitted semantic inputs solely to exercise the developer-facing integration
/// surfaces. The fixture bytes are validated independently by `source_fixture_snapshot`; this
/// helper does not claim that these semantic links were extracted from those bytes.
fn admitted_surface_semantics(
    case: FixtureCase,
    source: &SourceFixtureSnapshot,
) -> (Vec<CrossLayerPath>, Vec<InvariantEvaluation>) {
    if matches!(
        case,
        FixtureCase::UnsupportedSemanticLink
            | FixtureCase::UnsupportedFramework
            | FixtureCase::HostileRepository
    ) {
        return (Vec::new(), Vec::new());
    }

    let route = source.routes.first().expect("supported surface route");
    let actor = admitted_actor(case);
    let value = admitted_value(case, &actor);
    let operation = admitted_operation(case, &value);
    let links = vec![
        admitted_link(
            case,
            route,
            actor.actor_id().clone(),
            "surface_route_reaches_actor",
            160,
        ),
        admitted_link(
            case,
            route,
            operation.operation_id().clone(),
            "surface_route_reaches_operation",
            180,
        ),
    ];
    let correlated = correlate_cross_layer_paths(
        PathCorrelationInputs {
            routes: std::slice::from_ref(route),
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            data_operations: std::slice::from_ref(&operation),
            provider_clients: &[],
            links: &links,
        },
        BusinessLogicLimits::default(),
        PathCorrelationLimits::default(),
    )
    .unwrap();
    let path = correlated.paths().first().expect("correlated surface path");
    let invariant = admitted_invariant(case, route);
    let evaluation = evaluate_tenant_binding(
        TenantBindingInputs {
            invariant: &invariant,
            path,
            route,
            actors: std::slice::from_ref(&actor),
            guards: &[],
            values: std::slice::from_ref(&value),
            operation: &operation,
        },
        BusinessLogicLimits::default(),
    )
    .unwrap();
    (correlated.paths().to_vec(), vec![evaluation])
}

fn surface_coverage_state(
    case: FixtureCase,
    paths: &[CrossLayerPath],
    evaluations: &[InvariantEvaluation],
) -> CoverageState {
    if case == FixtureCase::UnsupportedFramework {
        return CoverageState::Unsupported;
    }
    if paths.is_empty() || evaluations.is_empty() {
        return CoverageState::Partial;
    }
    if paths
        .iter()
        .all(|path| path.path_state() == PathState::Supported)
        && evaluations
            .iter()
            .all(|evaluation| evaluation.state() != InvariantEvaluationState::Unknown)
    {
        CoverageState::Covered
    } else {
        CoverageState::Partial
    }
}

fn analyze_fixture(case: FixtureCase) -> FixtureAnalysis {
    let source = source_fixture_snapshot(case);
    let (paths, evaluations) = admitted_surface_semantics(case, &source);
    let coverage_state = surface_coverage_state(case, &paths, &evaluations);
    let coverage = REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
        .into_iter()
        .map(|area| {
            BusinessLogicCoverage::new(
                area,
                coverage_state.clone(),
                "R3_T030_ADMITTED_DEVELOPER_SURFACE_SEMANTICS",
                ".",
                Vec::new(),
                R3_BUSINESS_LOGIC_PRODUCER_ID,
                BusinessLogicLimits::default(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let producer = produce_business_logic_outputs(&evaluations, &coverage, OBSERVED_AT).unwrap();

    FixtureAnalysis {
        source,
        paths,
        evaluations,
        producer,
    }
}

fn reconciled_findings(analysis: &FixtureAnalysis) -> Vec<Finding> {
    if !analysis
        .evaluations
        .iter()
        .any(|evaluation| evaluation.state() == InvariantEvaluationState::Violated)
    {
        return Vec::new();
    }
    let interpretation = analysis
        .producer
        .evidence()
        .iter()
        .filter(|item| item.claim().category == "business_logic_invariant_interpretation")
        .cloned()
        .collect::<Vec<Evidence>>();
    assert_eq!(interpretation.len(), 1);
    let rule = ReconciliationRule::from_runtime(
        "business_logic_invariant_interpretation",
        "business_logic_invariant",
        "Bounded business-logic invariant violation",
        "A runtime-owned reconciliation rule mapped a violated bounded static invariant to a canonical Finding.",
        Severity::High,
    )
    .unwrap();
    let reconciler = ReconcilerAuthority::from_runtime(
        "sentrdel.r3-t030-reconciler",
        format!("sha256:{}", "f".repeat(64)),
    )
    .unwrap();
    reconcile_evidence(&interpretation, &rule, &reconciler, OBSERVED_AT).unwrap()
}

fn repository(case: FixtureCase) -> CliRepository {
    CliRepository::new(format!("fixture:r3-t030:{}", case.slug()), ".").unwrap()
}

fn review(
    case: FixtureCase,
    analysis: &FixtureAnalysis,
) -> sentrdel_cli::review::business_logic::RegisteredBusinessLogicReviewOutput {
    let findings = reconciled_findings(analysis);
    let baseline = ReviewOutput::new(
        repository(case),
        if findings.is_empty() {
            CliDecision::Allow
        } else {
            CliDecision::Ask
        },
        findings,
        Vec::new(),
        Vec::new(),
        CliTiming::default(),
        None,
    )
    .unwrap();
    baseline
        .integrate_r3_business_logic(
            &analysis.producer,
            &[normalized_path(case.path())],
            &analysis.source.routes,
            &analysis.paths,
            &analysis.evaluations,
        )
        .unwrap()
}

fn init(case: FixtureCase) -> sentrdel_cli::init::InitOutput {
    let stacks = StackDetectorRegistry::new(STACK_SPECS)
        .unwrap()
        .detect([case.path()], DetectionLimits::default())
        .unwrap();
    let supabase = detect_supabase(std::iter::empty::<&str>(), DetectionLimits::default()).unwrap();
    let mut packs = SecurityPackRegistry::new();
    register_r3_pack(&mut packs).unwrap();
    let repository_id = format!("fixture:r3-t030:{}", case.slug());
    let repository_root_digest = format!("sha256:{}", "a".repeat(64));
    let snapshot = build_project_profile_snapshot(
        &repository_id,
        &repository_root_digest,
        &LanguageEcosystemDetection {
            languages: vec!["javascript".to_owned()],
            package_ecosystems: vec!["npm".to_owned()],
        },
        &CiMcpConfigDetection {
            ci_systems: Vec::new(),
            mcp_configurations: Vec::new(),
        },
        &stacks,
        &supabase,
        &packs,
        OBSERVED_AT,
        OBSERVED_AT,
    )
    .unwrap();

    if case == FixtureCase::UnsupportedFramework {
        let framework = snapshot
            .coverage
            .get(
                ProjectCoverageSubjectKind::Framework,
                "fastify",
                PackCoverageDimension::BusinessLogic,
            )
            .expect("unsupported Fastify business-logic row");
        assert_eq!(framework.state, CoverageState::Unsupported);
        let project = snapshot
            .coverage
            .get(
                ProjectCoverageSubjectKind::Project,
                R3_BUSINESS_LOGIC_PROVIDER,
                PackCoverageDimension::BusinessLogic,
            )
            .expect("project R3 capability row");
        assert_eq!(project.state, CoverageState::Unavailable);
    }

    build_init_output(&snapshot, ".", 0).unwrap()
}

fn explain(
    case: FixtureCase,
    registered: &sentrdel_cli::review::business_logic::RegisteredBusinessLogicReviewOutput,
) -> Option<String> {
    let finding = registered.output().findings().first()?.clone();
    let output = ExplainOutput::new(
        1,
        finding,
        repository(case),
        ImpactComponents::new("request actor", "data operation", "protected resource").unwrap(),
        registered.output().envelope().coverage.clone(),
        CliTiming::default(),
        None,
    )
    .unwrap();
    let context = BusinessLogicExplainContext::from_output(&output, registered.context())
        .unwrap()
        .expect("R3 Finding must match its exact bounded path/invariant context");
    Some(render_explain_human_with_business_logic_context(
        &output,
        Some(&context),
    ))
}

#[test]
fn fixture_bytes_drive_real_extraction_and_preserve_fail_visible_differences() {
    let safe = source_fixture_snapshot(FixtureCase::Safe);
    let vulnerable = source_fixture_snapshot(FixtureCase::Vulnerable);

    assert!(
        safe.actor_identities
            .contains(&ActorIdentityKind::AuthenticatedUser)
    );
    assert!(!vulnerable
        .actor_identities
        .contains(&ActorIdentityKind::AuthenticatedUser));
    assert!(safe.value_kinds.contains(&ValueOriginKind::AuthenticatedUserId));
    assert!(!vulnerable
        .value_kinds
        .contains(&ValueOriginKind::AuthenticatedUserId));
    assert_eq!(safe.data_states, vec![CoverageState::Partial]);
    assert_eq!(vulnerable.data_states, vec![CoverageState::Covered]);
    assert_eq!(safe.data_filter_counts, vec![2]);
    assert_eq!(vulnerable.data_filter_counts, vec![1]);

    for case in FixtureCase::ALL {
        assert_eq!(
            source_fixture_snapshot(case),
            source_fixture_snapshot(case),
            "source extraction replay drift for {}",
            case.slug()
        );
    }
}

#[test]
fn admitted_semantics_have_production_correlator_and_invariant_states() {
    let safe = analyze_fixture(FixtureCase::Safe);
    let vulnerable = analyze_fixture(FixtureCase::Vulnerable);
    let unknown = analyze_fixture(FixtureCase::ContradictoryUnknown);

    assert_eq!(
        safe.evaluations[0].state(),
        InvariantEvaluationState::Satisfied
    );
    assert_eq!(
        vulnerable.evaluations[0].state(),
        InvariantEvaluationState::Violated
    );
    assert_eq!(
        unknown.evaluations[0].state(),
        InvariantEvaluationState::Unknown
    );
    assert_eq!(safe.paths[0].path_state(), PathState::Supported);
    assert_eq!(vulnerable.paths[0].path_state(), PathState::Supported);
    assert_eq!(unknown.paths[0].path_state(), PathState::Partial);
}

#[test]
fn r3_fixture_matrix_has_deterministic_review_init_and_explain_behavior() {
    for case in FixtureCase::ALL {
        let first_analysis = analyze_fixture(case);
        let second_analysis = analyze_fixture(case);
        assert_eq!(
            first_analysis,
            second_analysis,
            "analysis replay drift for {}",
            case.slug()
        );

        let first_review = review(case, &first_analysis);
        let second_review = review(case, &second_analysis);
        assert_eq!(
            first_review.render_json().unwrap(),
            second_review.render_json().unwrap(),
            "review JSON replay drift for {}",
            case.slug()
        );
        assert_eq!(
            first_review.render_human(true),
            second_review.render_human(true),
            "review human replay drift for {}",
            case.slug()
        );

        let first_init = init(case);
        let second_init = init(case);
        assert_eq!(
            first_init,
            second_init,
            "init replay drift for {}",
            case.slug()
        );

        let first_explain = explain(case, &first_review);
        let second_explain = explain(case, &second_review);
        assert_eq!(
            first_explain,
            second_explain,
            "explain replay drift for {}",
            case.slug()
        );

        match case {
            FixtureCase::Vulnerable => {
                assert_eq!(first_review.output().envelope().decision, CliDecision::Ask);
                assert_eq!(first_review.output().findings().len(), 1);
                let rendered = first_explain.expect("violated admitted semantics are explainable");
                assert!(rendered.contains("[VIOLATED]"));
                assert!(rendered.contains("R2 supporting Evidence"));
                assert!(rendered.contains("does not prove runtime exploitability"));
                assert!(rendered.contains("reconciler remain the verdict authority"));
            }
            FixtureCase::Safe => {
                assert!(first_review.output().findings().is_empty());
                assert!(first_explain.is_none());
            }
            FixtureCase::ContradictoryUnknown => {
                assert!(first_review.output().findings().is_empty());
                assert!(first_explain.is_none());
            }
            FixtureCase::UnsupportedSemanticLink
            | FixtureCase::UnsupportedFramework
            | FixtureCase::HostileRepository => {
                assert!(first_analysis.paths.is_empty());
                assert!(first_analysis.evaluations.is_empty());
                assert!(first_review.output().findings().is_empty());
                assert!(first_explain.is_none());
            }
        }
    }
}

#[test]
fn hostile_repository_and_project_invariant_authority_attempts_remain_inert() {
    assert!(HOSTILE_README.contains("SENTRDEL_CANARY"));
    assert!(HOSTILE_README.contains("Ignore previous instructions"));

    let load = load_project_invariants(
        Some(FORBIDDEN_AUTHORITY_INVARIANTS),
        &normalized_path(PROJECT_INVARIANT_PATH),
        &format!("sha256:{}", "b".repeat(64)),
        ProjectInvariantLimits::default(),
        BusinessLogicLimits::default(),
    );
    assert_eq!(load.state(), ProjectInvariantLoadState::Rejected);
    assert!(load.definitions().is_empty());
    assert!(!load.diagnostics().is_empty());

    const { assert!(!TARGET_BUILD_EXECUTION_ALLOWED) };
    const { assert!(!R3_BUSINESS_LOGIC_CREATES_FINDINGS) };
    const { assert!(!R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS) };
    const { assert!(!R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY) };
    const { assert!(!PROJECT_INVARIANT_CREATES_FINDINGS) };
    const { assert!(!PROJECT_INVARIANT_EXECUTES_TARGET_CODE) };
    const { assert!(!PROJECT_INVARIANT_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!PROJECT_INVARIANT_REQUESTS_PROVIDER_CREDENTIALS) };
    const { assert!(!PROJECT_INVARIANT_PARSE_FAILURE_DISABLES_BUILTINS) };
    const { assert!(!PROJECT_INVARIANT_CAN_WEAKEN_BUILTINS) };
}
