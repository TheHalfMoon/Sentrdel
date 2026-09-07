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
        R3_BUSINESS_LOGIC_PROVIDER, register_r3_pack,
        coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS,
        invariant::ProjectInvariantLimits,
        model::{
            BusinessLogicCoverage, BusinessLogicLimits, CrossLayerPath, InvariantEvaluation,
            InvariantEvaluationState, PathState, StableSemanticId,
        },
        producer::{
            BusinessLogicProducerOutput, R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY,
            R3_BUSINESS_LOGIC_CREATES_FINDINGS, R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE,
            R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS, R3_BUSINESS_LOGIC_PRODUCER_ID,
            R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS, produce_business_logic_outputs,
        },
        project_invariant::{
            PROJECT_INVARIANT_CAN_WEAKEN_BUILTINS, PROJECT_INVARIANT_CREATES_FINDINGS,
            PROJECT_INVARIANT_EXECUTES_TARGET_CODE, PROJECT_INVARIANT_PARSE_FAILURE_DISABLES_BUILTINS,
            PROJECT_INVARIANT_PATH, PROJECT_INVARIANT_PERFORMS_NETWORK_ACCESS,
            PROJECT_INVARIANT_REQUESTS_PROVIDER_CREDENTIALS, ProjectInvariantLoadState,
            load_project_invariants,
        },
        route::{RouteAdapter, RouteCoverageGapReason, extract_routes},
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

    const fn expected_state(self) -> InvariantEvaluationState {
        match self {
            Self::Safe => InvariantEvaluationState::Satisfied,
            Self::Vulnerable => InvariantEvaluationState::Violated,
            Self::ContradictoryUnknown
            | Self::UnsupportedSemanticLink
            | Self::UnsupportedFramework
            | Self::HostileRepository => InvariantEvaluationState::Unknown,
        }
    }

    const fn expected_coverage(self) -> CoverageState {
        match self {
            Self::Safe | Self::Vulnerable => CoverageState::Covered,
            Self::ContradictoryUnknown
            | Self::UnsupportedSemanticLink
            | Self::HostileRepository => CoverageState::Partial,
            Self::UnsupportedFramework => CoverageState::Unsupported,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct FixtureAnalysis {
    routes: Vec<sentrdel_review::business_logic::model::RouteObservation>,
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

fn route_result(case: FixtureCase) -> Vec<sentrdel_review::business_logic::model::RouteObservation> {
    let extraction = match case {
        FixtureCase::Safe | FixtureCase::Vulnerable => Some(extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &normalized_path(case.path()),
            case.source().as_bytes(),
            BusinessLogicLimits::default(),
        )),
        FixtureCase::ContradictoryUnknown => Some(extract_routes(
            RouteAdapter::NextPagesApi,
            StructuralLanguage::JavaScript,
            &normalized_path(case.path()),
            case.source().as_bytes(),
            BusinessLogicLimits::default(),
        )),
        FixtureCase::UnsupportedSemanticLink => {
            let result = extract_routes(
                RouteAdapter::Express,
                StructuralLanguage::JavaScript,
                &normalized_path(case.path()),
                case.source().as_bytes(),
                BusinessLogicLimits::default(),
            )
            .unwrap();
            assert!(result.routes().is_empty());
            assert!(result.gaps().iter().any(|gap| {
                gap.reason() == RouteCoverageGapReason::DynamicRegistration
                    || gap.reason() == RouteCoverageGapReason::DynamicRoutePattern
            }));
            return Vec::new();
        }
        FixtureCase::UnsupportedFramework => {
            assert!(case.source().contains("fastify.route"));
            return Vec::new();
        }
        FixtureCase::HostileRepository => {
            assert!(case.source().contains("SENTRDEL_CANARY"));
            return Vec::new();
        }
    };
    let result = extraction.expect("supported fixture extraction").unwrap();
    assert_eq!(result.routes().len(), 1, "{} route count", case.slug());
    if case == FixtureCase::ContradictoryUnknown {
        assert_eq!(result.routes()[0].coverage_state(), &CoverageState::Partial);
    }
    result.routes().to_vec()
}

fn analyze_fixture(case: FixtureCase) -> FixtureAnalysis {
    let routes = route_result(case);
    let mut paths = Vec::new();
    let mut evaluations = Vec::new();

    if let Some(route) = routes.first() {
        let path_id = id("r3.t030.path", case.slug());
        let state = if case == FixtureCase::ContradictoryUnknown {
            PathState::Partial
        } else {
            PathState::Supported
        };
        let guard_id = id("r3.t030.guard", case.slug());
        paths.push(
            CrossLayerPath::new(
                path_id.clone(),
                route.route_id().clone(),
                vec![id("r3.t030.actor", case.slug())],
                vec![guard_id.clone()],
                id("r3.t030.operation", case.slug()),
                None,
                Vec::new(),
                vec![format!("evidence:r2:t030:{}", case.slug())],
                state,
                route.provenance().to_vec(),
                BusinessLogicLimits::default(),
            )
            .unwrap(),
        );
        evaluations.push(
            InvariantEvaluation::new(
                id("r3.t030.evaluation", case.slug()),
                id("r3.t030.invariant", case.slug()),
                Some(path_id),
                case.expected_state(),
                vec![guard_id],
                Vec::new(),
                if case.expected_state() == InvariantEvaluationState::Unknown {
                    vec!["STATIC_SCOPE_OR_LINKING_INCOMPLETE".to_owned()]
                } else {
                    vec!["STATIC_SCOPE_ONLY".to_owned()]
                },
                route.provenance().to_vec(),
                BusinessLogicLimits::default(),
            )
            .unwrap(),
        );
    }

    let coverage = REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
        .into_iter()
        .map(|area| {
            BusinessLogicCoverage::new(
                area,
                case.expected_coverage(),
                format!("R3_T030_{}", case.slug().replace('-', "_").to_uppercase()),
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
        routes,
        paths,
        evaluations,
        producer,
    }
}

fn reconciled_findings(case: FixtureCase, producer: &BusinessLogicProducerOutput) -> Vec<Finding> {
    if case != FixtureCase::Vulnerable {
        return Vec::new();
    }
    let interpretation = producer
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

fn review(case: FixtureCase, analysis: &FixtureAnalysis) -> sentrdel_cli::review::business_logic::RegisteredBusinessLogicReviewOutput {
    let findings = reconciled_findings(case, &analysis.producer);
    let baseline = ReviewOutput::new(
        repository(case),
        if findings.is_empty() { CliDecision::Allow } else { CliDecision::Ask },
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
            &analysis.routes,
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
    let snapshot = build_project_profile_snapshot(
        format!("fixture:r3-t030:{}", case.slug()),
        format!("sha256:{}", "a".repeat(64)),
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

fn explain(case: FixtureCase, registered: &sentrdel_cli::review::business_logic::RegisteredBusinessLogicReviewOutput) -> Option<String> {
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
fn r3_fixture_matrix_has_deterministic_review_init_and_explain_behavior() {
    for case in FixtureCase::ALL {
        let first_analysis = analyze_fixture(case);
        let second_analysis = analyze_fixture(case);
        assert_eq!(first_analysis, second_analysis, "analysis replay drift for {}", case.slug());

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
        assert_eq!(first_init, second_init, "init replay drift for {}", case.slug());

        let first_explain = explain(case, &first_review);
        let second_explain = explain(case, &second_review);
        assert_eq!(first_explain, second_explain, "explain replay drift for {}", case.slug());

        match case {
            FixtureCase::Vulnerable => {
                assert_eq!(first_review.output().envelope().decision, CliDecision::Ask);
                assert_eq!(first_review.output().findings().len(), 1);
                let rendered = first_explain.expect("vulnerable fixture has an explainable Finding");
                assert!(rendered.contains("[VIOLATED]"));
                assert!(rendered.contains("R2 supporting Evidence"));
                assert!(rendered.contains("does not prove runtime exploitability"));
                assert!(rendered.contains("reconciler remain the verdict authority"));
            }
            FixtureCase::Safe => {
                assert_eq!(first_analysis.evaluations[0].state(), InvariantEvaluationState::Satisfied);
                assert!(first_review.output().findings().is_empty());
                assert!(first_explain.is_none());
            }
            FixtureCase::ContradictoryUnknown => {
                assert_eq!(first_analysis.evaluations[0].state(), InvariantEvaluationState::Unknown);
                assert_eq!(first_analysis.paths[0].path_state(), PathState::Partial);
                assert!(first_review.output().findings().is_empty());
            }
            FixtureCase::UnsupportedSemanticLink | FixtureCase::UnsupportedFramework | FixtureCase::HostileRepository => {
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
    assert!(HOSTILE_README.contains("SYSTEM"));

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