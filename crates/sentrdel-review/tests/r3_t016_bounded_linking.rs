use sentrdel_review::{
    business_logic::{
        link::{
            AdmittedScipReference, LinkDocument, LinkingDiagnosticReason, LinkingError,
            ScipProducerBasis, ScipSemanticInput, link_inter_file_semantics,
        },
        model::{
            BusinessLogicLimits, ConfidenceBasis, FrameworkFamily, HttpMethod, LinkBasis,
            RouteObservation, SourceLocation, StableSemanticId,
        },
    },
    structural::StructuralLanguage,
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::coverage::CoverageState;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path")
}

fn id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
        .expect("stable semantic id")
}

fn provenance(value: &str) -> SourceLocation {
    SourceLocation::new(
        path(value),
        0,
        1,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("source provenance")
}

fn route_with(
    importer: &str,
    handler: Option<&str>,
    callbacks: Vec<StableSemanticId>,
    coverage: CoverageState,
) -> RouteObservation {
    RouteObservation::new(
        id("route", importer),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/fixture",
        handler.map(str::to_owned),
        callbacks,
        vec![provenance(importer)],
        coverage,
        BusinessLogicLimits::default(),
    )
    .expect("route observation")
}

fn route(importer: &str, handler: &str) -> RouteObservation {
    route_with(
        importer,
        Some(handler),
        vec![id("callback", &format!("{importer}:{handler}"))],
        CoverageState::Covered,
    )
}

fn document(value: &str, source: &str) -> LinkDocument {
    LinkDocument::new(
        path(value),
        StructuralLanguage::TypeScript,
        source.as_bytes().to_vec(),
    )
    .expect("link document")
}

fn scip_reference(
    suffix: &str,
    producer_basis: ScipProducerBasis,
) -> AdmittedScipReference {
    AdmittedScipReference::new(
        id("scip-source", suffix),
        id("scip-target", suffix),
        format!("qualified-{suffix}"),
        format!("sha256:{:0>64}", suffix),
        producer_basis,
        vec![provenance("src/routes.ts")],
        BusinessLogicLimits::default(),
    )
    .expect("admitted SCIP reference")
}

#[test]
fn explicit_relative_named_import_links_exact_callback_and_export() {
    let result = link_inter_file_semantics(
        &[route("src/routes.ts", "handler")],
        &[
            document(
                "src/routes.ts",
                "import { handler } from './handlers.ts';\napp.get('/fixture', handler);",
            ),
            document(
                "src/handlers.ts",
                "export function handler(req, res) { return res.json({ ok: true }); }",
            ),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("bounded linking");

    assert_eq!(result.coverage().local_state(), &CoverageState::Covered);
    assert_eq!(
        result.coverage().semantic_state(),
        &CoverageState::Unavailable
    );
    assert!(result.links().iter().any(|link| {
        link.basis() == LinkBasis::SupportedCallbackChain
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
    assert!(result.links().iter().any(|link| {
        link.basis() == LinkBasis::SupportedImportBinding
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
}

#[test]
fn package_extensionless_and_repository_escape_imports_are_partial_not_guessed() {
    for source in [
        "import { handler } from '@scope/pkg';\napp.get('/fixture', handler);",
        "import { handler } from './handlers';\napp.get('/fixture', handler);",
        "import { handler } from '../../outside.ts';\napp.get('/fixture', handler);",
    ] {
        let result = link_inter_file_semantics(
            &[route("src/routes.ts", "handler")],
            &[document("src/routes.ts", source)],
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("bounded linking");

        assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
        assert!(result.diagnostics().iter().any(|diagnostic| {
            diagnostic.reason() == LinkingDiagnosticReason::UnsupportedModuleSpecifier
        }));
        assert!(!result
            .links()
            .iter()
            .any(|link| link.basis() == LinkBasis::SupportedImportBinding));
    }
}

#[test]
fn namespace_and_dynamic_imports_remain_visible_local_coverage_gaps() {
    let namespace = link_inter_file_semantics(
        &[route("src/routes.ts", "handlers.handler")],
        &[
            document(
                "src/routes.ts",
                "import * as handlers from './handlers.ts';\napp.get('/fixture', handlers.handler);",
            ),
            document("src/handlers.ts", "export function handler() {}"),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("namespace linking");
    assert_eq!(namespace.coverage().local_state(), &CoverageState::Partial);
    assert!(namespace.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::UnsupportedImportBinding
    }));

    let dynamic = link_inter_file_semantics(
        &[route("src/routes.ts", "handler")],
        &[
            document(
                "src/routes.ts",
                "const modulePromise = import('./handlers.ts');\nconst handler = async (...args) => (await modulePromise).handler(...args);\napp.get('/fixture', handler);",
            ),
            document("src/handlers.ts", "export function handler() {}"),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("dynamic linking");
    assert_eq!(dynamic.coverage().local_state(), &CoverageState::Partial);
    assert!(dynamic.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::DynamicImportBinding
    }));
}

#[test]
fn missing_and_ambiguous_targets_never_mint_import_links() {
    let missing_document = link_inter_file_semantics(
        &[route("src/routes.ts", "handler")],
        &[document(
            "src/routes.ts",
            "import { handler } from './handlers.ts';\napp.get('/fixture', handler);",
        )],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("missing target document");
    assert_eq!(
        missing_document.coverage().local_state(),
        &CoverageState::Partial
    );
    assert!(missing_document.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::MissingTargetDocument
    }));

    let ambiguous_export = link_inter_file_semantics(
        &[route("src/routes.ts", "handler")],
        &[
            document(
                "src/routes.ts",
                "import { handler } from './handlers.ts';\napp.get('/fixture', handler);",
            ),
            document(
                "src/handlers.ts",
                "export function handler() {}\nexport function handler() {}",
            ),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous export");
    assert_eq!(
        ambiguous_export.coverage().local_state(),
        &CoverageState::Partial
    );
    assert!(ambiguous_export.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::AmbiguousTargetExport
    }));
    assert!(!ambiguous_export
        .links()
        .iter()
        .any(|link| link.basis() == LinkBasis::SupportedImportBinding));
}

#[test]
fn same_raw_handler_name_without_import_never_creates_cross_file_false_join() {
    let result = link_inter_file_semantics(
        &[route("src/routes.ts", "handler")],
        &[
            document(
                "src/routes.ts",
                "function handler() {}\napp.get('/fixture', handler);",
            ),
            document("src/unrelated.ts", "export function handler() {}"),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("bounded linking");

    assert!(!result
        .links()
        .iter()
        .any(|link| link.basis() == LinkBasis::SupportedImportBinding));
}

#[test]
fn partial_route_observation_cannot_become_clean_local_linking() {
    let route = route_with(
        "src/routes.ts",
        Some("handler"),
        vec![id("callback", "partial")],
        CoverageState::Partial,
    );
    let result = link_inter_file_semantics(
        &[route],
        &[document(
            "src/routes.ts",
            "function handler() {}\napp.get('/fixture', handler);",
        )],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("partial route linking");

    assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::IncompleteRouteObservation
    }));
}

#[test]
fn compiler_backed_scip_is_extracted_while_heuristic_or_absent_is_not_clean() {
    let compiler = link_inter_file_semantics(
        &[],
        &[],
        ScipSemanticInput::Admitted {
            references: vec![scip_reference("1", ScipProducerBasis::CompilerBacked)],
            complete: true,
        },
        BusinessLogicLimits::default(),
    )
    .expect("compiler-backed SCIP");
    assert_eq!(
        compiler.coverage().semantic_state(),
        &CoverageState::Covered
    );
    assert!(compiler.links().iter().any(|link| {
        link.basis() == LinkBasis::ScipReference
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));

    let heuristic = link_inter_file_semantics(
        &[],
        &[],
        ScipSemanticInput::Admitted {
            references: vec![scip_reference("2", ScipProducerBasis::Heuristic)],
            complete: true,
        },
        BusinessLogicLimits::default(),
    )
    .expect("heuristic SCIP");
    assert_eq!(
        heuristic.coverage().semantic_state(),
        &CoverageState::Partial
    );
    assert!(heuristic.links().iter().any(|link| {
        link.basis() == LinkBasis::ScipReference
            && link.confidence_basis() == ConfidenceBasis::Inferred
    }));

    let unavailable = link_inter_file_semantics(
        &[],
        &[],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("unavailable SCIP");
    assert_eq!(
        unavailable.coverage().semantic_state(),
        &CoverageState::Unavailable
    );
    assert!(!unavailable
        .links()
        .iter()
        .any(|link| link.basis() == LinkBasis::ScipReference));
}

#[test]
fn output_is_deterministic_for_identical_inputs() {
    let routes = vec![route("src/routes.ts", "handler")];
    let documents = vec![
        document(
            "src/routes.ts",
            "import { handler } from './handlers.ts';\napp.get('/fixture', handler);",
        ),
        document("src/handlers.ts", "export function handler() {}"),
    ];
    let first = link_inter_file_semantics(
        &routes,
        &documents,
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("first linking");
    let second = link_inter_file_semantics(
        &routes,
        &documents,
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("second linking");

    assert_eq!(first, second);
}

#[test]
fn path_candidate_and_link_caps_fail_closed() {
    let tiny = BusinessLogicLimits {
        max_path_candidates: 1,
        ..BusinessLogicLimits::default()
    };
    let document_error = link_inter_file_semantics(
        &[],
        &[
            document("src/a.ts", "export function a() {}"),
            document("src/b.ts", "export function b() {}"),
        ],
        ScipSemanticInput::Unavailable,
        tiny,
    )
    .expect_err("document cap must fail");
    assert!(matches!(
        document_error,
        LinkingError::TooManyDocuments { count: 2, max: 1 }
    ));

    let two_callbacks = route_with(
        "src/routes.ts",
        Some("handler"),
        vec![id("callback", "one"), id("callback", "two")],
        CoverageState::Covered,
    );
    let link_error = link_inter_file_semantics(
        &[two_callbacks],
        &[],
        ScipSemanticInput::Unavailable,
        tiny,
    )
    .expect_err("link cap must fail");
    assert!(matches!(
        link_error,
        LinkingError::TooManyLinks { count: 2, max: 1 }
    ));
}

#[test]
fn diagnostic_and_scip_caps_fail_closed() {
    let diagnostic_limits = BusinessLogicLimits {
        max_diagnostics: 1,
        ..BusinessLogicLimits::default()
    };
    let incomplete = route_with(
        "src/routes.ts",
        None,
        Vec::new(),
        CoverageState::Partial,
    );
    let diagnostic_error = link_inter_file_semantics(
        &[incomplete],
        &[],
        ScipSemanticInput::Unavailable,
        diagnostic_limits,
    )
    .expect_err("diagnostic cap must fail");
    assert!(matches!(
        diagnostic_error,
        LinkingError::TooManyDiagnostics { count: 2, max: 1 }
    ));

    let scip_limits = BusinessLogicLimits {
        max_path_candidates: 1,
        ..BusinessLogicLimits::default()
    };
    let scip_error = link_inter_file_semantics(
        &[],
        &[],
        ScipSemanticInput::Admitted {
            references: vec![
                scip_reference("3", ScipProducerBasis::CompilerBacked),
                scip_reference("4", ScipProducerBasis::CompilerBacked),
            ],
            complete: true,
        },
        scip_limits,
    )
    .expect_err("SCIP cap must fail");
    assert!(matches!(
        scip_error,
        LinkingError::TooManyScipReferences { count: 2, max: 1 }
    ));
}

#[test]
fn authority_canaries_remain_false() {
    use sentrdel_review::business_logic::link::{
        R3_LINK_CREATES_FINDINGS, R3_LINK_EXECUTES_TARGET_CODE, R3_LINK_PERFORMS_NETWORK_ACCESS,
        R3_LINK_QUALIFIES_SCIP_PRODUCERS,
    };

    const { assert!(!R3_LINK_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_LINK_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_LINK_QUALIFIES_SCIP_PRODUCERS) };
    const { assert!(!R3_LINK_CREATES_FINDINGS) };
}
