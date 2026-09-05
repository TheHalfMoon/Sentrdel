use sentrdel_graph::{
    ScipArtifact, ScipDocument, ScipIngestionRequest, ScipOccurrence, ScipOccurrenceRole,
    ScipPosition, ScipProducerQualification, ScipRange, ingest_scip,
};
use sentrdel_review::{
    business_logic::{
        link::{
            LinkDocument, LinkingDiagnosticReason, LinkingError, ScipSemanticInput,
            link_inter_file_semantics,
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

fn scip_input(qualification: ScipProducerQualification, complete: bool) -> ScipSemanticInput {
    let ingestion = ingest_scip(ScipIngestionRequest {
        artifact: ScipArtifact {
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            producer_name: "fixture-scip".to_owned(),
            producer_version: Some("1.0.0".to_owned()),
            documents: vec![ScipDocument {
                relative_path: "src/routes.ts".to_owned(),
                language: "typescript".to_owned(),
                occurrences: vec![ScipOccurrence {
                    symbol: "typescript npm fixture 1.0.0 handler().".to_owned(),
                    range: ScipRange {
                        start: ScipPosition {
                            line: 0,
                            character: 0,
                        },
                        end: ScipPosition {
                            line: 0,
                            character: 7,
                        },
                    },
                    role: ScipOccurrenceRole::Reference,
                }],
            }],
        },
        producer_qualification: qualification,
        scope: ".".to_owned(),
        observed_at: "2026-09-05T00:00:00Z".to_owned(),
    })
    .expect("canonical SCIP ingestion");
    ScipSemanticInput::Admitted {
        ingestion,
        provenance: vec![provenance("src/routes.ts")],
        complete,
    }
}

#[test]
fn explicit_relative_named_import_links_exact_callback_and_direct_export() {
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
fn unsupported_module_forms_remain_partial_and_never_guess_identity() {
    for source in [
        "import { handler } from '@scope/pkg';\napp.get('/fixture', handler);",
        "import { handler } from './handlers';\napp.get('/fixture', handler);",
        "import { handler } from '../../outside.ts';\napp.get('/fixture', handler);",
        "import * as handlers from './handlers.ts';\napp.get('/fixture', handlers.handler);",
    ] {
        let result = link_inter_file_semantics(
            &[route("src/routes.ts", "handler")],
            &[document("src/routes.ts", source)],
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("bounded linking");

        assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
        assert!(
            !result
                .links()
                .iter()
                .any(|link| link.basis() == LinkBasis::SupportedImportBinding)
        );
    }
}

#[test]
fn dynamic_import_is_visible_and_never_clean() {
    let result = link_inter_file_semantics(
        &[route("src/routes.ts", "handler")],
        &[
            document(
                "src/routes.ts",
                "const m = import('./handlers.ts');\napp.get('/fixture', handler);",
            ),
            document("src/handlers.ts", "export function handler() {}"),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("dynamic linking");

    assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::DynamicImportBinding
    }));
}

#[test]
fn canonical_scip_ingestion_controls_confidence_and_coverage() {
    let compiler = link_inter_file_semantics(
        &[],
        &[],
        scip_input(
            ScipProducerQualification::CompilerBacked {
                qualification_id: "SCIPQ-fixture-compiler".to_owned(),
            },
            true,
        ),
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
        scip_input(
            ScipProducerQualification::Heuristic {
                qualification_id: "SCIPQ-fixture-heuristic".to_owned(),
            },
            true,
        ),
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
}

#[test]
fn deterministic_replay_and_resource_caps_fail_closed() {
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
    let link_error =
        link_inter_file_semantics(&[two_callbacks], &[], ScipSemanticInput::Unavailable, tiny)
            .expect_err("link cap must fail");
    assert!(matches!(
        link_error,
        LinkingError::TooManyLinks { count: 2, max: 1 }
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
