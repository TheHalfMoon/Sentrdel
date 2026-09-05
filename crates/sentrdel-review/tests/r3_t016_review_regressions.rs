use sentrdel_review::{
    business_logic::{
        link::{LinkDocument, LinkingDiagnosticReason, LinkingError, link_inter_file_semantics},
        model::{
            BusinessLogicLimits, FrameworkFamily, HttpMethod, LinkBasis, RouteObservation,
            SourceLocation, StableSemanticId,
        },
        route::MAX_ROUTE_OBSERVATIONS,
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

fn route(importer: &str) -> RouteObservation {
    RouteObservation::new(
        id("route", importer),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/fixture",
        Some("handler".to_owned()),
        vec![id("callback", importer)],
        vec![provenance(importer)],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("route observation")
}

fn route_with_provenance(paths: &[&str]) -> RouteObservation {
    RouteObservation::new(
        id("route", "multi-provenance"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/fixture",
        Some("handler".to_owned()),
        vec![id("callback", "multi-provenance")],
        paths.iter().map(|value| provenance(value)).collect(),
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("route observation")
}

fn document_with_language(
    value: &str,
    language: StructuralLanguage,
    source: &str,
) -> LinkDocument {
    LinkDocument::new(path(value), language, source.as_bytes().to_vec()).expect("link document")
}

fn document(value: &str, source: &str) -> LinkDocument {
    document_with_language(value, StructuralLanguage::TypeScript, source)
}

fn has_import_link(result: &sentrdel_review::business_logic::link::LinkingResult) -> bool {
    result
        .links()
        .iter()
        .any(|link| link.basis() == LinkBasis::SupportedImportBinding)
}

#[test]
fn missing_route_source_document_is_partial_and_explicit() {
    let result = link_inter_file_semantics(
        &[route("src/routes.ts")],
        &[],
        BusinessLogicLimits::default(),
    )
    .expect("linking result");

    assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::MissingRouteDocument
    }));
}

#[test]
fn duplicate_route_input_is_bounded_before_link_deduplication() {
    let repeated = route("src/routes.ts");
    let routes = vec![repeated; MAX_ROUTE_OBSERVATIONS + 1];
    let error = link_inter_file_semantics(&routes, &[], BusinessLogicLimits::default())
        .expect_err("route input cap must fail closed");

    assert!(matches!(
        error,
        LinkingError::TooManyRoutes { count, max }
            if count == MAX_ROUTE_OBSERVATIONS + 1 && max == MAX_ROUTE_OBSERVATIONS
    ));
}

#[test]
fn multiple_route_provenance_documents_cannot_choose_lexical_first_importer() {
    let result = link_inter_file_semantics(
        &[route_with_provenance(&["src/a.ts", "src/routes.ts"])],
        &[
            document(
                "src/a.ts",
                "import { handler } from './handlers.ts';\napp.get('/fixture', handler);",
            ),
            document(
                "src/routes.ts",
                "import { handler } from './other.ts';\napp.get('/fixture', handler);",
            ),
            document("src/handlers.ts", "export function handler() {}"),
            document("src/other.ts", "export function handler() {}"),
        ],
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous route document");

    assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
    assert!(!has_import_link(&result));
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::AmbiguousRouteDocument
    }));
}

#[test]
fn callback_shadowing_forms_never_resolve_to_top_level_import() {
    let cases = [
        "import { handler } from './handlers.ts';\nfunction register(handler) { app.get('/fixture', handler); }",
        "import { handler } from './handlers.ts';\n{ const handler = () => {}; app.get('/fixture', handler); }",
        "import { handler } from './handlers.ts';\ntry { throw 1; } catch (handler) { app.get('/fixture', handler); }",
        "import { handler } from './handlers.ts';\napp.get('/fixture', handler);\nfunction handler() {}",
    ];

    for source in cases {
        let result = link_inter_file_semantics(
            &[route("src/routes.ts")],
            &[
                document("src/routes.ts", source),
                document("src/handlers.ts", "export function handler() {}"),
            ],
            BusinessLogicLimits::default(),
        )
        .expect("shadowed callback linking");

        assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
        assert!(!has_import_link(&result));
        assert!(result.diagnostics().iter().any(|diagnostic| {
            diagnostic.reason() == LinkingDiagnosticReason::ShadowedImportBinding
        }));
    }
}

#[test]
fn bare_arrow_parameters_never_resolve_to_top_level_imports() {
    let cases = [
        (
            StructuralLanguage::JavaScript,
            "src/routes.js",
            "src/handlers.js",
            "import { handler } from './handlers.js';\nconst register = handler => app.get('/fixture', handler);",
        ),
        (
            StructuralLanguage::TypeScript,
            "src/routes.ts",
            "src/handlers.ts",
            "import { handler } from './handlers.ts';\nconst register = handler => app.get('/fixture', handler);",
        ),
    ];

    for (language, importer, target, source) in cases {
        let result = link_inter_file_semantics(
            &[route(importer)],
            &[
                document_with_language(importer, language, source),
                document_with_language(target, language, "export function handler() {}"),
            ],
            BusinessLogicLimits::default(),
        )
        .expect("bare arrow shadowing must remain visible");

        assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
        assert!(!has_import_link(&result));
        assert!(result.diagnostics().iter().any(|diagnostic| {
            diagnostic.reason() == LinkingDiagnosticReason::ShadowedImportBinding
        }));
    }
}

#[test]
fn indirect_named_and_default_reexports_are_not_direct_target_exports() {
    let named = link_inter_file_semantics(
        &[route("src/routes.ts")],
        &[
            document(
                "src/routes.ts",
                "import { handler } from './middle.ts';\napp.get('/fixture', handler);",
            ),
            document(
                "src/middle.ts",
                "import { realHandler } from './real.ts';\nexport { realHandler as handler };",
            ),
            document("src/real.ts", "export function realHandler() {}"),
        ],
        BusinessLogicLimits::default(),
    )
    .expect("named forwarding");
    assert_eq!(named.coverage().local_state(), &CoverageState::Partial);
    assert!(!has_import_link(&named));
    assert!(named.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::UnsupportedTargetExport
    }));

    let default = link_inter_file_semantics(
        &[route("src/routes.ts")],
        &[
            document(
                "src/routes.ts",
                "import handler from './middle.ts';\napp.get('/fixture', handler);",
            ),
            document(
                "src/middle.ts",
                "import realHandler from './real.ts';\nexport default realHandler;",
            ),
            document("src/real.ts", "export default function realHandler() {}"),
        ],
        BusinessLogicLimits::default(),
    )
    .expect("default forwarding");
    assert_eq!(default.coverage().local_state(), &CoverageState::Partial);
    assert!(!has_import_link(&default));
    assert!(default.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::UnsupportedTargetExport
    }));
}
