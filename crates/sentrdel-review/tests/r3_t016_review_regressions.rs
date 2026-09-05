use sentrdel_review::{
    business_logic::{
        link::{
            AdmittedScipReference, LinkDocument, LinkingDiagnosticReason, LinkingError,
            ScipProducerBasis, ScipSemanticInput, link_inter_file_semantics,
        },
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

fn semantic_id(namespace: &str, value: &str) -> StableSemanticId {
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
        semantic_id("route", importer),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/fixture",
        Some("handler".to_owned()),
        vec![semantic_id("callback", importer)],
        vec![provenance(importer)],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("route observation")
}

fn document(value: &str, source: &str) -> LinkDocument {
    LinkDocument::new(
        path(value),
        StructuralLanguage::TypeScript,
        source.as_bytes().to_vec(),
    )
    .expect("link document")
}

fn canonical_digest() -> String {
    format!("sha256:{}", "a".repeat(64))
}

#[test]
fn missing_route_source_document_is_partial_and_explicit() {
    let result = link_inter_file_semantics(
        &[route("src/routes.ts")],
        &[],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("linking result");

    assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::MissingRouteDocument
    }));
}

#[test]
fn multiple_route_provenance_documents_are_ambiguous_not_first_path_join() {
    let ambiguous_route = RouteObservation::new(
        semantic_id("route", "ambiguous-source"),
        FrameworkFamily::Express,
        HttpMethod::Get,
        "/fixture",
        Some("handler".to_owned()),
        vec![semantic_id("callback", "ambiguous-source")],
        vec![provenance("src/routes.ts"), provenance("src/a.ts")],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous route observation");
    let result = link_inter_file_semantics(
        &[ambiguous_route],
        &[
            document(
                "src/a.ts",
                "import { handler } from './handlers.ts';\nexport const unrelated = handler;",
            ),
            document("src/routes.ts", "app.get('/fixture', handler);"),
            document("src/handlers.ts", "export function handler() {}"),
        ],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous route document linking");

    assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
    assert!(result.diagnostics().iter().any(|diagnostic| {
        diagnostic.reason() == LinkingDiagnosticReason::AmbiguousRouteDocument
    }));
    assert!(
        !result
            .links()
            .iter()
            .any(|link| link.basis() == LinkBasis::SupportedImportBinding)
    );
}

#[test]
fn duplicate_route_input_is_bounded_before_link_deduplication() {
    let repeated = route("src/routes.ts");
    let routes = vec![repeated; MAX_ROUTE_OBSERVATIONS + 1];
    let error = link_inter_file_semantics(
        &routes,
        &[],
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect_err("route input cap must fail closed");

    assert!(matches!(
        error,
        LinkingError::TooManyRoutes { count, max }
            if count == MAX_ROUTE_OBSERVATIONS + 1 && max == MAX_ROUTE_OBSERVATIONS
    ));
}

#[test]
fn admitted_scip_metadata_matches_existing_canonical_boundary() {
    let source = semantic_id("scip-source", "source");
    let target = semantic_id("scip-target", "target");
    let source_provenance = vec![provenance("src/routes.ts")];

    for qualification_id in ["", "   ", "SCIPQ-invalid\ncontrol"] {
        let error = AdmittedScipReference::new(
            source.clone(),
            target.clone(),
            qualification_id,
            canonical_digest(),
            ScipProducerBasis::CompilerBacked,
            source_provenance.clone(),
            BusinessLogicLimits::default(),
        )
        .expect_err("invalid qualification metadata must fail closed");
        assert!(matches!(error, LinkingError::InvalidScipQualificationId));
    }

    for digest in [
        "sha256:abc".to_owned(),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
    ] {
        let error = AdmittedScipReference::new(
            source.clone(),
            target.clone(),
            "SCIPQ-qualified-compiler",
            digest,
            ScipProducerBasis::CompilerBacked,
            source_provenance.clone(),
            BusinessLogicLimits::default(),
        )
        .expect_err("malformed artifact digest must fail closed");
        assert!(matches!(error, LinkingError::InvalidScipArtifactDigest));
    }

    AdmittedScipReference::new(
        source,
        target,
        "SCIPQ-qualified-compiler",
        canonical_digest(),
        ScipProducerBasis::CompilerBacked,
        source_provenance,
        BusinessLogicLimits::default(),
    )
    .expect("canonical admitted SCIP metadata remains accepted");
}
