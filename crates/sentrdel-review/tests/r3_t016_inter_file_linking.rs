use sentrdel_review::{
    business_logic::{
        link::{
            INTER_FILE_LINKING_EXECUTES_TARGET, INTER_FILE_LINKING_REQUIRES_SCIP,
            LEXICAL_EQUALITY_PROVES_LINK_EQUIVALENCE, LinkingCoverageGapReason,
            QualifiedScipReference, REL_CALLBACK_IMPORT_BINDING, REL_CALLBACK_PRECEDES,
            REL_SCIP_REFERENCE, SCIP_QUALIFICATION_IS_INFERRED_FROM_REPOSITORY, SemanticIndexInput,
            SourceModule, link_inter_file,
        },
        model::{
            BusinessLogicLimits, ConfidenceBasis, FrameworkFamily, HttpMethod, LinkBasis,
            RouteObservation, SourceLocation, StableSemanticId,
        },
    },
    structural::StructuralLanguage,
    view::NormalizedRepoPath,
};
use sentrdel_schema::coverage::CoverageState;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized path")
}

fn id(namespace: &str, parts: &[&str]) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, parts, BusinessLogicLimits::default())
        .expect("stable semantic id")
}

fn location(path_value: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        path(path_value),
        start,
        start + 8,
        format!("sha256:{start:064x}"),
    )
    .expect("source location")
}

fn callback_id(
    framework: &str,
    source_path: &str,
    route_pattern: &str,
    index: usize,
    callback_key: &str,
) -> StableSemanticId {
    StableSemanticId::from_parts(
        "r3-route-callback",
        &[
            framework,
            source_path,
            route_pattern,
            &index.to_string(),
            callback_key,
        ],
        BusinessLogicLimits::default(),
    )
    .expect("callback id")
}

fn express_route(source_path: &str, callback_keys: &[&str]) -> RouteObservation {
    let route_pattern = "/users/:id";
    let callbacks = callback_keys
        .iter()
        .enumerate()
        .map(|(index, key)| callback_id("express", source_path, route_pattern, index, key))
        .collect();
    RouteObservation::new(
        id("r3-route", &[source_path]),
        FrameworkFamily::Express,
        HttpMethod::Get,
        route_pattern,
        callback_keys.last().map(|value| (*value).to_owned()),
        callbacks,
        vec![location(source_path, 0)],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("route")
}

#[test]
fn unique_local_import_and_callback_order_produce_bounded_links() {
    let route_source = br#"
        import { authorize as auth } from "../auth";
        app.get("/users/:id", audit, auth);
    "#;
    let auth_source = br#"export function authorize() { return true; }"#;
    let route = express_route("src/routes/users.ts", &["audit", "auth"]);
    let modules = [
        SourceModule::new(
            path("src/routes/users.ts"),
            StructuralLanguage::TypeScript,
            route_source,
        ),
        SourceModule::new(
            path("src/auth.ts"),
            StructuralLanguage::TypeScript,
            auth_source,
        ),
    ];

    let result = link_inter_file(
        &[route],
        &modules,
        SemanticIndexInput::NotProvided,
        BusinessLogicLimits::default(),
    )
    .expect("linking");

    assert_eq!(result.local_coverage(), &CoverageState::Covered);
    assert_eq!(result.semantic_coverage(), &CoverageState::Unavailable);
    assert!(result.links().iter().any(|link| {
        link.relation() == REL_CALLBACK_PRECEDES
            && link.basis() == LinkBasis::SupportedCallbackChain
    }));
    assert!(result.links().iter().any(|link| {
        link.relation() == REL_CALLBACK_IMPORT_BINDING
            && link.basis() == LinkBasis::SupportedImportBinding
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == LinkingCoverageGapReason::SemanticIndexUnavailable })
    );
}

#[test]
fn ambiguous_extension_resolution_is_partial_and_never_links() {
    let route_source = br#"
        import { authorize as auth } from "../auth";
        app.get("/users/:id", auth);
    "#;
    let route = express_route("src/routes/users.ts", &["auth"]);
    let modules = [
        SourceModule::new(
            path("src/routes/users.ts"),
            StructuralLanguage::TypeScript,
            route_source,
        ),
        SourceModule::new(
            path("src/auth.ts"),
            StructuralLanguage::TypeScript,
            b"export function authorize() {}",
        ),
        SourceModule::new(
            path("src/auth.js"),
            StructuralLanguage::JavaScript,
            b"export function authorize() {}",
        ),
    ];

    let result = link_inter_file(
        &[route],
        &modules,
        SemanticIndexInput::NotProvided,
        BusinessLogicLimits::default(),
    )
    .expect("linking");

    assert_eq!(result.local_coverage(), &CoverageState::Partial);
    assert!(
        !result
            .links()
            .iter()
            .any(|link| link.relation() == REL_CALLBACK_IMPORT_BINDING)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == LinkingCoverageGapReason::AmbiguousLocalImport })
    );
}

#[test]
fn unresolved_type_only_and_namespace_imports_fail_visible() {
    let unresolved_source = br#"
        import { authorize as auth } from "../missing";
        app.get("/users/:id", auth);
    "#;
    let type_source = br#"
        import type { Handler as auth } from "../auth";
        app.get("/users/:id", auth);
    "#;
    let namespace_source = br#"
        import * as auth from "../auth";
        app.get("/users/:id", auth.authorize);
    "#;

    for (source_path, source, callback, expected) in [
        (
            "src/routes/unresolved.ts",
            unresolved_source.as_slice(),
            "auth",
            LinkingCoverageGapReason::UnresolvedLocalImport,
        ),
        (
            "src/routes/type-only.ts",
            type_source.as_slice(),
            "auth",
            LinkingCoverageGapReason::TypeOnlyImportBinding,
        ),
        (
            "src/routes/namespace.ts",
            namespace_source.as_slice(),
            "auth.authorize",
            LinkingCoverageGapReason::UnsupportedNamespaceImport,
        ),
    ] {
        let route = express_route(source_path, &[callback]);
        let modules = [
            SourceModule::new(path(source_path), StructuralLanguage::TypeScript, source),
            SourceModule::new(
                path("src/auth.ts"),
                StructuralLanguage::TypeScript,
                b"export type Handler = unknown; export function authorize() {}",
            ),
        ];
        let result = link_inter_file(
            &[route],
            &modules,
            SemanticIndexInput::NotProvided,
            BusinessLogicLimits::default(),
        )
        .expect("linking");
        assert_eq!(result.local_coverage(), &CoverageState::Partial);
        assert!(result.gaps().iter().any(|gap| gap.reason() == expected));
    }
}

#[test]
fn qualified_scip_references_preserve_confidence_and_qualification() {
    let provenance = vec![location("src/helpers/auth.ts", 40)];
    let extracted = QualifiedScipReference::new(
        id("r3-scip-source", &["reference"]),
        id("r3-scip-target", &["definition"]),
        "scip-typescript-1",
        ConfidenceBasis::Extracted,
        provenance.clone(),
        BusinessLogicLimits::default(),
    )
    .expect("qualified reference");
    let references = [extracted];
    let result = link_inter_file(
        &[],
        &[],
        SemanticIndexInput::Qualified {
            references: &references,
            coverage_state: CoverageState::Covered,
        },
        BusinessLogicLimits::default(),
    )
    .expect("linking");

    assert_eq!(result.semantic_coverage(), &CoverageState::Covered);
    assert_eq!(result.semantic_qualification_ids(), &["scip-typescript-1"]);
    assert!(result.links().iter().any(|link| {
        link.relation() == REL_SCIP_REFERENCE
            && link.basis() == LinkBasis::ScipReference
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));

    let inferred = QualifiedScipReference::new(
        id("r3-scip-source", &["heuristic-reference"]),
        id("r3-scip-target", &["heuristic-definition"]),
        "scip-heuristic-1",
        ConfidenceBasis::Inferred,
        provenance,
        BusinessLogicLimits::default(),
    )
    .expect("qualified inferred reference");
    let inferred_refs = [inferred];
    let partial = link_inter_file(
        &[],
        &[],
        SemanticIndexInput::Qualified {
            references: &inferred_refs,
            coverage_state: CoverageState::Covered,
        },
        BusinessLogicLimits::default(),
    )
    .expect("linking");
    assert_eq!(partial.semantic_coverage(), &CoverageState::Partial);
    assert!(
        partial
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == LinkingCoverageGapReason::SemanticIndexInferred })
    );
}

#[test]
fn semantic_absence_partial_ambiguity_and_empty_index_never_become_clean() {
    let unavailable = link_inter_file(
        &[],
        &[],
        SemanticIndexInput::NotProvided,
        BusinessLogicLimits::default(),
    )
    .expect("unavailable");
    assert_eq!(unavailable.semantic_coverage(), &CoverageState::Unavailable);

    let failed = link_inter_file(
        &[],
        &[],
        SemanticIndexInput::CoverageGap(CoverageState::Failed),
        BusinessLogicLimits::default(),
    )
    .expect("failed coverage");
    assert_eq!(failed.semantic_coverage(), &CoverageState::Failed);

    let empty = link_inter_file(
        &[],
        &[],
        SemanticIndexInput::Qualified {
            references: &[],
            coverage_state: CoverageState::Covered,
        },
        BusinessLogicLimits::default(),
    )
    .expect("empty index");
    assert_eq!(empty.semantic_coverage(), &CoverageState::Partial);
    assert!(
        empty
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == LinkingCoverageGapReason::SemanticIndexEmpty })
    );

    let ambiguous = QualifiedScipReference::new(
        id("r3-scip-source", &["ambiguous-reference"]),
        id("r3-scip-target", &["ambiguous-definition"]),
        "scip-compiler-1",
        ConfidenceBasis::Ambiguous,
        vec![location("src/helpers/auth.ts", 60)],
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous semantic reference");
    let ambiguous_refs = [ambiguous];
    let ambiguous_result = link_inter_file(
        &[],
        &[],
        SemanticIndexInput::Qualified {
            references: &ambiguous_refs,
            coverage_state: CoverageState::Covered,
        },
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous linking");
    assert_eq!(
        ambiguous_result.semantic_coverage(),
        &CoverageState::Partial
    );
    assert!(
        ambiguous_result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == LinkingCoverageGapReason::SemanticReferenceAmbiguous })
    );
}

#[test]
fn replay_is_deterministic_and_caps_fail_visible() {
    let source_a = br#"
        import { authorize as auth } from "../auth";
        app.get("/users/:id", auth);
    "#;
    let source_b = br#"
        import { authorize as auth } from "../auth";
        app.get("/users/:id", auth);
    "#;
    let routes = [
        express_route("src/routes/a.ts", &["auth"]),
        express_route("src/routes/b.ts", &["auth"]),
    ];
    let modules_forward = [
        SourceModule::new(
            path("src/routes/a.ts"),
            StructuralLanguage::TypeScript,
            source_a,
        ),
        SourceModule::new(
            path("src/routes/b.ts"),
            StructuralLanguage::TypeScript,
            source_b,
        ),
        SourceModule::new(
            path("src/auth.ts"),
            StructuralLanguage::TypeScript,
            b"export function authorize() {}",
        ),
    ];
    let modules_reverse = [
        SourceModule::new(
            path("src/auth.ts"),
            StructuralLanguage::TypeScript,
            b"export function authorize() {}",
        ),
        SourceModule::new(
            path("src/routes/b.ts"),
            StructuralLanguage::TypeScript,
            source_b,
        ),
        SourceModule::new(
            path("src/routes/a.ts"),
            StructuralLanguage::TypeScript,
            source_a,
        ),
    ];
    let forward = link_inter_file(
        &routes,
        &modules_forward,
        SemanticIndexInput::NotProvided,
        BusinessLogicLimits::default(),
    )
    .expect("forward");
    let reverse = link_inter_file(
        &[routes[1].clone(), routes[0].clone()],
        &modules_reverse,
        SemanticIndexInput::NotProvided,
        BusinessLogicLimits::default(),
    )
    .expect("reverse");
    assert_eq!(forward, reverse);

    let error = link_inter_file(
        &[],
        &modules_forward,
        SemanticIndexInput::NotProvided,
        BusinessLogicLimits {
            max_path_candidates: 2,
            ..BusinessLogicLimits::default()
        },
    )
    .expect_err("source cap");
    assert!(matches!(
        error,
        sentrdel_review::business_logic::link::InterFileLinkError::TooManySourceModules {
            count: 3,
            maximum: 2
        }
    ));
}

#[test]
fn authority_canaries_remain_closed() {
    const { assert!(!INTER_FILE_LINKING_EXECUTES_TARGET) };
    const { assert!(!INTER_FILE_LINKING_REQUIRES_SCIP) };
    const { assert!(!LEXICAL_EQUALITY_PROVES_LINK_EQUIVALENCE) };
    const { assert!(!SCIP_QUALIFICATION_IS_INFERRED_FROM_REPOSITORY) };
    const { assert!(!sentrdel_review::business_logic::R3_TARGET_EXECUTION_ALLOWED) };
    const { assert!(!sentrdel_review::business_logic::R3_PROVIDER_CREDENTIALS_ALLOWED) };
    const { assert!(!sentrdel_review::business_logic::R3_DIRECT_FINDING_CREATION_ALLOWED) };
}
