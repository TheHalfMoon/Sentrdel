use sentrdel_review::business_logic::model::{BusinessLogicLimits, FrameworkFamily, HttpMethod};
use sentrdel_review::business_logic::route::{
    RouteAdapter, RouteCoverageGapReason, RouteExtractionError, MAX_ROUTE_CALLBACKS, extract_routes,
};
use sentrdel_review::structural::{StructuralError, StructuralLanguage};
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::coverage::CoverageState;

const EXPRESS_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/safe-tenant/src/routes/accounts.js"
);
const NEXT_APP_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-app/safe-role/app/api/admin/users/[id]/route.js"
);
const NEXT_PAGES_DYNAMIC_GUARD: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-pages/unknown-dynamic-guard/pages/api/accounts/[id].js"
);
const SUPABASE_EDGE_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/supabase-edge/safe-owner/supabase/functions/private-doc/index.ts"
);
const DYNAMIC_UNSUPPORTED: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/dynamic-unsupported/src/dynamic.js"
);
const MALFORMED: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/malformed-source/src/broken.js"
);

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn express_literal_route_and_callback_chain_are_covered() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Express route");

    assert!(result.gaps().is_empty());
    assert_eq!(result.routes().len(), 1);
    let route = &result.routes()[0];
    assert_eq!(route.framework(), FrameworkFamily::Express);
    assert_eq!(route.method(), HttpMethod::Get);
    assert_eq!(route.route_pattern(), "/accounts/:id");
    assert_eq!(route.callback_chain().len(), 2);
    assert_eq!(route.coverage_state(), &CoverageState::Covered);
    assert_eq!(route.provenance()[0].path().as_str(), "src/routes/accounts.js");
}

#[test]
fn dynamic_express_registration_is_a_visible_gap_not_a_route() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/dynamic.js"),
        DYNAMIC_UNSUPPORTED.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("classify dynamic registration");

    assert!(result.routes().is_empty());
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration));
}

#[test]
fn express_dynamic_path_is_a_visible_gap() {
    let source = b"export function install(app, handler, path) { app.get(path, handler); }\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify dynamic route path");

    assert!(result.routes().is_empty());
    assert_eq!(result.gaps().len(), 1);
    assert_eq!(result.gaps()[0].reason(), RouteCoverageGapReason::DynamicRoutePattern);
}

#[test]
fn unresolved_express_callback_makes_route_partial() {
    let source = b"app.post('/accounts', makeHandler(config));\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract partial route");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].coverage_state(), &CoverageState::Partial);
    assert!(result.routes()[0].callback_chain().is_empty());
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback));
}

#[test]
fn next_app_route_handler_derives_repository_route_identity() {
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/users/[id]/route.js"),
        NEXT_APP_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Next App route");

    assert!(result.gaps().is_empty());
    assert_eq!(result.routes().len(), 1);
    let route = &result.routes()[0];
    assert_eq!(route.framework(), FrameworkFamily::NextApp);
    assert_eq!(route.method(), HttpMethod::Delete);
    assert_eq!(route.route_pattern(), "/api/admin/users/[id]");
    assert_eq!(route.handler_semantic_key(), Some("DELETE"));
    assert_eq!(route.coverage_state(), &CoverageState::Covered);
}

#[test]
fn next_pages_default_handler_preserves_unknown_method_as_partial_coverage() {
    let result = extract_routes(
        RouteAdapter::NextPagesApi,
        StructuralLanguage::JavaScript,
        &path("pages/api/accounts/[id].js"),
        NEXT_PAGES_DYNAMIC_GUARD.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Next Pages route");

    assert_eq!(result.routes().len(), 1);
    let route = &result.routes()[0];
    assert_eq!(route.framework(), FrameworkFamily::NextPagesApi);
    assert_eq!(route.method(), HttpMethod::OtherSupported);
    assert_eq!(route.route_pattern(), "/api/accounts/[id]");
    assert_eq!(route.handler_semantic_key(), Some("handler"));
    assert_eq!(route.coverage_state(), &CoverageState::Partial);
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound));
}

#[test]
fn supabase_edge_deno_serve_is_bounded_and_method_partial() {
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/private-doc/index.ts"),
        SUPABASE_EDGE_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Supabase Edge route");

    assert_eq!(result.routes().len(), 1);
    let route = &result.routes()[0];
    assert_eq!(route.framework(), FrameworkFamily::SupabaseEdge);
    assert_eq!(route.method(), HttpMethod::OtherSupported);
    assert_eq!(route.route_pattern(), "/functions/v1/private-doc");
    assert_eq!(route.coverage_state(), &CoverageState::Partial);
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound));
}

#[test]
fn malformed_source_fails_closed_through_fixed_grammar_boundary() {
    let error = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/broken.js"),
        MALFORMED.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect_err("malformed source must fail");

    assert!(matches!(
        error,
        RouteExtractionError::Structural(StructuralError::MalformedSyntax)
    ));
}

#[test]
fn comments_and_strings_cannot_mint_routes() {
    let source = br#"
const instruction = "app.get('/admin', dangerousHandler)";
// router.post('/shadow', handler)
export const value = 1;
"#;
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/instructions.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("ignore instruction-shaped data");

    assert!(result.routes().is_empty());
    assert!(result.gaps().is_empty());
}

#[test]
fn callback_cap_fails_closed() {
    let callbacks = (0..=MAX_ROUTE_CALLBACKS)
        .map(|index| format!("handler{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let source = format!("app.get('/bounded', {callbacks});\n");
    let error = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/cap.js"),
        source.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect_err("callback cap must fail closed");

    assert!(matches!(
        error,
        RouteExtractionError::TooManyCallbacks { count, max }
            if count == MAX_ROUTE_CALLBACKS + 1 && max == MAX_ROUTE_CALLBACKS
    ));
}

#[test]
fn equivalent_inputs_replay_deterministically() {
    let first = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .unwrap();
    let second = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .unwrap();

    assert_eq!(first, second);
}
