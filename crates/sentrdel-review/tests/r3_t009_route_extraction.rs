use sentrdel_review::business_logic::model::{BusinessLogicLimits, FrameworkFamily, HttpMethod};
use sentrdel_review::business_logic::route::{
    MAX_ROUTE_CALLBACKS, RouteAdapter, RouteCoverageGapReason, RouteExtractionError, extract_routes,
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
const REGEX_LITERAL_ROUTE_SHAPE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/regex-literal/src/route-shaped.js"
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
    assert_eq!(
        route.provenance()[0].path().as_str(),
        "src/routes/accounts.js"
    );
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
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration)
    );
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
    assert_eq!(
        result.gaps()[0].reason(),
        RouteCoverageGapReason::DynamicRoutePattern
    );
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
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback)
    );
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
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
    );
}

#[test]
fn next_pages_named_export_before_default_handler_is_supported() {
    let source = b"export const config = { api: { bodyParser: false } };\nexport default async function handler(req, res) { return res.json({ ok: true }); }\n";
    let result = extract_routes(
        RouteAdapter::NextPagesApi,
        StructuralLanguage::JavaScript,
        &path("pages/api/configured.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("find supported default handler after named export");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].handler_semantic_key(), Some("handler"));
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
    );
}

#[test]
fn next_pages_non_function_default_export_is_an_explicit_gap() {
    let source = b"export const config = { api: { bodyParser: false } };\nconst configuration = { enabled: true };\nexport default configuration;\n";
    let result = extract_routes(
        RouteAdapter::NextPagesApi,
        StructuralLanguage::JavaScript,
        &path("pages/api/configuration.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify non-function default export");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
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
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
    );
}

#[test]
fn supabase_non_entry_file_is_an_explicit_unsupported_route_file_gap() {
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/private-doc/helper.ts"),
        SUPABASE_EDGE_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("reject non-entry Supabase Edge source file");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedRouteFile)
    );
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
fn regex_literals_cannot_mint_routes_or_unbalance_callbacks() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/route-shaped.js"),
        REGEX_LITERAL_ROUTE_SHAPE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("mask route-shaped regex literal");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/real");
    assert!(
        !result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "x")
    );
}

#[test]
fn regex_literal_after_control_flow_condition_cannot_mint_route() {
    let source = b"if (enabled) /app.get('x', handler)/.test(value);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/conditional-regex.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("mask regex literal used as an if consequent");

    assert!(result.routes().is_empty());
    assert!(result.gaps().is_empty());
}

#[test]
fn express_use_middleware_is_explicit_coverage_gap() {
    let source =
        b"app.use('/admin', authenticationMiddleware);\nrouter.use('/tenant', tenantMiddleware);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/middleware.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify unsupported Express middleware");

    assert!(result.routes().is_empty());
    assert_eq!(result.gaps().len(), 2);
    assert!(
        result
            .gaps()
            .iter()
            .all(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedMiddleware)
    );
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

#[test]
fn qualified_express_receivers_cannot_mint_routes() {
    let source =
        b"client.app.get('/nested', handler); client?.router.post('/optional', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/nested.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject qualified Express receivers");
    assert!(result.routes().is_empty());
}

#[test]
fn private_field_express_receiver_cannot_mint_route() {
    let source = br#"
class Routes {
    #app;

    install(handler) {
        this.#app.get('/private-field', handler);
    }
}
"#;
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/private-field.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject private-field Express receiver");

    assert!(result.routes().is_empty());
    assert!(result.gaps().is_empty());
}

#[test]
fn private_field_deno_receiver_cannot_mint_supabase_route() {
    let source = br#"
class Runtime {
    #Deno;

    install(handler) {
        this.#Deno.serve(handler);
    }
}
"#;
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/private-doc/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject private-field Deno receiver");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn next_app_non_function_export_does_not_search_later_statements() {
    let source = b"export const GET = configuration;\nconst later = () => {};\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/example/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject non-function Next App handler export");
    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn qualified_deno_receiver_cannot_mint_supabase_edge_route() {
    let source = b"runtime.Deno.serve(handler);\n";
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/nested/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject qualified Deno receiver");
    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}
