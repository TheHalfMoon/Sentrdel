use sentrdel_review::business_logic::model::{
    BusinessLogicLimits, FrameworkFamily, HttpMethod, StableSemanticId,
};
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
fn division_after_function_expression_keeps_real_route_visible() {
    let source = b"const ratio = function () {} / app.get('/registered', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/division.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve route registration used as division operand");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/registered");
}

#[test]
fn template_literal_text_cannot_mint_routes_but_substitutions_remain_executable() {
    let source = br#"
const inert = `app.get('/template-fake', handler)`;
const evaluated = `${app.get('/template-real', handler)}`;
"#;
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/template.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve executable template substitution while masking literal text");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/template-real");
    assert!(result.gaps().is_empty());
}

#[test]
fn express_method_names_are_case_sensitive() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes.js"),
        b"app.GET('/not-express-get', handler);",
        BusinessLogicLimits::default(),
    )
    .expect("parse valid JavaScript");

    assert!(result.routes().is_empty());
}

#[test]
fn express_middleware_registration_is_case_sensitive() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes.js"),
        b"app.USE('/not-express-middleware', handler);\nrouter.USE('/also-not-express-middleware', handler);\n",
        BusinessLogicLimits::default(),
    )
    .expect("parse valid JavaScript");

    assert!(result.routes().is_empty());
    assert!(result.gaps().is_empty());
}

#[test]
fn express_all_registrations_are_explicit_coverage_gaps() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes.js"),
        b"app.all('/admin', handler);\nrouter.all('/tenant', handler);\n",
        BusinessLogicLimits::default(),
    )
    .expect("classify Express all registrations");

    assert!(result.routes().is_empty());
    assert_eq!(result.gaps().len(), 2);
    assert!(
        result
            .gaps()
            .iter()
            .all(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
    );
}

#[test]
fn next_app_http_method_exports_require_canonical_uppercase_names() {
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/example/route.js"),
        b"export function get() { return new Response('x'); }",
        BusinessLogicLimits::default(),
    )
    .expect("parse valid JavaScript");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn conditional_callback_expression_is_partial_not_a_direct_inline_handler() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes.js"),
        b"app.get('/conditional', enabled ? (() => handlerA()) : handlerB);",
        BusinessLogicLimits::default(),
    )
    .expect("parse valid JavaScript");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].method(), HttpMethod::Get);
    assert_eq!(result.routes()[0].coverage_state(), &CoverageState::Partial);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback)
    );
}

#[test]
fn deno_serve_two_argument_overload_uses_second_argument_as_handler() {
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/example/index.ts"),
        b"const options = { port: 8080 }; const handler = (req: Request) => new Response('ok'); Deno.serve(options, handler);",
        BusinessLogicLimits::default(),
    )
    .expect("parse valid TypeScript");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].handler_semantic_key(), Some("handler"));
    assert_eq!(result.routes()[0].coverage_state(), &CoverageState::Partial);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
    );
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

#[test]
fn express_callback_chain_preserves_execution_order() {
    let limits = BusinessLogicLimits::default();
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/order.js"),
        b"app.get('/ordered', authenticate, requireTenant, handler);",
        limits,
    )
    .expect("extract ordered callback chain");

    let expected = ["authenticate", "requireTenant", "handler"]
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let index = index.to_string();
            StableSemanticId::from_parts(
                "r3-route-callback",
                &["express", "src/order.js", "/ordered", &index, key],
                limits,
            )
            .expect("expected callback id")
        })
        .collect::<Vec<_>>();
    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].callback_chain(), expected.as_slice());
}

#[test]
fn express_route_chains_are_explicit_coverage_gaps() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/chains.js"),
        b"app.route('/admin').get(handler); router.route('/tenant').post(handler);",
        BusinessLogicLimits::default(),
    )
    .expect("classify unsupported route chains");

    assert!(result.routes().is_empty());
    assert_eq!(result.gaps().len(), 2);
    assert!(
        result
            .gaps()
            .iter()
            .all(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
    );
}

#[test]
fn express_setting_getter_does_not_mint_a_route() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/settings.js"),
        b"const env = app.get('env'); app.get('/real', handler);",
        BusinessLogicLimits::default(),
    )
    .expect("distinguish Express setting getter");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/real");
    assert!(result.gaps().is_empty());
}

#[test]
fn express_comments_between_arguments_are_trivia() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/comments.js"),
        b"app.get(/* audited */ '/admin' /* path */, /* guard */ authenticate, /* handler */ handler);",
        BusinessLogicLimits::default(),
    )
    .expect("treat comments as argument trivia");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/admin");
    assert_eq!(result.routes()[0].callback_chain().len(), 2);
    assert_eq!(result.routes()[0].coverage_state(), &CoverageState::Covered);
    assert!(result.gaps().is_empty());
}

#[test]
fn non_function_callback_literals_are_unresolved() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/non-callable.js"),
        b"app.get('/true', true); app.post('/null', null);",
        BusinessLogicLimits::default(),
    )
    .expect("classify non-callable literals");

    assert_eq!(result.routes().len(), 2);
    assert!(
        result
            .routes()
            .iter()
            .all(|route| route.coverage_state() == &CoverageState::Partial)
    );
    assert!(
        result
            .routes()
            .iter()
            .all(|route| route.callback_chain().is_empty())
    );
    assert_eq!(
        result
            .gaps()
            .iter()
            .filter(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback)
            .count(),
        2
    );
}

#[test]
fn next_app_mixed_supported_and_export_list_methods_keep_gap_visible() {
    let source = b"export function GET() { return new Response('ok'); }\nconst handler = () => new Response('post');\nexport { handler as POST };\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/mixed/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify mixed Next exports");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].method(), HttpMethod::Get);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn shadowed_deno_binding_is_an_explicit_coverage_gap() {
    let source = b"const Deno = mockRuntime; const handler = (req: Request) => new Response('ok'); Deno.serve(handler);";
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/shadowed/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify shadowed Deno binding");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );
}

#[test]
fn express_param_callbacks_are_explicit_unsupported_middleware() {
    let source = b"router.param('id', authorize); router.get('/users/:id', handler);";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/params.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify Express param callbacks");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/users/:id");
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedMiddleware)
    );
}

#[test]
fn optional_chained_express_registration_is_a_dynamic_gap() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/optional.js"),
        b"app?.get('/admin', handler);",
        BusinessLogicLimits::default(),
    )
    .expect("classify optional Express registration");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration)
    );
}

#[test]
fn fluent_express_suffix_registration_is_a_dynamic_gap() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/fluent.js"),
        b"app.get('/a', first).post('/b', second);",
        BusinessLogicLimits::default(),
    )
    .expect("classify fluent Express suffix");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/a");
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration)
    );
}

#[test]
fn next_app_typed_method_export_remains_visible_as_a_gap() {
    let source = b"export function GET() { return new Response('get'); }\nexport const POST: RouteHandler = async () => new Response('post');\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::TypeScript,
        &path("app/api/typed/route.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify typed Next App method export");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].method(), HttpMethod::Get);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn default_imported_deno_binding_is_an_explicit_coverage_gap() {
    let source = b"import Deno from './mock-runtime'; const handler = (req: Request) => new Response('ok'); Deno.serve(handler);";
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/import-shadow/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify default-imported Deno binding");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );
}

#[test]
fn next_app_multi_declarator_method_export_keeps_additional_method_visible() {
    let source =
        b"export const GET = () => new Response('get'), POST = () => new Response('post');\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/multi/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("keep additional Next App method declarator visible");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].method(), HttpMethod::Get);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn optional_express_method_invocation_is_a_dynamic_gap() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/optional-method.js"),
        b"app.get?.('/admin', handler);",
        BusinessLogicLimits::default(),
    )
    .expect("classify optional Express method invocation");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration)
    );
}

#[test]
fn express_literal_prefix_dynamic_path_does_not_mint_a_route() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/dynamic-prefix.js"),
        b"app.get('/users/' + id, handler);",
        BusinessLogicLimits::default(),
    )
    .expect("classify literal-prefix dynamic route path");

    assert!(result.routes().is_empty());
    assert_eq!(
        result
            .gaps()
            .iter()
            .filter(|gap| gap.reason() == RouteCoverageGapReason::DynamicRoutePattern)
            .count(),
        1
    );
}

#[test]
fn destructured_deno_alias_is_an_explicit_coverage_gap() {
    let source = b"const { runtime: Deno } = mocks; const handler = (req: Request) => new Response('ok'); Deno.serve(handler);";
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/destructured-shadow/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify destructured Deno binding");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );
}

#[test]
fn deno_serve_non_function_literal_is_unresolved() {
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/non-callable/index.ts"),
        b"Deno.serve(null);",
        BusinessLogicLimits::default(),
    )
    .expect("classify non-callable Deno handler");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback)
    );
}

#[test]
fn next_app_multi_declarator_scan_stops_at_asi_boundary() {
    let source = b"export const runtime = 'edge'\nlet local, POST = handler\nexport function GET() { return new Response('ok'); }\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/asi/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("stop additional declarator scan at ASI boundary");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].method(), HttpMethod::Get);
    assert!(result.gaps().is_empty());
}

#[test]
fn typescript_non_null_express_receiver_is_a_visible_gap() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::TypeScript,
        &path("src/non-null.ts"),
        b"app!.get('/admin', handler);",
        BusinessLogicLimits::default(),
    )
    .expect("classify non-null asserted Express receiver");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration)
    );
}

#[test]
fn additional_express_http_methods_are_explicit_gaps() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/extended-methods.js"),
        b"app.trace('/proxy', handler); app.connect('/tunnel', handler);",
        BusinessLogicLimits::default(),
    )
    .expect("surface bounded unsupported Express HTTP methods");

    assert!(result.routes().is_empty());
    assert_eq!(
        result
            .gaps()
            .iter()
            .filter(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound)
            .count(),
        2
    );
}

#[test]
fn next_app_let_and_var_method_exports_remain_visible() {
    let source = b"export function GET() { return new Response('get'); }\nexport let POST = async () => new Response('post');\nexport var PUT = () => new Response('put');\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/mutable/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract Next App let and var handlers");

    assert_eq!(result.routes().len(), 3);
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.method() == HttpMethod::Get)
    );
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.method() == HttpMethod::Post)
    );
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.method() == HttpMethod::Put)
    );
    assert!(result.gaps().is_empty());
}

#[test]
fn next_app_wildcard_reexport_is_an_explicit_gap() {
    let source =
        b"export function GET() { return new Response('get'); }\nexport * from './handlers';\n";
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/reexport/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("surface wildcard Next App re-export");

    assert_eq!(result.routes().len(), 1);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

#[test]
fn catch_parameter_deno_binding_is_an_explicit_gap() {
    let source = b"const handler = (req: Request) => new Response('ok'); try { throw mockRuntime; } catch (Deno) { Deno.serve(handler); }";
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/catch-shadow/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify catch-parameter Deno binding");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );
}

#[test]
fn next_app_private_folder_is_not_a_route() {
    let result = extract_routes(
        RouteAdapter::NextApp,
        StructuralLanguage::TypeScript,
        &path("app/_internal/route.ts"),
        b"export function GET() { return new Response('hidden'); }",
        BusinessLogicLimits::default(),
    )
    .expect("reject private Next App folder");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedRouteFile)
    );
}

#[test]
fn shadowed_express_receiver_is_an_explicit_gap() {
    let source = b"function inspect(app) { app.get('/metadata', callback); }";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/shadowed-app.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify shadowed Express receiver");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );
}

#[test]
fn express_function_declaration_named_app_is_ambiguous() {
    for source in [
        b"function app() {}\napp.get('/local', handler);".as_slice(),
        b"export function app() {}\napp.get('/exported-local', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/function-app.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify local function named app as ambiguous");

        assert!(result.routes().is_empty());
        assert!(
            result
                .gaps()
                .iter()
                .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
        );
    }
}

#[test]
fn express_function_declaration_named_router_is_ambiguous() {
    for source in [
        b"function router() {}\nrouter.get('/local', handler);".as_slice(),
        b"export function router() {}\nrouter.get('/exported-local', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/function-router.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify local function named router as ambiguous");

        assert!(result.routes().is_empty());
        assert!(
            result
                .gaps()
                .iter()
                .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
        );
    }
}

#[test]
fn bounded_express_factory_bindings_remain_supported() {
    let source = b"const app = express();\nconst router = express.Router();\napp.get('/app', handler);\nrouter.post('/router', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/factories.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve bounded Express factory bindings");

    assert_eq!(result.routes().len(), 2);
    assert!(result.gaps().is_empty());
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/app")
    );
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/router")
    );
}

#[test]
fn lookalike_express_factory_bindings_are_ambiguous() {
    let source = b"const app = fakeexpress();\nconst router = other.Router();\napp.get('/fake-app', handler);\nrouter.get('/fake-router', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/lookalike-factories.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject lookalike Express factory bindings");

    assert!(result.routes().is_empty());
    assert_eq!(
        result
            .gaps()
            .iter()
            .filter(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
            .count(),
        2
    );
}

#[test]
fn shadowed_express_factory_binding_is_ambiguous() {
    for source in [
        b"const express = createMockFactory;\nconst app = express();\napp.get('/mock-app', handler);".as_slice(),
        b"const express = createMockFactory;\nconst router = express.Router();\nrouter.get('/mock-router', handler);".as_slice(),
        b"export function configure(express) {\n  const app = express();\n  app.get('/parameter-shadow', handler);\n}".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/shadowed-express-factory.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify shadowed express factory as ambiguous");

        assert!(result.routes().is_empty());
        assert!(
            result
                .gaps()
                .iter()
                .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
        );
    }
}

#[test]
fn canonical_express_package_import_factory_remains_supported() {
    let source = b"import express from 'express';\nconst app = express();\nconst router = express.Router();\napp.get('/app-import', handler);\nrouter.post('/router-import', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/imported-express.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve exact express package import");

    assert_eq!(result.routes().len(), 2);
    assert!(result.gaps().is_empty());
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/app-import")
    );
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/router-import")
    );
}

#[test]
fn noncanonical_express_import_factory_is_ambiguous() {
    let source = b"import express from './mock-express.js';\nconst app = express();\napp.get('/mock-import', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/mock-import.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject noncanonical express import factory");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
    );
}

#[test]
fn named_and_namespace_express_imports_are_ambiguous() {
    for source in [
        b"import { json as express } from 'express';\nconst app = express();\napp.get('/named-alias', handler);".as_slice(),
        b"import * as express from 'express';\nconst app = express();\napp.get('/namespace-import', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/ambiguous-express-import.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify non-default Express imports as ambiguous");

        assert!(result.routes().is_empty());
        assert!(
            result
                .gaps()
                .iter()
                .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
        );
    }
}

#[test]
fn default_express_import_with_named_imports_remains_supported() {
    let source = b"import express, { json } from 'express';\nconst app = express();\napp.get('/default-plus-named', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/default-express-import.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve default Express factory binding");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/default-plus-named");
    assert!(result.gaps().is_empty());
}
