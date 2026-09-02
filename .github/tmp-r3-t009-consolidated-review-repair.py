from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} guard failed: expected 1 occurrence, found {count}")
    return text.replace(old, new, 1)


route_path = Path("crates/sentrdel-review/src/business_logic/route.rs")
route = route_path.read_text(encoding="utf-8")
route = replace_once(
    route,
    "    DynamicRegistration,\n    DynamicRoutePattern,",
    "    DynamicRegistration,\n    UnsupportedRegistration,\n    DynamicRoutePattern,",
    "coverage enum",
)
route = replace_once(
    route,
    """        let Some(method) = parse_express_http_method(registration) else {
            index = method_end;
            continue;
        };""",
    """        if registration == "route" && mask.get(after_registration) == Some(&b'(') {
            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {
                return Err(RouteExtractionError::Structural(
                    StructuralError::MalformedSyntax,
                ));
            };
            builder.gap(
                RouteCoverageGapReason::UnsupportedRegistration,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        let Some(method) = parse_express_http_method(registration) else {
            index = method_end;
            continue;
        };""",
    "app.route gap",
)
route = replace_once(
    route,
    "        let first = skip_source_ws(bytes, call_start + 1);",
    "        let first = skip_source_trivia(source, call_start + 1, call_end);",
    "first argument trivia",
)
route = replace_once(
    route,
    """        let after_path = skip_source_ws(bytes, after_path);
        let mut callback_keys = Vec::new();""",
    """        let after_path = skip_source_trivia(source, after_path, call_end);
        if receiver == "app"
            && method == HttpMethod::Get
            && (after_path >= call_end || bytes[after_path] != b',')
        {
            // Express app.get(name) is a settings getter, not a route registration.
            index = call_end + 1;
            continue;
        }
        let mut callback_keys = Vec::new();""",
    "setting getter",
)
route = replace_once(
    route,
    """    if value.is_empty() || value.starts_with("...") {
        return None;
    }
    if looks_like_function_value(mask, start) {""",
    """    if value.is_empty() || value.starts_with("...") {
        return None;
    }
    if matches!(value, "true" | "false" | "null") {
        return None;
    }
    if looks_like_function_value(mask, start) {""",
    "non-function callback literals",
)
route = replace_once(
    route,
    """) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut args = Vec::new();""",
    """) -> Vec<(usize, usize)> {
    let mut args = Vec::new();""",
    "split args bytes removal",
)
route = replace_once(
    route,
    "                let (trimmed_start, trimmed_end) = trim_range(bytes, item_start, index);",
    """                let (trimmed_start, trimmed_end) =
                    trim_argument_range(source, mask, item_start, index);""",
    "split args inner trim",
)
route = replace_once(
    route,
    "    let (trimmed_start, trimmed_end) = trim_range(bytes, item_start, end);",
    "    let (trimmed_start, trimmed_end) = trim_argument_range(source, mask, item_start, end);",
    "split args final trim",
)
route = replace_once(
    route,
    "fn parse_string_literal(source: &str, start: usize) -> Option<(String, usize)> {",
    """fn skip_source_trivia(source: &str, mut index: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while index < end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index + 1 >= end || bytes[index] != b'/' {
            return index;
        }
        if bytes[index + 1] == b'/' {
            index += 2;
            while index < end && !matches!(bytes[index], b'\\n' | b'\\r') {
                index += 1;
            }
            continue;
        }
        if bytes[index + 1] == b'*' {
            index += 2;
            while index + 1 < end && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            if index + 1 < end {
                index += 2;
            }
            continue;
        }
        return index;
    }
}

fn trim_argument_range(
    source: &str,
    mask: &[u8],
    mut start: usize,
    mut end: usize,
) -> (usize, usize) {
    let bytes = source.as_bytes();
    while start < end
        && (bytes[start].is_ascii_whitespace() || mask.get(start) == Some(&b' '))
    {
        start += 1;
    }
    while end > start
        && (bytes[end - 1].is_ascii_whitespace() || mask.get(end - 1) == Some(&b' '))
    {
        end -= 1;
    }
    (start, end)
}

fn parse_string_literal(source: &str, start: usize) -> Option<(String, usize)> {""",
    "trivia helpers",
)
route_path.write_text(route, encoding="utf-8")

model_path = Path("crates/sentrdel-review/src/business_logic/model.rs")
model = model_path.read_text(encoding="utf-8")
model = replace_once(
    model,
    "            callback_chain: normalize_semantic_ids(callback_chain, limits)?,",
    """            callback_chain: {
                // Callback order is semantic for middleware/guard dominance; preserve execution order.
                if callback_chain.len() > limits.max_related_ids {
                    return Err(ModelError::TooManyRelatedIds {
                        count: callback_chain.len(),
                        max: limits.max_related_ids,
                    });
                }
                callback_chain
            },""",
    "callback ordering constructor",
)
model = replace_once(
    model,
    '        assert_eq!(route.callback_chain(), &[a, id("r3.callback", "b")]);',
    """        assert_eq!(
            route.callback_chain(),
            &[id("r3.callback", "b"), a, id("r3.callback", "b")]
        );""",
    "callback ordering model test",
)
model_path.write_text(model, encoding="utf-8")

tests_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
tests = tests_path.read_text(encoding="utf-8")
tests = replace_once(
    tests,
    "use sentrdel_review::business_logic::model::{BusinessLogicLimits, FrameworkFamily, HttpMethod};",
    """use sentrdel_review::business_logic::model::{
    BusinessLogicLimits, FrameworkFamily, HttpMethod, StableSemanticId,
};""",
    "test import",
)
if "fn callback_execution_order_is_preserved_for_express_middleware_chain()" in tests:
    raise SystemExit("test guard failed: consolidated regressions already exist")
tests += r'''

#[test]
fn callback_execution_order_is_preserved_for_express_middleware_chain() {
    let limits = BusinessLogicLimits::default();
    let source = b"app.get('/ordered', authenticate, authorize, handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/order.js"),
        source,
        limits,
    )
    .expect("extract ordered callback chain");

    let expected = vec![
        StableSemanticId::from_parts(
            "r3-route-callback",
            &["express", "src/order.js", "/ordered", "0", "authenticate"],
            limits,
        )
        .unwrap(),
        StableSemanticId::from_parts(
            "r3-route-callback",
            &["express", "src/order.js", "/ordered", "1", "authorize"],
            limits,
        )
        .unwrap(),
        StableSemanticId::from_parts(
            "r3-route-callback",
            &["express", "src/order.js", "/ordered", "2", "handler"],
            limits,
        )
        .unwrap(),
    ];
    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].callback_chain(), expected.as_slice());
}

#[test]
fn express_route_chains_are_explicit_unsupported_registration_gaps() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/route-chain.js"),
        b"app.route('/admin').get(handler);\nrouter.route('/tenant').post(handler);\n",
        BusinessLogicLimits::default(),
    )
    .expect("classify unsupported Express route chains");

    assert!(result.routes().is_empty());
    assert_eq!(result.gaps().len(), 2);
    assert!(result
        .gaps()
        .iter()
        .all(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedRegistration));
}

#[test]
fn express_app_get_setting_lookup_does_not_mint_route() {
    let app = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/settings.js"),
        b"app.get('env');\napp.get('trust proxy');\n",
        BusinessLogicLimits::default(),
    )
    .expect("classify Express setting getters");
    assert!(app.routes().is_empty());
    assert!(app.gaps().is_empty());

    let router = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/router.js"),
        b"router.get('/missing-handler');\n",
        BusinessLogicLimits::default(),
    )
    .expect("preserve Router route semantics");
    assert_eq!(router.routes().len(), 1);
    assert_eq!(router.routes()[0].coverage_state(), &CoverageState::Partial);
    assert!(router
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback));
}

#[test]
fn express_argument_comments_are_trivia_not_dynamic_semantics() {
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/commented-route.js"),
        b"app.get(/* audited path */ '/admin' /* route */, /* auth */ authenticate /* checked */, handler /* final */);\n",
        BusinessLogicLimits::default(),
    )
    .expect("extract commented static route");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/admin");
    assert_eq!(result.routes()[0].coverage_state(), &CoverageState::Covered);
    assert_eq!(result.routes()[0].callback_chain().len(), 2);
    assert!(result.gaps().is_empty());
}

#[test]
fn non_function_literals_are_not_resolved_callback_keys() {
    let express = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/literal-handler.js"),
        b"app.get('/admin', true);\n",
        BusinessLogicLimits::default(),
    )
    .expect("classify non-function Express callback literal");
    assert_eq!(express.routes().len(), 1);
    assert_eq!(express.routes()[0].coverage_state(), &CoverageState::Partial);
    assert!(express.routes()[0].callback_chain().is_empty());
    assert!(express
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback));

    let supabase = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/literal-handler/index.ts"),
        b"Deno.serve(null);\n",
        BusinessLogicLimits::default(),
    )
    .expect("classify non-function Supabase callback literal");
    assert!(supabase.routes().is_empty());
    assert!(supabase
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback));
}
'''
tests_path.write_text(tests, encoding="utf-8")
