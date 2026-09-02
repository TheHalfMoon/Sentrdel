from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


route_path = Path("crates/sentrdel-review/src/business_logic/route.rs")
model_path = Path("crates/sentrdel-review/src/business_logic/model.rs")
test_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")

route = route_path.read_text()
model = model_path.read_text()
tests = test_path.read_text()

# 1. Preserve callback execution order instead of treating the chain as a set.
model = replace_once(
    model,
    "            callback_chain: normalize_semantic_ids(callback_chain, limits)?,\n",
    "            // Callback chains are execution-order sequences, not set-like related IDs.\n"
    "            callback_chain: preserve_semantic_id_sequence(callback_chain, limits)?,\n",
    "route callback sequence constructor",
)
model = replace_once(
    model,
    "pub(crate) fn normalize_semantic_ids(\n    mut values: Vec<StableSemanticId>,\n    limits: BusinessLogicLimits,\n) -> Result<Vec<StableSemanticId>, ModelError> {\n",
    "fn preserve_semantic_id_sequence(\n"
    "    values: Vec<StableSemanticId>,\n"
    "    limits: BusinessLogicLimits,\n"
    ") -> Result<Vec<StableSemanticId>, ModelError> {\n"
    "    let limits = limits.validate()?;\n"
    "    validate_related_id_count(values.len(), limits)?;\n"
    "    Ok(values)\n"
    "}\n\n"
    "pub(crate) fn normalize_semantic_ids(\n"
    "    mut values: Vec<StableSemanticId>,\n"
    "    limits: BusinessLogicLimits,\n"
    ") -> Result<Vec<StableSemanticId>, ModelError> {\n",
    "ordered semantic id helper",
)

# 2. Add a specific fail-visible reason for an ambiguous/shadowed runtime receiver.
route = replace_once(
    route,
    "    UnsupportedHandlerExport,\n    MethodNotStaticallyBound,\n",
    "    UnsupportedHandlerExport,\n    AmbiguousReceiverBinding,\n    MethodNotStaticallyBound,\n",
    "ambiguous receiver gap reason",
)

# 3. app.route()/router.route() chains are unsupported and must be visible.
route = replace_once(
    route,
    "        let after_registration = skip_mask_ws(mask, method_end);\n        if registration == \"use\" && mask.get(after_registration) == Some(&b'(') {\n",
    "        let after_registration = skip_mask_ws(mask, method_end);\n"
    "        if registration == \"route\" && mask.get(after_registration) == Some(&b'(') {\n"
    "            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {\n"
    "                return Err(RouteExtractionError::Structural(\n"
    "                    StructuralError::MalformedSyntax,\n"
    "                ));\n"
    "            };\n"
    "            builder.gap(\n"
    "                RouteCoverageGapReason::MethodNotStaticallyBound,\n"
    "                receiver_start,\n"
    "                call_end + 1,\n"
    "            )?;\n"
    "            index = call_end + 1;\n"
    "            continue;\n"
    "        }\n"
    "        if registration == \"use\" && mask.get(after_registration) == Some(&b'(') {\n",
    "express route chain gap",
)

# 4. Comments are trivia at argument boundaries; a one-argument app.get is a setting getter.
route = replace_once(
    route,
    "        let first = skip_source_ws(bytes, call_start + 1);\n",
    "        let first = skip_source_ws_and_comments(source, call_start + 1, call_end);\n",
    "express leading argument comments",
)
route = replace_once(
    route,
    "        let after_path = skip_source_ws(bytes, after_path);\n        let mut callback_keys = Vec::new();\n",
    "        let after_path = skip_source_ws_and_comments(source, after_path, call_end);\n"
    "        // Express overloads app.get(name) as an application-setting getter. It is not a route.\n"
    "        if method == HttpMethod::Get && after_path >= call_end {\n"
    "            index = call_end + 1;\n"
    "            continue;\n"
    "        }\n"
    "        let mut callback_keys = Vec::new();\n",
    "express setting getter",
)

# 5. Surface unsupported Next export-list HTTP handlers even when another method is supported.
route = replace_once(
    route,
    "                }\n            }\n        }\n        index = export_start + \"export\".len();\n",
    "                }\n"
    "            }\n"
    "        } else if mask.get(cursor) == Some(&b'{')\n"
    "            && let Some(close) = find_balanced(mask, cursor, b'{', b'}')\n"
    "            && export_list_mentions_next_http_method(source, mask, cursor + 1, close)\n"
    "        {\n"
    "            builder.gap(\n"
    "                RouteCoverageGapReason::UnsupportedHandlerExport,\n"
    "                export_start,\n"
    "                close + 1,\n"
    "            )?;\n"
    "        }\n"
    "        index = export_start + \"export\".len();\n",
    "next export list coverage",
)

# 6. Fail visible when Deno is shadowed by a local binding.
route = replace_once(
    route,
    "    let route_pattern = format!(\"/functions/v1/{function_name}\");\n    let mut index = 0;\n",
    "    let route_pattern = format!(\"/functions/v1/{function_name}\");\n"
    "    let deno_shadowed = has_local_deno_binding(source)?;\n"
    "    let mut index = 0;\n",
    "deno binding pre-scan",
)
route = replace_once(
    route,
    "        let args = split_top_level_args(source, mask, call_start + 1, call_end);\n        let callback = match args.as_slice() {\n",
    "        if deno_shadowed {\n"
    "            builder.gap(\n"
    "                RouteCoverageGapReason::AmbiguousReceiverBinding,\n"
    "                deno_start,\n"
    "                call_end + 1,\n"
    "            )?;\n"
    "            found = true;\n"
    "            index = call_end + 1;\n"
    "            continue;\n"
    "        }\n"
    "        let args = split_top_level_args(source, mask, call_start + 1, call_end);\n"
    "        let callback = match args.as_slice() {\n",
    "deno shadow gap",
)

# 7. Reject definitive non-function literal callback forms and trim comments around callback args.
route = replace_once(
    route,
    "fn callback_key(source: &str, mask: &[u8], start: usize, end: usize) -> Option<String> {\n    let value = source.get(start..end)?.trim();\n    if value.is_empty() || value.starts_with(\"...\") {\n        return None;\n    }\n",
    "fn callback_key(source: &str, mask: &[u8], start: usize, end: usize) -> Option<String> {\n"
    "    let (start, end) = trim_source_trivia_range(source, start, end);\n"
    "    let value = source.get(start..end)?.trim();\n"
    "    if value.is_empty()\n"
    "        || value.starts_with(\"...\")\n"
    "        || matches!(value, \"true\" | \"false\" | \"null\")\n"
    "    {\n"
    "        return None;\n"
    "    }\n",
    "callback literal rejection",
)
route = replace_once(
    route,
    "    let bytes = source.as_bytes();\n    let mut args = Vec::new();\n",
    "    let mut args = Vec::new();\n",
    "split args raw bytes removal",
)
route = replace_once(
    route,
    "                let (trimmed_start, trimmed_end) = trim_range(bytes, item_start, index);\n",
    "                let (trimmed_start, trimmed_end) =\n                    trim_source_trivia_range(source, item_start, index);\n",
    "split args intermediate trivia",
)
route = replace_once(
    route,
    "    let (trimmed_start, trimmed_end) = trim_range(bytes, item_start, end);\n",
    "    let (trimmed_start, trimmed_end) = trim_source_trivia_range(source, item_start, end);\n",
    "split args final trivia",
)

# 8. Add helpers for Next export lists, Deno binding recognition, and source comment trivia.
route = replace_once(
    route,
    "fn extract_next_pages(\n",
    "fn export_list_mentions_next_http_method(\n"
    "    source: &str,\n"
    "    mask: &[u8],\n"
    "    mut index: usize,\n"
    "    end: usize,\n"
    ") -> bool {\n"
    "    while index < end {\n"
    "        if is_ident_start(mask[index]) {\n"
    "            let token_end = parse_ident_end(mask, index);\n"
    "            if token_end <= end && parse_next_http_method(&source[index..token_end]).is_some() {\n"
    "                return true;\n"
    "            }\n"
    "            index = token_end;\n"
    "        } else {\n"
    "            index += 1;\n"
    "        }\n"
    "    }\n"
    "    false\n"
    "}\n\n"
    "fn extract_next_pages(\n",
    "next export-list helper",
)

route = replace_once(
    route,
    "fn method_identity(method: HttpMethod) -> &'static str {\n",
    "fn has_local_deno_binding(source: &str) -> Result<bool, StructuralError> {\n"
    "    let language: tree_sitter::Language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();\n"
    "    let mut parser = tree_sitter::Parser::new();\n"
    "    parser\n"
    "        .set_language(&language)\n"
    "        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;\n"
    "    let tree = parser.parse(source, None).ok_or_else(|| {\n"
    "        StructuralError::ParseFailed(\"Deno binding parser returned no syntax tree\".to_owned())\n"
    "    })?;\n"
    "    let mut cursor = tree.root_node().walk();\n"
    "    loop {\n"
    "        let node = cursor.node();\n"
    "        if matches!(node.kind(), \"identifier\" | \"shorthand_property_identifier_pattern\")\n"
    "            && source.get(node.byte_range()) == Some(\"Deno\")\n"
    "            && identifier_is_binding(node)\n"
    "        {\n"
    "            return Ok(true);\n"
    "        }\n"
    "        if cursor.goto_first_child() {\n"
    "            continue;\n"
    "        }\n"
    "        loop {\n"
    "            if cursor.goto_next_sibling() {\n"
    "                break;\n"
    "            }\n"
    "            if !cursor.goto_parent() {\n"
    "                return Ok(false);\n"
    "            }\n"
    "        }\n"
    "    }\n"
    "}\n\n"
    "fn identifier_is_binding(node: tree_sitter::Node<'_>) -> bool {\n"
    "    let Some(parent) = node.parent() else {\n"
    "        return false;\n"
    "    };\n"
    "    let same_as_field = |field: &str| {\n"
    "        parent.child_by_field_name(field).is_some_and(|candidate| {\n"
    "            candidate.start_byte() == node.start_byte() && candidate.end_byte() == node.end_byte()\n"
    "        })\n"
    "    };\n"
    "    match parent.kind() {\n"
    "        \"variable_declarator\" | \"function_declaration\" | \"class_declaration\" => {\n"
    "            same_as_field(\"name\")\n"
    "        }\n"
    "        \"assignment_expression\" => same_as_field(\"left\"),\n"
    "        \"formal_parameters\"\n"
    "        | \"required_parameter\"\n"
    "        | \"optional_parameter\"\n"
    "        | \"rest_pattern\"\n"
    "        | \"import_specifier\"\n"
    "        | \"namespace_import\"\n"
    "        | \"shorthand_property_identifier_pattern\" => true,\n"
    "        _ => parent.parent().is_some_and(|grandparent| {\n"
    "            matches!(\n"
    "                grandparent.kind(),\n"
    "                \"formal_parameters\" | \"required_parameter\" | \"optional_parameter\"\n"
    "            )\n"
    "        }),\n"
    "    }\n"
    "}\n\n"
    "fn method_identity(method: HttpMethod) -> &'static str {\n",
    "deno binding helper",
)

route = replace_once(
    route,
    "fn skip_source_ws(bytes: &[u8], mut index: usize) -> usize {\n    while index < bytes.len() && bytes[index].is_ascii_whitespace() {\n        index += 1;\n    }\n    index\n}\n\nfn trim_range(bytes: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {\n    while start < end && bytes[start].is_ascii_whitespace() {\n        start += 1;\n    }\n    while end > start && bytes[end - 1].is_ascii_whitespace() {\n        end -= 1;\n    }\n    (start, end)\n}\n",
    "fn skip_source_ws_and_comments(source: &str, mut index: usize, end: usize) -> usize {\n"
    "    let bytes = source.as_bytes();\n"
    "    loop {\n"
    "        while index < end && bytes[index].is_ascii_whitespace() {\n"
    "            index += 1;\n"
    "        }\n"
    "        if index + 1 >= end {\n"
    "            return index;\n"
    "        }\n"
    "        if &bytes[index..index + 2] == b\"//\" {\n"
    "            index += 2;\n"
    "            while index < end && !matches!(bytes[index], b'\\n' | b'\\r') {\n"
    "                index += 1;\n"
    "            }\n"
    "            continue;\n"
    "        }\n"
    "        if &bytes[index..index + 2] == b\"/*\" {\n"
    "            let mut cursor = index + 2;\n"
    "            while cursor + 1 < end && &bytes[cursor..cursor + 2] != b\"*/\" {\n"
    "                cursor += 1;\n"
    "            }\n"
    "            if cursor + 1 >= end {\n"
    "                return end;\n"
    "            }\n"
    "            index = cursor + 2;\n"
    "            continue;\n"
    "        }\n"
    "        return index;\n"
    "    }\n"
    "}\n\n"
    "fn trim_source_trivia_range(source: &str, start: usize, mut end: usize) -> (usize, usize) {\n"
    "    let bytes = source.as_bytes();\n"
    "    let start = skip_source_ws_and_comments(source, start, end);\n"
    "    loop {\n"
    "        while end > start && bytes[end - 1].is_ascii_whitespace() {\n"
    "            end -= 1;\n"
    "        }\n"
    "        if end >= start + 2 && &bytes[end - 2..end] == b\"*/\" {\n"
    "            if let Some(relative) = source[start..end - 2].rfind(\"/*\") {\n"
    "                end = start + relative;\n"
    "                continue;\n"
    "            }\n"
    "        }\n"
    "        let line_start = source[start..end]\n"
    "            .rfind(['\\n', '\\r'])\n"
    "            .map_or(start, |relative| start + relative + 1);\n"
    "        if let Some(relative) = source[line_start..end].find(\"//\") {\n"
    "            end = line_start + relative;\n"
    "            continue;\n"
    "        }\n"
    "        return (start, end);\n"
    "    }\n"
    "}\n",
    "source trivia helpers",
)

# Tests: import StableSemanticId and append comprehensive review regressions.
tests = replace_once(
    tests,
    "use sentrdel_review::business_logic::model::{BusinessLogicLimits, FrameworkFamily, HttpMethod};\n",
    "use sentrdel_review::business_logic::model::{\n"
    "    BusinessLogicLimits, FrameworkFamily, HttpMethod, StableSemanticId,\n"
    "};\n",
    "test stable id import",
)

new_tests = r'''

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
    assert!(result
        .gaps()
        .iter()
        .all(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound));
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
    assert!(result
        .routes()
        .iter()
        .all(|route| route.coverage_state() == &CoverageState::Partial));
    assert!(result
        .routes()
        .iter()
        .all(|route| route.callback_chain().is_empty()));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnresolvedCallback));
}
'''

tests = tests.rstrip() + new_tests + "\n"

route_path.write_text(route)
model_path.write_text(model)
test_path.write_text(tests)
