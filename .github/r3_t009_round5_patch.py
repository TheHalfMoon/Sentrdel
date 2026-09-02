from pathlib import Path

ROUTE = Path("crates/sentrdel-review/src/business_logic/route.rs")
TESTS = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")


def replace_one(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


route = ROUTE.read_text()
route = replace_one(
    route,
    "        RouteAdapter::Express => extract_express(source, &mask, &mut builder)?,\n",
    "        RouteAdapter::Express => extract_express(language, source, &mask, &mut builder)?,\n",
    "express language dispatch",
)
route = replace_one(
    route,
    "fn extract_express(\n    source: &str,\n    mask: &[u8],\n    builder: &mut ExtractionBuilder<'_>,\n) -> Result<(), RouteExtractionError> {\n    let bytes = source.as_bytes();\n",
    "fn extract_express(\n    language: StructuralLanguage,\n    source: &str,\n    mask: &[u8],\n    builder: &mut ExtractionBuilder<'_>,\n) -> Result<(), RouteExtractionError> {\n    let app_binding_ambiguous = has_ambiguous_express_receiver_binding(source, language, \"app\")?;\n    let router_binding_ambiguous =\n        has_ambiguous_express_receiver_binding(source, language, \"router\")?;\n    let bytes = source.as_bytes();\n",
    "express binding pre-scan",
)
route = replace_one(
    route,
    "        if !is_unqualified_identifier(mask, receiver_start) {\n            index = receiver_end;\n            continue;\n        }\n        let mut cursor = skip_mask_ws(mask, receiver_end);\n        if mask.get(cursor..cursor.saturating_add(2)) == Some(b\"?.\") {\n",
    "        if !is_unqualified_identifier(mask, receiver_start) {\n            index = receiver_end;\n            continue;\n        }\n        let receiver_binding_ambiguous = match receiver {\n            \"app\" => app_binding_ambiguous,\n            \"router\" => router_binding_ambiguous,\n            _ => false,\n        };\n        let mut cursor = skip_mask_ws(mask, receiver_end);\n        if mask.get(cursor) == Some(&b'!') {\n            let dot = skip_mask_ws(mask, cursor + 1);\n            if mask.get(dot) == Some(&b'.') {\n                let member_start = skip_mask_ws(mask, dot + 1);\n                if let Some(member_end) = parse_ident_end_if_any(mask, member_start) {\n                    let registration = &source[member_start..member_end];\n                    let call_start = skip_mask_ws(mask, member_end);\n                    if (is_express_registration_name(registration)\n                        || is_other_express_http_method(registration))\n                        && mask.get(call_start) == Some(&b'(')\n                    {\n                        let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {\n                            return Err(RouteExtractionError::Structural(\n                                StructuralError::MalformedSyntax,\n                            ));\n                        };\n                        builder.gap(\n                            if receiver_binding_ambiguous {\n                                RouteCoverageGapReason::AmbiguousReceiverBinding\n                            } else {\n                                RouteCoverageGapReason::DynamicRegistration\n                            },\n                            receiver_start,\n                            call_end + 1,\n                        )?;\n                        index = call_end + 1;\n                        continue;\n                    }\n                }\n            }\n        }\n        if mask.get(cursor..cursor.saturating_add(2)) == Some(b\"?.\") {\n",
    "typescript non-null express receiver",
)
route = replace_one(
    route,
    "        let method_end = parse_ident_end(mask, cursor);\n        let registration = &source[cursor..method_end];\n        let after_registration = skip_mask_ws(mask, method_end);\n        if is_express_registration_name(registration)\n",
    "        let method_end = parse_ident_end(mask, cursor);\n        let registration = &source[cursor..method_end];\n        let after_registration = skip_mask_ws(mask, method_end);\n        if receiver_binding_ambiguous\n            && (is_express_registration_name(registration)\n                || is_other_express_http_method(registration))\n        {\n            let call_start = if mask.get(after_registration) == Some(&b'(') {\n                Some(after_registration)\n            } else if mask.get(after_registration..after_registration.saturating_add(2))\n                == Some(b\"?.\")\n            {\n                let candidate = skip_mask_ws(mask, after_registration + 2);\n                (mask.get(candidate) == Some(&b'(')).then_some(candidate)\n            } else {\n                None\n            };\n            if let Some(call_start) = call_start {\n                let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {\n                    return Err(RouteExtractionError::Structural(\n                        StructuralError::MalformedSyntax,\n                    ));\n                };\n                builder.gap(\n                    RouteCoverageGapReason::AmbiguousReceiverBinding,\n                    receiver_start,\n                    call_end + 1,\n                )?;\n                index = call_end + 1;\n                continue;\n            }\n        }\n        if is_express_registration_name(registration)\n",
    "ambiguous express receiver gap",
)
route = replace_one(
    route,
    "        if registration == \"all\" && mask.get(after_registration) == Some(&b'(') {\n            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {\n                return Err(RouteExtractionError::Structural(\n                    StructuralError::MalformedSyntax,\n                ));\n            };\n            builder.gap(\n                RouteCoverageGapReason::MethodNotStaticallyBound,\n                receiver_start,\n                call_end + 1,\n            )?;\n            index = call_end + 1;\n            continue;\n        }\n        let Some(method) = parse_express_http_method(registration) else {\n",
    "        if registration == \"all\" && mask.get(after_registration) == Some(&b'(') {\n            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {\n                return Err(RouteExtractionError::Structural(\n                    StructuralError::MalformedSyntax,\n                ));\n            };\n            builder.gap(\n                RouteCoverageGapReason::MethodNotStaticallyBound,\n                receiver_start,\n                call_end + 1,\n            )?;\n            index = call_end + 1;\n            continue;\n        }\n        if is_other_express_http_method(registration)\n            && mask.get(after_registration) == Some(&b'(')\n        {\n            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {\n                return Err(RouteExtractionError::Structural(\n                    StructuralError::MalformedSyntax,\n                ));\n            };\n            builder.gap(\n                RouteCoverageGapReason::MethodNotStaticallyBound,\n                receiver_start,\n                call_end + 1,\n            )?;\n            index = call_end + 1;\n            continue;\n        }\n        let Some(method) = parse_express_http_method(registration) else {\n",
    "other express methods gap",
)
route = replace_one(
    route,
    "        } else if word == Some(\"const\") {\n            cursor = skip_mask_ws(mask, word_end.expect(\"const end\"));\n",
    "        } else if matches!(word, Some(\"const\" | \"let\" | \"var\")) {\n            cursor = skip_mask_ws(mask, word_end.expect(\"variable declaration end\"));\n",
    "next variable declaration kinds",
)
route = route.replace(
    "surface_additional_next_const_methods(source, mask, name_end, builder)?;",
    "surface_additional_next_variable_methods(source, mask, name_end, builder)?;",
)
route = route.replace(
    "fn surface_additional_next_const_methods(\n",
    "fn surface_additional_next_variable_methods(\n",
)
route = replace_one(
    route,
    "        } else if mask.get(cursor) == Some(&b'{')\n",
    "        } else if mask.get(cursor) == Some(&b'*') {\n            builder.gap(\n                RouteCoverageGapReason::UnsupportedHandlerExport,\n                export_start,\n                cursor + 1,\n            )?;\n        } else if mask.get(cursor) == Some(&b'{')\n",
    "next wildcard re-export",
)
route = replace_one(
    route,
    "            b';' if paren == 0 && brace == 0 && bracket == 0 => break,\n            b',' if paren == 0 && brace == 0 && bracket == 0 => {\n",
    "            b';' if paren == 0 && brace == 0 && bracket == 0 => break,\n            b'\\n' | b'\\r'\n                if paren == 0\n                    && brace == 0\n                    && bracket == 0\n                    && top_level_newline_ends_statement(source, index) =>\n            {\n                break;\n            }\n            b',' if paren == 0 && brace == 0 && bracket == 0 => {\n",
    "next ASI boundary",
)
route = replace_one(
    route,
    "    Ok(())\n}\n\nfn export_list_mentions_next_http_method(\n",
    "    Ok(())\n}\n\nfn top_level_newline_ends_statement(source: &str, newline: usize) -> bool {\n    let bytes = source.as_bytes();\n    let mut previous = newline;\n    while previous > 0 && bytes[previous - 1].is_ascii_whitespace() {\n        previous -= 1;\n    }\n    let previous = previous.checked_sub(1).and_then(|index| bytes.get(index)).copied();\n\n    let mut next = newline.saturating_add(1);\n    while next < bytes.len() && bytes[next].is_ascii_whitespace() {\n        next += 1;\n    }\n    if next >= bytes.len() {\n        return true;\n    }\n    if matches!(bytes[next], b',' | b'.')\n        || bytes.get(next..next.saturating_add(2)) == Some(b\"?.\")\n    {\n        return false;\n    }\n\n    !matches!(\n        previous,\n        Some(\n            b'=' | b',' | b'(' | b'[' | b'{' | b':' | b'?' | b'+' | b'-' | b'*' | b'/'\n                | b'%' | b'&' | b'|' | b'^' | b'!' | b'~' | b'<' | b'>'\n        )\n    )\n}\n\nfn export_list_mentions_next_http_method(\n",
    "next ASI helper",
)
route = replace_one(
    route,
    "fn has_local_deno_binding(source: &str) -> Result<bool, StructuralError> {\n",
    "fn has_ambiguous_express_receiver_binding(\n    source: &str,\n    structural_language: StructuralLanguage,\n    receiver: &str,\n) -> Result<bool, StructuralError> {\n    let language: tree_sitter::Language = match structural_language {\n        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),\n        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),\n    };\n    let mut parser = tree_sitter::Parser::new();\n    parser\n        .set_language(&language)\n        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;\n    let tree = parser.parse(source, None).ok_or_else(|| {\n        StructuralError::ParseFailed(\"Express binding parser returned no syntax tree\".to_owned())\n    })?;\n    let mut cursor = tree.root_node().walk();\n    loop {\n        let node = cursor.node();\n        if matches!(\n            node.kind(),\n            \"identifier\" | \"shorthand_property_identifier_pattern\"\n        ) && source.get(node.byte_range()) == Some(receiver)\n            && identifier_is_binding(node)\n            && !express_binding_is_known_receiver(node, source)\n        {\n            return Ok(true);\n        }\n        if cursor.goto_first_child() {\n            continue;\n        }\n        loop {\n            if cursor.goto_next_sibling() {\n                break;\n            }\n            if !cursor.goto_parent() {\n                return Ok(false);\n            }\n        }\n    }\n}\n\nfn express_binding_is_known_receiver(node: tree_sitter::Node<'_>, source: &str) -> bool {\n    let mut ancestor = node.parent();\n    while let Some(current) = ancestor {\n        match current.kind() {\n            \"function_declaration\" | \"generator_function_declaration\" => {\n                return current\n                    .parent()\n                    .is_some_and(|parent| parent.kind() == \"export_statement\");\n            }\n            \"variable_declarator\" => {\n                let Some(value) = current.child_by_field_name(\"value\") else {\n                    return false;\n                };\n                let value = source.get(value.byte_range()).unwrap_or_default();\n                return value.contains(\"express(\")\n                    || value.contains(\"express.Router(\")\n                    || value.contains(\".Router(\");\n            }\n            \"program\" => return false,\n            _ => ancestor = current.parent(),\n        }\n    }\n    false\n}\n\nfn has_local_deno_binding(source: &str) -> Result<bool, StructuralError> {\n",
    "express receiver binding helper",
)
route = replace_one(
    route,
    "        \"assignment_expression\" | \"assignment_pattern\" => same_as_field(\"left\"),\n        \"pair_pattern\" => same_as_field(\"value\"),\n",
    "        \"assignment_expression\" | \"assignment_pattern\" => same_as_field(\"left\"),\n        \"catch_clause\" => same_as_field(\"parameter\"),\n        \"pair_pattern\" => same_as_field(\"value\"),\n",
    "catch binding",
)
route = replace_one(
    route,
    "fn is_express_registration_name(value: &str) -> bool {\n    parse_express_http_method(value).is_some() || matches!(value, \"all\" | \"param\" | \"route\" | \"use\")\n}\n\nfn parse_express_http_method(value: &str) -> Option<HttpMethod> {\n",
    "fn is_express_registration_name(value: &str) -> bool {\n    parse_express_http_method(value).is_some()\n        || is_other_express_http_method(value)\n        || matches!(value, \"all\" | \"param\" | \"route\" | \"use\")\n}\n\nfn is_other_express_http_method(value: &str) -> bool {\n    matches!(\n        value,\n        \"connect\"\n            | \"trace\"\n            | \"copy\"\n            | \"lock\"\n            | \"mkcol\"\n            | \"move\"\n            | \"notify\"\n            | \"propfind\"\n            | \"proppatch\"\n            | \"purge\"\n            | \"report\"\n            | \"search\"\n            | \"subscribe\"\n            | \"unlock\"\n            | \"unsubscribe\"\n    )\n}\n\nfn parse_express_http_method(value: &str) -> Option<HttpMethod> {\n",
    "express extended method set",
)
route = replace_one(
    route,
    "        if part.starts_with('(') || part.starts_with('@') || part.is_empty() {\n",
    "        if part.starts_with('(')\n            || part.starts_with('@')\n            || part.starts_with('_')\n            || part.is_empty()\n        {\n",
    "next private folder",
)
ROUTE.write_text(route)


tests = TESTS.read_text()
addition = r'''

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
    assert!(result.routes().iter().any(|route| route.method() == HttpMethod::Get));
    assert!(result.routes().iter().any(|route| route.method() == HttpMethod::Post));
    assert!(result.routes().iter().any(|route| route.method() == HttpMethod::Put));
    assert!(result.gaps().is_empty());
}

#[test]
fn next_app_wildcard_reexport_is_an_explicit_gap() {
    let source = b"export function GET() { return new Response('get'); }\nexport * from './handlers';\n";
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
'''
if "fn next_app_multi_declarator_scan_stops_at_asi_boundary" in tests:
    raise SystemExit("round-five regression tests already present")
TESTS.write_text(tests + addition)
