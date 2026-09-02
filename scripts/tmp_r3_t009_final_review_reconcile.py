from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


route_path = Path("crates/sentrdel-review/src/business_logic/route.rs")
route = route_path.read_text()

route = replace_once(
    route,
    """        let mut cursor = skip_mask_ws(mask, receiver_end);\n        if mask.get(cursor) == Some(&b'[')\n""",
    """        let mut cursor = skip_mask_ws(mask, receiver_end);\n        if mask.get(cursor..cursor.saturating_add(2)) == Some(b\"?.\") {\n            let member_start = skip_mask_ws(mask, cursor + 2);\n            if let Some(member_end) = parse_ident_end_if_any(mask, member_start) {\n                let registration = &source[member_start..member_end];\n                let call_start = skip_mask_ws(mask, member_end);\n                if is_express_registration_name(registration)\n                    && mask.get(call_start) == Some(&b'(')\n                {\n                    let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {\n                        return Err(RouteExtractionError::Structural(\n                            StructuralError::MalformedSyntax,\n                        ));\n                    };\n                    builder.gap(\n                        RouteCoverageGapReason::DynamicRegistration,\n                        receiver_start,\n                        call_end + 1,\n                    )?;\n                    index = call_end + 1;\n                    continue;\n                }\n            }\n        }\n        if mask.get(cursor) == Some(&b'[')\n""",
    "optional-chained Express registration",
)

route = replace_once(
    route,
    """        if registration == \"use\" && mask.get(after_registration) == Some(&b'(') {\n""",
    """        if matches!(registration, \"use\" | \"param\")\n            && mask.get(after_registration) == Some(&b'(')\n        {\n""",
    "Express param middleware",
)

route = replace_once(
    route,
    """        )?;\n        index = call_end + 1;\n    }\n    Ok(())\n}\n\nfn extract_next_app(\n""",
    """        )?;\n        let suffix_dot = skip_mask_ws(mask, call_end + 1);\n        if mask.get(suffix_dot) == Some(&b'.') {\n            let member_start = skip_mask_ws(mask, suffix_dot + 1);\n            if let Some(member_end) = parse_ident_end_if_any(mask, member_start) {\n                let registration = &source[member_start..member_end];\n                let suffix_call_start = skip_mask_ws(mask, member_end);\n                if is_express_registration_name(registration)\n                    && mask.get(suffix_call_start) == Some(&b'(')\n                {\n                    let Some(suffix_call_end) =\n                        find_balanced(mask, suffix_call_start, b'(', b')')\n                    else {\n                        return Err(RouteExtractionError::Structural(\n                            StructuralError::MalformedSyntax,\n                        ));\n                    };\n                    builder.gap(\n                        RouteCoverageGapReason::DynamicRegistration,\n                        suffix_dot,\n                        suffix_call_end + 1,\n                    )?;\n                    index = suffix_call_end + 1;\n                    continue;\n                }\n            }\n        }\n        index = call_end + 1;\n    }\n    Ok(())\n}\n\nfn extract_next_app(\n""",
    "fluent Express suffix",
)

route = replace_once(
    route,
    """                    if mask.get(rhs) == Some(&b'=') {\n                        rhs = skip_mask_ws(mask, rhs + 1);\n                        if looks_like_function_value(mask, rhs) {\n                            let callback_keys = vec![name.to_owned()];\n                            builder.route(\n                                method,\n                                \"next-app-route-handler\",\n                                &route_pattern,\n                                name,\n                                &callback_keys,\n                                export_start,\n                                name_end,\n                                CoverageState::Covered,\n                            )?;\n                            found = true;\n                        } else {\n                            builder.gap(\n                                RouteCoverageGapReason::UnsupportedHandlerExport,\n                                export_start,\n                                name_end,\n                            )?;\n                        }\n                    }\n""",
    """                    if mask.get(rhs) == Some(&b'=') {\n                        rhs = skip_mask_ws(mask, rhs + 1);\n                        if looks_like_function_value(mask, rhs) {\n                            let callback_keys = vec![name.to_owned()];\n                            builder.route(\n                                method,\n                                \"next-app-route-handler\",\n                                &route_pattern,\n                                name,\n                                &callback_keys,\n                                export_start,\n                                name_end,\n                                CoverageState::Covered,\n                            )?;\n                            found = true;\n                        } else {\n                            builder.gap(\n                                RouteCoverageGapReason::UnsupportedHandlerExport,\n                                export_start,\n                                name_end,\n                            )?;\n                        }\n                    } else {\n                        builder.gap(\n                            RouteCoverageGapReason::UnsupportedHandlerExport,\n                            export_start,\n                            name_end,\n                        )?;\n                    }\n""",
    "typed Next App method declaration visibility",
)

route = replace_once(
    route,
    """        | \"import_specifier\"\n        | \"namespace_import\"\n""",
    """        | \"import_specifier\"\n        | \"import_clause\"\n        | \"namespace_import\"\n""",
    "default-imported Deno binding",
)

route = replace_once(
    route,
    """fn parse_express_http_method(value: &str) -> Option<HttpMethod> {\n""",
    """fn is_express_registration_name(value: &str) -> bool {\n    parse_express_http_method(value).is_some()\n        || matches!(value, \"all\" | \"param\" | \"route\" | \"use\")\n}\n\nfn parse_express_http_method(value: &str) -> Option<HttpMethod> {\n""",
    "Express registration-name helper",
)

route_path.write_text(route)

test_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
tests = test_path.read_text()
marker = """#[test]\nfn deno_serve_non_function_literal_is_unresolved() {\n"""
insert = r'''#[test]
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedMiddleware));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::DynamicRegistration));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding));
}

'''
tests = replace_once(tests, marker, insert + marker, "focused review regression insertion")
test_path.write_text(tests)
