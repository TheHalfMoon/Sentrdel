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
    '''        let registration = &source[cursor..method_end];
        let after_registration = skip_mask_ws(mask, method_end);
        if registration == "route" && mask.get(after_registration) == Some(&b'(') {
''',
    '''        let registration = &source[cursor..method_end];
        let after_registration = skip_mask_ws(mask, method_end);
        if is_express_registration_name(registration)
            && mask.get(after_registration..after_registration.saturating_add(2)) == Some(b"?.")
        {
            let optional_call_start = skip_mask_ws(mask, after_registration + 2);
            if mask.get(optional_call_start) == Some(&b'(') {
                let Some(call_end) = find_balanced(mask, optional_call_start, b'(', b')') else {
                    return Err(RouteExtractionError::Structural(
                        StructuralError::MalformedSyntax,
                    ));
                };
                builder.gap(
                    RouteCoverageGapReason::DynamicRegistration,
                    receiver_start,
                    call_end + 1,
                )?;
                index = call_end + 1;
                continue;
            }
        }
        if registration == "route" && mask.get(after_registration) == Some(&b'(') {
''',
    "optional Express method invocation",
)

route = replace_once(
    route,
    '''        let after_path = skip_source_ws_and_comments(source, after_path, call_end);
        // Express overloads app.get(name) as an application-setting getter. It is not a route.
        if method == HttpMethod::Get && after_path >= call_end {
''',
    '''        let after_path = skip_source_ws_and_comments(source, after_path, call_end);
        if after_path < call_end && bytes[after_path] != b',' {
            builder.gap(
                RouteCoverageGapReason::DynamicRoutePattern,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        // Express overloads app.get(name) as an application-setting getter. It is not a route.
        if method == HttpMethod::Get && after_path >= call_end {
''',
    "complete Express literal route expression",
)

route = replace_once(
    route,
    '''                    } else {
                        builder.gap(
                            RouteCoverageGapReason::UnsupportedHandlerExport,
                            export_start,
                            name_end,
                        )?;
                    }
                }
            }
        } else if mask.get(cursor) == Some(&b'{')
''',
    '''                    } else {
                        builder.gap(
                            RouteCoverageGapReason::UnsupportedHandlerExport,
                            export_start,
                            name_end,
                        )?;
                    }
                }
                surface_additional_next_const_methods(source, mask, name_end, builder)?;
            }
        } else if mask.get(cursor) == Some(&b'{')
''',
    "Next App multi-declarator visibility",
)

route = replace_once(
    route,
    '''fn export_list_mentions_next_http_method(
''',
    '''fn surface_additional_next_const_methods(
    source: &str,
    mask: &[u8],
    mut index: usize,
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    while index < mask.len() {
        match mask[index] {
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b';' if paren == 0 && brace == 0 && bracket == 0 => break,
            b',' if paren == 0 && brace == 0 && bracket == 0 => {
                let name_start = skip_mask_ws(mask, index + 1);
                if let Some(name_end) = parse_ident_end_if_any(mask, name_start) {
                    let name = &source[name_start..name_end];
                    let after_name = skip_mask_ws(mask, name_end);
                    if parse_next_http_method(name).is_some()
                        && matches!(mask.get(after_name), Some(&b'=') | Some(&b':'))
                    {
                        builder.gap(
                            RouteCoverageGapReason::UnsupportedHandlerExport,
                            name_start,
                            name_end,
                        )?;
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn export_list_mentions_next_http_method(
''',
    "Next App additional declarator helper",
)

route = replace_once(
    route,
    '''        "assignment_expression" => same_as_field("left"),
        "formal_parameters"
''',
    '''        "assignment_expression" | "assignment_pattern" => same_as_field("left"),
        "pair_pattern" => same_as_field("value"),
        "object_pattern" | "array_pattern" => true,
        "formal_parameters"
''',
    "destructured Deno binding visibility",
)

route_path.write_text(route)

tests_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
tests = tests_path.read_text()
anchor = '''#[test]
fn deno_serve_non_function_literal_is_unresolved() {
'''
additions = r'''#[test]
fn next_app_multi_declarator_method_export_keeps_additional_method_visible() {
    let source = b"export const GET = () => new Response('get'), POST = () => new Response('post');\n";
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

'''
tests = replace_once(tests, anchor, additions + anchor, "fresh exact-head regression insertion")
tests_path.write_text(tests)
