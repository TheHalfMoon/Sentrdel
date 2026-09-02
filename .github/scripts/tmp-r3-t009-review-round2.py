from pathlib import Path

route = Path("crates/sentrdel-review/src/business_logic/route.rs")
text = route.read_text(encoding="utf-8")

old = """pub enum RouteCoverageGapReason {\n    DynamicRegistration,\n    DynamicRoutePattern,\n    UnresolvedCallback,\n"""
new = """pub enum RouteCoverageGapReason {\n    DynamicRegistration,\n    DynamicRoutePattern,\n    UnsupportedMiddleware,\n    UnresolvedCallback,\n"""
assert text.count(old) == 1, text.count(old)
text = text.replace(old, new, 1)

old = "let end = find_call_close(bytes, after).unwrap_or(after);"
assert text.count(old) == 1, text.count(old)
text = text.replace(old, "let end = find_balanced(mask, after, b'(', b')').unwrap_or(after);", 1)

old = """        let method_end = parse_ident_end(mask, cursor);\n        let Some(method) = parse_http_method(&source[cursor..method_end]) else {\n            index = method_end;\n            continue;\n        };\n        cursor = skip_mask_ws(mask, method_end);\n"""
new = """        let method_end = parse_ident_end(mask, cursor);\n        let registration = &source[cursor..method_end];\n        let after_registration = skip_mask_ws(mask, method_end);\n        if registration.eq_ignore_ascii_case(\"use\")\n            && mask.get(after_registration) == Some(&b'(')\n        {\n            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {\n                return Err(RouteExtractionError::Structural(\n                    StructuralError::MalformedSyntax,\n                ));\n            };\n            builder.gap(\n                RouteCoverageGapReason::UnsupportedMiddleware,\n                receiver_start,\n                call_end + 1,\n            )?;\n            index = call_end + 1;\n            continue;\n        }\n        let Some(method) = parse_http_method(registration) else {\n            index = method_end;\n            continue;\n        };\n        cursor = after_registration;\n"""
assert text.count(old) == 1, text.count(old)
text = text.replace(old, new, 1)

old = "find_call_close(bytes, call_start)"
assert text.count(old) == 2, text.count(old)
text = text.replace(old, "find_balanced(mask, call_start, b'(', b')')")

old = "split_top_level_args(source, after_path + 1, call_end)"
assert text.count(old) == 1, text.count(old)
text = text.replace(old, "split_top_level_args(source, mask, after_path + 1, call_end)", 1)
old = "split_top_level_args(source, call_start + 1, call_end)"
assert text.count(old) == 1, text.count(old)
text = text.replace(old, "split_top_level_args(source, mask, call_start + 1, call_end)", 1)

start = text.index("fn split_top_level_args(")
end = text.index("\nfn parse_string_literal(", start)
new_split = r'''fn split_top_level_args(
    source: &str,
    mask: &[u8],
    start: usize,
    end: usize,
) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut args = Vec::new();
    let mut item_start = start;
    let mut index = start;
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    while index < end {
        match mask[index] {
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b',' if paren == 0 && brace == 0 && bracket == 0 => {
                let (trimmed_start, trimmed_end) = trim_range(bytes, item_start, index);
                if trimmed_start < trimmed_end {
                    args.push((trimmed_start, trimmed_end));
                }
                item_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    let (trimmed_start, trimmed_end) = trim_range(bytes, item_start, end);
    if trimmed_start < trimmed_end {
        args.push((trimmed_start, trimmed_end));
    }
    args
}
'''
text = text[:start] + new_split + text[end:]

start = text.index("fn find_call_close(")
end = text.index("\nfn find_balanced(", start)
text = text[:start] + text[end + 1:]

start = text.index("fn skip_literal_or_comment(")
end = text.index("\nfn regex_literal_can_start(", start)
text = text[:start] + text[end + 1:]

old = """    if matches!(\n        code[previous],\n        b'(' | b','\n            | b'='\n            | b':'\n            | b';'\n            | b'!'\n            | b'&'\n            | b'|'\n            | b'?'\n            | b'{'\n            | b'}'\n            | b'['\n            | b'+'\n            | b'-'\n            | b'*'\n            | b'%'\n            | b'~'\n            | b'^'\n            | b'<'\n            | b'>'\n    ) {\n        return true;\n    }\n    if !is_ident_continue(code[previous]) {\n"""
new = """    if matches!(\n        code[previous],\n        b'(' | b','\n            | b'='\n            | b':'\n            | b';'\n            | b'!'\n            | b'&'\n            | b'|'\n            | b'?'\n            | b'{'\n            | b'}'\n            | b'['\n            | b'+'\n            | b'-'\n            | b'*'\n            | b'%'\n            | b'~'\n            | b'^'\n            | b'<'\n            | b'>'\n    ) {\n        return true;\n    }\n    if code[previous] == b')' && control_flow_close_allows_regex(code, previous) {\n        return true;\n    }\n    if !is_ident_continue(code[previous]) {\n"""
assert text.count(old) == 1, text.count(old)
text = text.replace(old, new, 1)

old = """        || keyword == b\"yield\"\n        || keyword == b\"await\"\n        || keyword == b\"new\"\n}\n\nfn regex_literal_end"""
new = """        || keyword == b\"yield\"\n        || keyword == b\"await\"\n        || keyword == b\"new\"\n        || keyword == b\"else\"\n        || keyword == b\"do\"\n}\n\nfn control_flow_close_allows_regex(code: &[u8], close: usize) -> bool {\n    let mut depth = 1usize;\n    let mut cursor = close;\n    while cursor > 0 {\n        cursor -= 1;\n        match code[cursor] {\n            b')' => depth += 1,\n            b'(' => {\n                depth -= 1;\n                if depth == 0 {\n                    return preceding_control_flow_keyword(code, cursor);\n                }\n            }\n            _ => {}\n        }\n    }\n    false\n}\n\nfn preceding_control_flow_keyword(code: &[u8], open: usize) -> bool {\n    let Some(previous) = (0..open)\n        .rev()\n        .find(|candidate| !code[*candidate].is_ascii_whitespace())\n    else {\n        return false;\n    };\n    if !is_ident_continue(code[previous]) {\n        return false;\n    }\n\n    let end = previous + 1;\n    let mut start = previous;\n    while start > 0 && is_ident_continue(code[start - 1]) {\n        start -= 1;\n    }\n    matches!(\n        &code[start..end],\n        b\"if\" | b\"while\" | b\"for\" | b\"with\" | b\"switch\" | b\"catch\"\n    )\n}\n\nfn regex_literal_end"""
assert text.count(old) == 1, text.count(old)
text = text.replace(old, new, 1)

route.write_text(text, encoding="utf-8", newline="\n")

tests = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
text = tests.read_text(encoding="utf-8")
marker = "#[test]\nfn callback_cap_fails_closed() {"
assert text.count(marker) == 1, text.count(marker)
insert = r'''#[test]
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
    let source = b"app.use('/admin', authenticationMiddleware);\nrouter.use('/tenant', tenantMiddleware);\n";
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
    assert!(result
        .gaps()
        .iter()
        .all(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedMiddleware));
}

'''
text = text.replace(marker, insert + marker, 1)
tests.write_text(text, encoding="utf-8", newline="\n")
