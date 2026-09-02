from pathlib import Path

route = Path("crates/sentrdel-review/src/business_logic/route.rs")
text = route.read_text(encoding="utf-8")

start = text.index("fn extract_next_pages(")
end = text.index("\nfn extract_supabase_edge(", start)
new_next_pages = r'''fn extract_next_pages(
    source: &str,
    mask: &[u8],
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let Some(route_pattern) = next_pages_route_pattern(builder.path.as_str()) else {
        builder.gap(
            RouteCoverageGapReason::UnsupportedRouteFile,
            0,
            source.len(),
        )?;
        return Ok(());
    };

    let mut search_index = 0usize;
    let mut default_export = None;
    while let Some(export_start) = find_word(mask, b"export", search_index) {
        let cursor = skip_mask_ws(mask, export_start + "export".len());
        if let Some(default_end) = parse_ident_end_if_any(mask, cursor)
            && &source[cursor..default_end] == "default"
        {
            default_export = Some((export_start, skip_mask_ws(mask, default_end)));
            break;
        }
        search_index = export_start + "export".len();
    }

    let Some((export_start, value_start)) = default_export else {
        builder.gap(
            RouteCoverageGapReason::UnsupportedHandlerExport,
            0,
            source.len(),
        )?;
        return Ok(());
    };

    if !looks_like_function_value(mask, value_start) {
        builder.gap(
            RouteCoverageGapReason::UnsupportedHandlerExport,
            export_start,
            source.len(),
        )?;
        return Ok(());
    }

    let mut cursor = value_start;
    if let Some(async_end) = parse_ident_end_if_any(mask, cursor)
        && &source[cursor..async_end] == "async"
    {
        cursor = skip_mask_ws(mask, async_end);
    }

    let handler_key = if let Some(token_end) = parse_ident_end_if_any(mask, cursor) {
        if &source[cursor..token_end] == "function" {
            cursor = skip_mask_ws(mask, token_end);
            parse_ident_end_if_any(mask, cursor)
                .map(|handler_end| source[cursor..handler_end].to_owned())
                .unwrap_or_else(|| format!("inline@{export_start}"))
        } else {
            format!("inline@{export_start}")
        }
    } else {
        format!("inline@{export_start}")
    };

    let callbacks = vec![handler_key.clone()];
    builder.route(
        HttpMethod::OtherSupported,
        "next-pages-api-default-handler",
        &route_pattern,
        &handler_key,
        &callbacks,
        export_start,
        source.len(),
        CoverageState::Partial,
    )?;
    builder.gap(
        RouteCoverageGapReason::MethodNotStaticallyBound,
        export_start,
        source.len(),
    )?;
    Ok(())
}
'''
text = text[:start] + new_next_pages + text[end:]

start = text.index("fn code_mask(")
end = text.index("\nfn find_word(", start)
new_mask = r'''fn code_mask(source: &str) -> Vec<u8> {
    let bytes = source.as_bytes();
    let mut mask = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' | b'"' | b'`' => {
                let quote = bytes[index];
                mask[index] = b' ';
                index += 1;
                while index < bytes.len() {
                    mask[index] = b' ';
                    if bytes[index] == b'\\' {
                        index += 1;
                        if index < bytes.len() {
                            mask[index] = b' ';
                            index += 1;
                        }
                        continue;
                    }
                    if bytes[index] == quote {
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                mask[index] = b' ';
                mask[index + 1] = b' ';
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    mask[index] = b' ';
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                mask[index] = b' ';
                mask[index + 1] = b' ';
                index += 2;
                while index < bytes.len() {
                    mask[index] = b' ';
                    if bytes.get(index) == Some(&b'*')
                        && bytes.get(index + 1) == Some(&b'/')
                    {
                        mask[index + 1] = b' ';
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            b'/' if regex_literal_can_start(&mask, index) => {
                let end = regex_literal_end(bytes, index).unwrap_or(bytes.len());
                mask[index..end].fill(b' ');
                index = end;
            }
            _ => index += 1,
        }
    }
    mask
}

fn skip_literal_or_comment(bytes: &[u8], index: usize) -> Option<usize> {
    let byte = *bytes.get(index)?;
    if matches!(byte, b'\'' | b'"' | b'`') {
        let quote = byte;
        let mut cursor = index + 1;
        while cursor < bytes.len() {
            if bytes[cursor] == b'\\' {
                cursor = cursor.saturating_add(2);
                continue;
            }
            if bytes[cursor] == quote {
                return Some(cursor + 1);
            }
            cursor += 1;
        }
        return Some(bytes.len());
    }
    if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
        let mut cursor = index + 2;
        while cursor < bytes.len() && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        return Some(cursor);
    }
    if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
        let mut cursor = index + 2;
        while cursor + 1 < bytes.len() {
            if bytes[cursor] == b'*' && bytes[cursor + 1] == b'/' {
                return Some(cursor + 2);
            }
            cursor += 1;
        }
        return Some(bytes.len());
    }
    if byte == b'/' && regex_literal_can_start(bytes, index) {
        return Some(regex_literal_end(bytes, index).unwrap_or(bytes.len()));
    }
    None
}

fn regex_literal_can_start(code: &[u8], index: usize) -> bool {
    let Some(previous) = (0..index)
        .rev()
        .find(|candidate| !code[*candidate].is_ascii_whitespace())
    else {
        return true;
    };

    if matches!(
        code[previous],
        b'(' | b',' | b'=' | b':' | b';' | b'!' | b'&' | b'|' | b'?' | b'{'
            | b'}' | b'[' | b'+' | b'-' | b'*' | b'%' | b'~' | b'^' | b'<' | b'>'
    ) {
        return true;
    }
    if !is_ident_continue(code[previous]) {
        return false;
    }

    let end = previous + 1;
    let mut start = previous;
    while start > 0 && is_ident_continue(code[start - 1]) {
        start -= 1;
    }
    let keyword = &code[start..end];
    keyword == b"return"
        || keyword == b"throw"
        || keyword == b"case"
        || keyword == b"delete"
        || keyword == b"void"
        || keyword == b"typeof"
        || keyword == b"instanceof"
        || keyword == b"in"
        || keyword == b"of"
        || keyword == b"yield"
        || keyword == b"await"
        || keyword == b"new"
}

fn regex_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'/') {
        return None;
    }

    let mut index = start + 1;
    let mut in_character_class = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index = index.saturating_add(2),
            b'[' if !in_character_class => {
                in_character_class = true;
                index += 1;
            }
            b']' if in_character_class => {
                in_character_class = false;
                index += 1;
            }
            b'/' if !in_character_class => {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                    index += 1;
                }
                return Some(index);
            }
            b'\n' | b'\r' => return None,
            _ => index += 1,
        }
    }
    None
}
'''
text = text[:start] + new_mask + text[end:]
route.write_text(text, encoding="utf-8", newline="\n")

tests = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
text = tests.read_text(encoding="utf-8")
marker = '''const MALFORMED: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/malformed-source/src/broken.js"
);
'''
assert text.count(marker) == 1, text.count(marker)
text = text.replace(
    marker,
    marker
    + '''const REGEX_LITERAL_ROUTE_SHAPE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/regex-literal/src/route-shaped.js"
);
''',
    1,
)

marker = "#[test]\nfn supabase_edge_deno_serve_is_bounded_and_method_partial() {"
assert text.count(marker) == 1, text.count(marker)
next_pages_tests = r'''#[test]
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::MethodNotStaticallyBound));
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
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport));
}

'''
text = text.replace(marker, next_pages_tests + marker, 1)

marker = "#[test]\nfn callback_cap_fails_closed() {"
assert text.count(marker) == 1, text.count(marker)
regex_test = r'''#[test]
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
    assert!(!result
        .routes()
        .iter()
        .any(|route| route.route_pattern() == "x"));
}

'''
text = text.replace(marker, regex_test + marker, 1)
tests.write_text(text, encoding="utf-8", newline="\n")

fixture = Path("fixtures/repos/r3-business-logic/adversarial/regex-literal/src/route-shaped.js")
fixture.parent.mkdir(parents=True, exist_ok=True)
fixture.write_text(
    "const routeLike = /app.get('x', handler)/;\n"
    "const delimiterLike = /[)]callback[(]/;\n"
    "app.get('/real', (req, res) => delimiterLike.test(req.path) ? handler(req, res) : res.end());\n",
    encoding="utf-8",
    newline="\n",
)
