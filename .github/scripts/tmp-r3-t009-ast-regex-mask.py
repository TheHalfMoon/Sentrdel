from pathlib import Path

route = Path("crates/sentrdel-review/src/business_logic/route.rs")
text = route.read_text(encoding="utf-8")
old = "    let mask = code_mask(source);\n"
new = "    let mask = code_mask(language, source)?;\n"
assert text.count(old) == 1, text.count(old)
text = text.replace(old, new, 1)

start = text.index("fn code_mask(source: &str) -> Vec<u8> {")
end = text.index("\nfn find_word(", start)
new_mask = r'''fn code_mask(
    language: StructuralLanguage,
    source: &str,
) -> Result<Vec<u8>, StructuralError> {
    let bytes = source.as_bytes();
    let mut mask = bytes.to_vec();
    let regex_ranges = regex_literal_ranges(language, source)?;
    let mut regex_index = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(&(start, end)) = regex_ranges.get(regex_index)
            && start == index
        {
            mask[start..end].fill(b' ');
            regex_index += 1;
            index = end;
            continue;
        }

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
                    if bytes.get(index) == Some(&b'*') && bytes.get(index + 1) == Some(&b'/') {
                        mask[index + 1] = b' ';
                        index += 2;
                        break;
                    }
                    index += 1;
                }
            }
            _ => index += 1,
        }
    }
    Ok(mask)
}

fn regex_literal_ranges(
    language: StructuralLanguage,
    source: &str,
) -> Result<Vec<(usize, usize)>, StructuralError> {
    let parser_language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&parser_language)
        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        StructuralError::ParseFailed("route regex parser returned no syntax tree".to_owned())
    })?;

    let mut ranges = Vec::new();
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        if node.kind() == "regex" {
            ranges.push((node.start_byte(), node.end_byte()));
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                ranges.sort_unstable();
                return Ok(ranges);
            }
        }
    }
}
'''
text = text[:start] + new_mask + text[end:]
route.write_text(text, encoding="utf-8", newline="\n")

tests = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
text = tests.read_text(encoding="utf-8")
marker = "#[test]\nfn express_use_middleware_is_explicit_coverage_gap() {"
assert text.count(marker) == 1, text.count(marker)
insert = r'''#[test]
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

'''
text = text.replace(marker, insert + marker, 1)
tests.write_text(text, encoding="utf-8", newline="\n")
