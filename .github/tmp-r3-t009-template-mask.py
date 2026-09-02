from pathlib import Path

route_path = Path("crates/sentrdel-review/src/business_logic/route.rs")
test_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
route = route_path.read_text()
tests = test_path.read_text()

start = route.index("fn code_mask(")
end = route.index("\nfn find_word(", start)
new_block = r'''fn code_mask(language: StructuralLanguage, source: &str) -> Result<Vec<u8>, StructuralError> {
    let mut mask = source.as_bytes().to_vec();
    for (start, end) in non_code_ranges(language, source)? {
        mask[start..end].fill(b' ');
    }
    Ok(mask)
}

fn non_code_ranges(
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
        StructuralError::ParseFailed("route mask parser returned no syntax tree".to_owned())
    })?;

    let mut ranges = Vec::new();
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        match node.kind() {
            "string" | "comment" | "regex" => {
                ranges.push((node.start_byte(), node.end_byte()));
            }
            "template_string" => push_template_literal_ranges(node, &mut ranges),
            _ => {}
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(merge_mask_ranges(ranges));
            }
        }
    }
}

fn push_template_literal_ranges(node: tree_sitter::Node<'_>, ranges: &mut Vec<(usize, usize)>) {
    let mut visible_end = node.start_byte();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "template_substitution" {
                if visible_end < child.start_byte() {
                    ranges.push((visible_end, child.start_byte()));
                }
                visible_end = child.end_byte();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    if visible_end < node.end_byte() {
        ranges.push((visible_end, node.end_byte()));
    }
}

fn merge_mask_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if start >= end {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}
'''
route = route[:start] + new_block + route[end:]

needle = '''#[test]\nfn express_use_middleware_is_explicit_coverage_gap() {'''
if needle not in tests:
    raise SystemExit("test insertion anchor not found")
regression = r'''#[test]
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

'''
tests = tests.replace(needle, regression + needle, 1)

route_path.write_text(route)
test_path.write_text(tests)
