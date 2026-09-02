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
    '''    let app_binding_ambiguous = has_ambiguous_express_receiver_binding(source, language, "app")?;
    let router_binding_ambiguous =
        has_ambiguous_express_receiver_binding(source, language, "router")?;
''',
    '''    let express_factory_binding_ambiguous =
        has_ambiguous_express_factory_binding(source, language)?;
    let app_binding_ambiguous = has_ambiguous_express_receiver_binding(
        source,
        language,
        "app",
        express_factory_binding_ambiguous,
    )?;
    let router_binding_ambiguous = has_ambiguous_express_receiver_binding(
        source,
        language,
        "router",
        express_factory_binding_ambiguous,
    )?;
''',
    "Express extraction binding pre-scan",
)

anchor = '''fn has_ambiguous_express_receiver_binding(
    source: &str,
    structural_language: StructuralLanguage,
    receiver: &str,
) -> Result<bool, StructuralError> {
'''
helper = r'''fn has_ambiguous_express_factory_binding(
    source: &str,
    structural_language: StructuralLanguage,
) -> Result<bool, StructuralError> {
    let language: tree_sitter::Language = match structural_language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        StructuralError::ParseFailed("Express factory binding parser returned no syntax tree".to_owned())
    })?;
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source.get(node.byte_range()) == Some("express")
            && identifier_is_binding(node)
            && !express_binding_is_known_factory_source(node, source)
        {
            return Ok(true);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(false);
            }
        }
    }
}

fn express_binding_is_known_factory_source(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        match current.kind() {
            "import_statement" => {
                let Some(module) = current.child_by_field_name("source") else {
                    return false;
                };
                return matches!(
                    source.get(module.byte_range()),
                    Some("\"express\"") | Some("'express'")
                );
            }
            "variable_declarator" | "function_declaration" | "generator_function_declaration"
            | "class_declaration" | "formal_parameters" | "required_parameter"
            | "optional_parameter" | "catch_clause" | "assignment_expression"
            | "assignment_pattern" => return false,
            "program" => return false,
            _ => ancestor = current.parent(),
        }
    }
    false
}

fn has_ambiguous_express_receiver_binding(
    source: &str,
    structural_language: StructuralLanguage,
    receiver: &str,
    express_factory_binding_ambiguous: bool,
) -> Result<bool, StructuralError> {
'''
route = replace_one(route, anchor, helper, "Express factory shadowing helper")
route = replace_one(
    route,
    '''            && identifier_is_binding(node)
            && !express_binding_is_known_receiver(node, source)
''',
    '''            && identifier_is_binding(node)
            && !express_binding_is_known_receiver(
                node,
                source,
                express_factory_binding_ambiguous,
            )
''',
    "Express receiver proof call",
)
route = replace_one(
    route,
    '''fn express_binding_is_known_receiver(node: tree_sitter::Node<'_>, source: &str) -> bool {
''',
    '''fn express_binding_is_known_receiver(
    node: tree_sitter::Node<'_>,
    source: &str,
    express_factory_binding_ambiguous: bool,
) -> bool {
''',
    "Express receiver proof signature",
)
route = replace_one(
    route,
    '''                return is_bounded_express_factory_call(value, source);
''',
    '''                return !express_factory_binding_ambiguous
                    && is_bounded_express_factory_call(value, source);
''',
    "Express factory ambiguity gate",
)
ROUTE.write_text(route)


tests = TESTS.read_text()
if "shadowed_express_factory_binding_is_ambiguous" in tests:
    raise SystemExit("round-seven regression tests already present")
addition = r'''

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
'''
TESTS.write_text(tests + addition)
