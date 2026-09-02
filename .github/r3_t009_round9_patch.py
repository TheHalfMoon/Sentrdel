from pathlib import Path

route_path = Path("crates/sentrdel-review/src/business_logic/route.rs")
test_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")

route = route_path.read_text()
old = '''    let express_factory_binding_ambiguous =
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
'''
new = '''    let express_factory_binding_proven =
        has_proven_express_factory_binding(source, language)?;
    let app_binding_ambiguous = has_ambiguous_express_receiver_binding(
        source,
        language,
        "app",
        express_factory_binding_proven,
    )?;
    let router_binding_ambiguous = has_ambiguous_express_receiver_binding(
        source,
        language,
        "router",
        express_factory_binding_proven,
    )?;
'''
if route.count(old) != 1:
    raise SystemExit("extract_express factory-state anchor mismatch")
route = route.replace(old, new)

old = '''fn has_ambiguous_express_factory_binding(
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
        StructuralError::ParseFailed(
            "Express factory binding parser returned no syntax tree".to_owned(),
        )
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
'''
new = '''fn has_proven_express_factory_binding(
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
        StructuralError::ParseFailed(
            "Express factory binding parser returned no syntax tree".to_owned(),
        )
    })?;
    let mut found_default_import = false;
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source.get(node.byte_range()) == Some("express")
            && identifier_is_binding(node)
        {
            if express_binding_is_known_factory_source(node, source) {
                found_default_import = true;
            } else {
                return Ok(false);
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(found_default_import);
            }
        }
    }
}
'''
if route.count(old) != 1:
    raise SystemExit("factory proof helper anchor mismatch")
route = route.replace(old, new)

old = '''fn has_ambiguous_express_receiver_binding(
    source: &str,
    structural_language: StructuralLanguage,
    receiver: &str,
    express_factory_binding_ambiguous: bool,
) -> Result<bool, StructuralError> {
'''
new = '''fn has_ambiguous_express_receiver_binding(
    source: &str,
    structural_language: StructuralLanguage,
    receiver: &str,
    express_factory_binding_proven: bool,
) -> Result<bool, StructuralError> {
'''
if route.count(old) != 1:
    raise SystemExit("receiver helper signature anchor mismatch")
route = route.replace(old, new)

old = '''            && !express_binding_is_known_receiver(node, source, express_factory_binding_ambiguous)
'''
new = '''            && !express_binding_is_known_receiver(node, source, express_factory_binding_proven)
'''
if route.count(old) != 1:
    raise SystemExit("receiver proof call anchor mismatch")
route = route.replace(old, new)

old = '''fn express_binding_is_known_receiver(
    node: tree_sitter::Node<'_>,
    source: &str,
    express_factory_binding_ambiguous: bool,
) -> bool {
'''
new = '''fn express_binding_is_known_receiver(
    node: tree_sitter::Node<'_>,
    source: &str,
    express_factory_binding_proven: bool,
) -> bool {
'''
if route.count(old) != 1:
    raise SystemExit("receiver proof signature anchor mismatch")
route = route.replace(old, new)

old = '''                return !express_factory_binding_ambiguous
                    && is_bounded_express_factory_call(value, source);
'''
new = '''                return express_factory_binding_proven
                    && is_bounded_express_factory_call(value, source);
'''
if route.count(old) != 1:
    raise SystemExit("receiver factory provenance anchor mismatch")
route = route.replace(old, new)
route_path.write_text(route)

tests = test_path.read_text()
old = '''#[test]
fn bounded_express_factory_bindings_remain_supported() {
    let source = b"const app = express();\\nconst router = express.Router();\\napp.get('/app', handler);\\nrouter.post('/router', handler);\\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/factories.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve bounded Express factory bindings");

    assert_eq!(result.routes().len(), 2);
    assert!(result.gaps().is_empty());
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/app")
    );
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/router")
    );
}
'''
new = '''#[test]
fn unbound_express_factory_bindings_are_ambiguous() {
    for source in [
        b"const app = express();\\napp.get('/unbound-app', handler);".as_slice(),
        b"const router = express.Router();\\nrouter.post('/unbound-router', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/unbound-express-factory.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify unbound Express factory provenance as ambiguous");

        assert!(result.routes().is_empty());
        assert_eq!(
            result
                .gaps()
                .iter()
                .filter(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
                .count(),
            1
        );
    }
}
'''
if tests.count(old) != 1:
    raise SystemExit("unbound factory regression anchor mismatch")
tests = tests.replace(old, new)
test_path.write_text(tests)
