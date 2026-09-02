from pathlib import Path

ROUTE = Path("crates/sentrdel-review/src/business_logic/route.rs")
TESTS = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")


def replace_one(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


route = ROUTE.read_text()
old = '''fn express_binding_is_known_receiver(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        match current.kind() {
            "function_declaration" | "generator_function_declaration" => {
                return current
                    .parent()
                    .is_some_and(|parent| parent.kind() == "export_statement");
            }
            "variable_declarator" => {
                let Some(value) = current.child_by_field_name("value") else {
                    return false;
                };
                let value = source.get(value.byte_range()).unwrap_or_default();
                return value.contains("express(")
                    || value.contains("express.Router(")
                    || value.contains(".Router(");
            }
            "program" => return false,
            _ => ancestor = current.parent(),
        }
    }
    false
}
'''
new = '''fn express_binding_is_known_receiver(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        match current.kind() {
            "function_declaration" | "generator_function_declaration" => {
                let Some(parameters) = current.child_by_field_name("parameters") else {
                    return false;
                };
                let node_is_parameter = node.start_byte() >= parameters.start_byte()
                    && node.end_byte() <= parameters.end_byte();
                return node_is_parameter
                    && current
                        .parent()
                        .is_some_and(|parent| parent.kind() == "export_statement");
            }
            "variable_declarator" => {
                let Some(value) = current.child_by_field_name("value") else {
                    return false;
                };
                return is_bounded_express_factory_call(value, source);
            }
            "program" => return false,
            _ => ancestor = current.parent(),
        }
    }
    false
}

fn is_bounded_express_factory_call(value: tree_sitter::Node<'_>, source: &str) -> bool {
    if value.kind() != "call_expression" {
        return false;
    }
    let Some(function) = value.child_by_field_name("function") else {
        return false;
    };
    match function.kind() {
        "identifier" => source.get(function.byte_range()) == Some("express"),
        "member_expression" => {
            let Some(object) = function.child_by_field_name("object") else {
                return false;
            };
            let Some(property) = function.child_by_field_name("property") else {
                return false;
            };
            source.get(object.byte_range()) == Some("express")
                && source.get(property.byte_range()) == Some("Router")
        }
        _ => false,
    }
}
'''
route = replace_one(route, old, new, "Express receiver binding proof")
ROUTE.write_text(route)


tests = TESTS.read_text()
if "express_function_declaration_named_app_is_ambiguous" in tests:
    raise SystemExit("round-six regression tests already present")
addition = r'''

#[test]
fn express_function_declaration_named_app_is_ambiguous() {
    for source in [
        b"function app() {}\napp.get('/local', handler);".as_slice(),
        b"export function app() {}\napp.get('/exported-local', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/function-app.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify local function named app as ambiguous");

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
fn express_function_declaration_named_router_is_ambiguous() {
    for source in [
        b"function router() {}\nrouter.get('/local', handler);".as_slice(),
        b"export function router() {}\nrouter.get('/exported-local', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/function-router.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify local function named router as ambiguous");

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
fn bounded_express_factory_bindings_remain_supported() {
    let source = b"const app = express();\nconst router = express.Router();\napp.get('/app', handler);\nrouter.post('/router', handler);\n";
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
    assert!(result.routes().iter().any(|route| route.route_pattern() == "/app"));
    assert!(
        result
            .routes()
            .iter()
            .any(|route| route.route_pattern() == "/router")
    );
}

#[test]
fn lookalike_express_factory_bindings_are_ambiguous() {
    let source = b"const app = fakeexpress();\nconst router = other.Router();\napp.get('/fake-app', handler);\nrouter.get('/fake-router', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/lookalike-factories.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject lookalike Express factory bindings");

    assert!(result.routes().is_empty());
    assert_eq!(
        result
            .gaps()
            .iter()
            .filter(|gap| gap.reason() == RouteCoverageGapReason::AmbiguousReceiverBinding)
            .count(),
        2
    );
}
'''
TESTS.write_text(tests + addition)
