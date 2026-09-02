from pathlib import Path

ROUTE = Path("crates/sentrdel-review/src/business_logic/route.rs")
TESTS = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")


def replace_one(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


route = ROUTE.read_text()
old = r'''fn express_binding_is_known_factory_source(node: tree_sitter::Node<'_>, source: &str) -> bool {
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
            "variable_declarator"
            | "function_declaration"
            | "generator_function_declaration"
            | "class_declaration"
            | "formal_parameters"
            | "required_parameter"
            | "optional_parameter"
            | "catch_clause"
            | "assignment_expression"
            | "assignment_pattern" => return false,
            "program" => return false,
            _ => ancestor = current.parent(),
        }
    }
    false
}
'''
new = r'''fn express_binding_is_known_factory_source(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "import_clause" {
        return false;
    }

    let mut ancestor = Some(parent);
    while let Some(current) = ancestor {
        if current.kind() == "import_statement" {
            let Some(module) = current.child_by_field_name("source") else {
                return false;
            };
            return matches!(
                source.get(module.byte_range()),
                Some("\"express\"") | Some("'express'")
            );
        }
        ancestor = current.parent();
    }
    false
}
'''
route = replace_one(route, old, new, "default Express import proof")
ROUTE.write_text(route)


tests = TESTS.read_text()
if "named_and_namespace_express_imports_are_ambiguous" in tests:
    raise SystemExit("round-eight regressions already present")
addition = r'''

#[test]
fn named_and_namespace_express_imports_are_ambiguous() {
    for source in [
        b"import { json as express } from 'express';\nconst app = express();\napp.get('/named-alias', handler);".as_slice(),
        b"import * as express from 'express';\nconst app = express();\napp.get('/namespace-import', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/ambiguous-express-import.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify non-default Express imports as ambiguous");

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
fn default_express_import_with_named_imports_remains_supported() {
    let source = b"import express, { json } from 'express';\nconst app = express();\napp.get('/default-plus-named', handler);\n";
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/default-express-import.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve default Express factory binding");

    assert_eq!(result.routes().len(), 1);
    assert_eq!(result.routes()[0].route_pattern(), "/default-plus-named");
    assert!(result.gaps().is_empty());
}
'''
TESTS.write_text(tests + addition)
