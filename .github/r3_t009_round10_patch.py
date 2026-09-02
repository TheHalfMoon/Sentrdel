from pathlib import Path

route_path = Path("crates/sentrdel-review/src/business_logic/route.rs")
test_path = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")

route = route_path.read_text()
old = '''            "variable_declarator" => {
                let Some(value) = current.child_by_field_name("value") else {
                    return false;
                };
                return express_factory_binding_proven
                    && is_bounded_express_factory_call(value, source);
            }
'''
new = '''            "variable_declarator" => {
                let Some(name) = current.child_by_field_name("name") else {
                    return false;
                };
                let node_is_bare_declarator_name = name.kind() == "identifier"
                    && node.start_byte() == name.start_byte()
                    && node.end_byte() == name.end_byte();
                if !node_is_bare_declarator_name {
                    return false;
                }
                let Some(value) = current.child_by_field_name("value") else {
                    return false;
                };
                return express_factory_binding_proven
                    && is_bounded_express_factory_call(value, source);
            }
'''
if route.count(old) != 1:
    raise SystemExit("receiver variable declarator anchor mismatch")
route_path.write_text(route.replace(old, new))

tests = test_path.read_text()
anchor = '''#[test]
fn canonical_express_package_import_factory_remains_supported() {
'''
insert = '''#[test]
fn destructured_express_factory_results_are_ambiguous() {
    for source in [
        b"import express from 'express';\\nconst { app } = express();\\napp.get('/object-destructure', handler);".as_slice(),
        b"import express from 'express';\\nconst { runtime: app } = express();\\napp.get('/alias-destructure', handler);".as_slice(),
        b"import express from 'express';\\nconst [app] = express();\\napp.get('/array-destructure', handler);".as_slice(),
        b"import express from 'express';\\nconst { router } = express.Router();\\nrouter.post('/router-destructure', handler);".as_slice(),
    ] {
        let result = extract_routes(
            RouteAdapter::Express,
            StructuralLanguage::JavaScript,
            &path("src/destructured-express-factory.js"),
            source,
            BusinessLogicLimits::default(),
        )
        .expect("classify destructured Express factory result as ambiguous");

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
'''
if tests.count(anchor) != 1:
    raise SystemExit("canonical factory test anchor mismatch")
test_path.write_text(tests.replace(anchor, insert))
