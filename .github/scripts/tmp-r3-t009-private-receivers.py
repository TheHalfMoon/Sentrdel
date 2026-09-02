from pathlib import Path

route = Path("crates/sentrdel-review/src/business_logic/route.rs")
text = route.read_text(encoding="utf-8")
old = """fn is_unqualified_identifier(mask: &[u8], start: usize) -> bool {\n    let mut index = start;\n    while index > 0 {\n        index -= 1;\n        if !mask[index].is_ascii_whitespace() {\n            return mask[index] != b'.';\n        }\n    }\n    true\n}\n"""
new = """fn is_unqualified_identifier(mask: &[u8], start: usize) -> bool {\n    let mut index = start;\n    while index > 0 {\n        index -= 1;\n        if !mask[index].is_ascii_whitespace() {\n            return !matches!(mask[index], b'.' | b'#');\n        }\n    }\n    true\n}\n"""
assert text.count(old) == 1, text.count(old)
route.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")

tests = Path("crates/sentrdel-review/tests/r3_t009_route_extraction.rs")
text = tests.read_text(encoding="utf-8")
marker = "#[test]\nfn next_app_non_function_export_does_not_search_later_statements() {"
assert text.count(marker) == 1, text.count(marker)
insert = r'''#[test]
fn private_field_express_receiver_cannot_mint_route() {
    let source = br#"
class Routes {
    #app;

    install(handler) {
        this.#app.get('/private-field', handler);
    }
}
"#;
    let result = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/private-field.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject private-field Express receiver");

    assert!(result.routes().is_empty());
    assert!(result.gaps().is_empty());
}

#[test]
fn private_field_deno_receiver_cannot_mint_supabase_route() {
    let source = br#"
class Runtime {
    #Deno;

    install(handler) {
        this.#Deno.serve(handler);
    }
}
"#;
    let result = extract_routes(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/private-doc/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject private-field Deno receiver");

    assert!(result.routes().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == RouteCoverageGapReason::UnsupportedHandlerExport)
    );
}

'''
tests.write_text(text.replace(marker, insert + marker, 1), encoding="utf-8", newline="\n")
