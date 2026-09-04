use sentrdel_review::business_logic::data::{
    DataCoverageGapReason, extract_supabase_data_operations,
};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, FieldSetMode};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

fn assert_unqualified_dynamic(adapter: RouteAdapter, fixture_path: &str, source: &[u8]) {
    let result = extract_supabase_data_operations(
        adapter,
        StructuralLanguage::JavaScript,
        &path(fixture_path),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect cross-adapter request mutation form");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == DataCoverageGapReason::UnqualifiedBroadRequestObject)
    );
}

#[test]
fn express_rejects_request_json_as_cross_adapter_request_body() {
    let source = br#"export function helper(client, request) {
  return client.from("profiles").update(request.json());
}
"#;
    assert_unqualified_dynamic(RouteAdapter::Express, "src/express.js", source);
}

#[test]
fn next_pages_rejects_request_json_as_cross_adapter_request_body() {
    let source = br#"export default function handler(client, request) {
  return client.from("profiles").update(request.json());
}
"#;
    assert_unqualified_dynamic(
        RouteAdapter::NextPagesApi,
        "pages/api/profile.js",
        source,
    );
}

#[test]
fn next_app_rejects_req_body_as_cross_adapter_request_body() {
    let source = br#"export async function POST(client, req) {
  return client.from("profiles").update(req.body);
}
"#;
    assert_unqualified_dynamic(RouteAdapter::NextApp, "app/api/profile/route.js", source);
}

#[test]
fn supabase_edge_rejects_req_body_as_cross_adapter_request_body() {
    let source = br#"Deno.serve(async (req) => {
  return supabase.from("profiles").update(req.body);
});
"#;
    assert_unqualified_dynamic(
        RouteAdapter::SupabaseEdge,
        "supabase/functions/profile/index.js",
        source,
    );
}

#[test]
fn next_pages_accepts_only_its_direct_req_body_form() {
    let source = br#"export default function handler(client, req) {
  return client.from("profiles").update(req.body);
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::NextPagesApi,
        StructuralLanguage::JavaScript,
        &path("pages/api/profile.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect supported Next Pages request mutation form");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::BroadRequestObject
    );
}

#[test]
fn next_app_accepts_only_its_zero_argument_request_json_form() {
    let source = br#"export async function POST(client, request) {
  return client.from("profiles").update(await request.json());
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/profile/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect supported Next App request mutation form");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::BroadRequestObject
    );
}
