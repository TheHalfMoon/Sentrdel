use sentrdel_review::business_logic::data::{
    DataCoverageGapReason, extract_supabase_data_operations,
};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, FieldSetMode};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::coverage::CoverageState;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

fn assert_unqualified_request_parameter(source: &[u8], fixture_path: &str) {
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path(fixture_path),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect unsupported request parameter pattern");

    assert_eq!(result.operations().len(), 1);
    let operation = &result.operations()[0];
    assert_eq!(
        operation
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
    assert_eq!(operation.coverage_state(), &CoverageState::Partial);
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == DataCoverageGapReason::UnqualifiedBroadRequestObject })
    );
}

#[test]
fn destructured_request_parameter_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, { req }) {
  return client.from("profiles").update(req.body);
}
"#;

    assert_unqualified_request_parameter(source, "src/destructured-request.js");
}

#[test]
fn aliased_destructured_request_parameter_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, { body: req }) {
  return client.from("profiles").update(req.body);
}
"#;

    assert_unqualified_request_parameter(source, "src/aliased-destructured-request.js");
}

#[test]
fn defaulted_request_parameter_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, req = fakeRequest) {
  return client.from("profiles").update(req.body);
}
"#;

    assert_unqualified_request_parameter(source, "src/defaulted-request.js");
}

#[test]
fn rest_request_parameter_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, ...req) {
  return client.from("profiles").update(req.body);
}
"#;

    assert_unqualified_request_parameter(source, "src/rest-request.js");
}
