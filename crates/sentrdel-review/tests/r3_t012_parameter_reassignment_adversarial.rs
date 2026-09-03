use sentrdel_review::business_logic::model::{BusinessLogicLimits, ValueOriginKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::business_logic::value::{ValueCoverageGapReason, extract_value_origins};
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

fn assert_no_request_path_after_write(source: &[u8], fixture: &str) {
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path(fixture),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect reassigned request parameter");

    assert!(
        result
            .values()
            .iter()
            .all(|value| value.origin_kind() != ValueOriginKind::RequestPath)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ValueCoverageGapReason::AmbiguousBinding)
    );
    assert!(
        result
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::Unknown)
    );
}

fn assert_no_request_body_after_write(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    source: &[u8],
    fixture: &str,
) {
    let result = extract_value_origins(
        adapter,
        language,
        &path(fixture),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect request-body alias after parameter reassignment");

    assert!(
        result
            .values()
            .iter()
            .all(|value| value.origin_kind() != ValueOriginKind::RequestBody)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ValueCoverageGapReason::AmbiguousBinding)
    );
    assert!(
        result
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::Unknown)
    );
}

#[test]
fn assigned_request_parameter_cannot_mint_request_origin() {
    let source = br#"import express from "express";
const app = express();
app.get("/", (req) => {
  req = fakeRequest;
  return req.params.id;
});
"#;
    assert_no_request_path_after_write(source, "src/reassigned-request.js");
}

#[test]
fn updated_request_parameter_cannot_mint_request_origin() {
    let source = br#"import express from "express";
const app = express();
app.get("/", (req) => {
  req++;
  return req.params.id;
});
"#;
    assert_no_request_path_after_write(source, "src/updated-request.js");
}

#[test]
fn augmented_assignment_to_request_parameter_cannot_mint_request_origin() {
    let source = br#"import express from "express";
const app = express();
app.get("/", (req) => {
  req += replacement;
  return req.params.id;
});
"#;
    assert_no_request_path_after_write(source, "src/augmented-request.js");
}

#[test]
fn for_of_request_parameter_write_cannot_mint_request_origin() {
    let source = br#"import express from "express";
const app = express();
app.get("/", (req) => {
  for (req of requests) {
    return req.params.id;
  }
});
"#;
    assert_no_request_path_after_write(source, "src/for-of-request.js");
}

#[test]
fn for_in_request_parameter_write_cannot_mint_request_origin() {
    let source = br#"import express from "express";
const app = express();
app.get("/", (req) => {
  for (req in requests) {
    return req.params.id;
  }
});
"#;
    assert_no_request_path_after_write(source, "src/for-in-request.js");
}

#[test]
fn write_in_nested_function_does_not_rebind_outer_request_parameter() {
    let source = br#"import express from "express";
const app = express();
app.get("/", (req) => {
  function helper(req) {
    req = fakeRequest;
    return req;
  }
  void helper;
  return req.params.id;
});
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/nested-write.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect nested function parameter write");

    assert!(
        result
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::RequestPath)
    );
}

#[test]
fn next_request_json_alias_loses_typed_origin_after_request_reassignment() {
    let source = br#"export async function POST(request) {
  request = fakeRequest;
  const body = await request.json();
  return body.role;
}
"#;
    assert_no_request_body_after_write(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        source,
        "app/api/users/route.js",
    );
}

#[test]
fn express_request_body_alias_loses_typed_origin_after_request_reassignment() {
    let source = br#"import express from "express";
const app = express();
app.post("/", (req) => {
  req = fakeRequest;
  const body = req.body;
  return body.role;
});
"#;
    assert_no_request_body_after_write(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        source,
        "src/request-body-alias.js",
    );
}
