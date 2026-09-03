use sentrdel_review::business_logic::model::{BusinessLogicLimits, ValueOriginKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::business_logic::value::{ValueCoverageGapReason, extract_value_origins};
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn identifier_use_in_another_function_does_not_cross_lexical_scope() {
    let source = br#"export function handler(req) {
  const accountId = req.params.accountId;
  return 1;
}
function helper() {
  return accountId;
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/cross-function.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect cross-function alias");

    assert!(!result.values().iter().any(|value| {
        value.semantic_key() == "use:accountId"
            && value.origin_kind() == ValueOriginKind::SupportedDerived
    }));
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ValueCoverageGapReason::AmbiguousBinding)
    );
}

#[test]
fn conventional_req_name_in_unrelated_helper_is_not_a_request_origin() {
    let source = br#"export function handler(input) {
  return 1;
}
function format(req) {
  return req.params.id;
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/helper-name.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect unverified helper request name");

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
}

#[test]
fn static_subscript_depth_exhaustion_is_not_reported_as_dynamic_access() {
    let source = br#"export function handler(req) {
  const params = req.params;
  const selected = params["accountId"];
  return selected;
}
"#;
    let limits = BusinessLogicLimits {
        max_derivation_depth: 1,
        ..BusinessLogicLimits::default()
    };
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/static-subscript-depth.js"),
        source,
        limits,
    )
    .expect("inspect static subscript depth cap");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ValueCoverageGapReason::DerivationDepthExceeded)
    );
    assert!(!result.gaps().iter().any(|gap| {
        if gap.reason() != ValueCoverageGapReason::DynamicExpression {
            return false;
        }
        let start = gap.provenance().start_byte();
        let end = gap.provenance().end_byte();
        source.get(start..end) == Some(b"params[\"accountId\"]".as_slice())
    }));
}
