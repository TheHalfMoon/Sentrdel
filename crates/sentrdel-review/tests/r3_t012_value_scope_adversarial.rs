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

    let helper_use_start = source
        .windows(b"return accountId".len())
        .rposition(|window| window == b"return accountId")
        .expect("helper return expression")
        + b"return ".len();
    let helper_use_end = helper_use_start + b"accountId".len();
    let helper_use = result
        .value_for_range(helper_use_start, helper_use_end)
        .expect("cross-scope identifier use must remain fail-visible");
    assert_eq!(helper_use.origin_kind(), ValueOriginKind::Unknown);
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

#[test]
fn express_request_parameter_shadow_does_not_mint_request_path_origin() {
    let source = br#"export function handler(req) {
  {
    const req = { params: { id: "fake" } };
    return req.params.id;
  }
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/shadowed-request.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed Express request parameter");

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

    let use_start = source
        .windows(b"req.params.id".len())
        .rposition(|window| window == b"req.params.id")
        .expect("shadowed request member use");
    let use_end = use_start + b"req.params.id".len();
    let value = result
        .value_for_range(use_start, use_end)
        .expect("shadowed request use must remain fail-visible");
    assert_eq!(value.origin_kind(), ValueOriginKind::Unknown);
}

#[test]
fn next_app_shadowed_request_cannot_seed_request_body_alias() {
    let source = br#"export async function POST(request) {
  {
    const request = { json: async () => ({ role: "admin" }) };
    const body = await request.json();
    return body.role;
  }
}
"#;
    let result = extract_value_origins(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/shadowed/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed Next App request parameter");

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

    let use_start = source
        .windows(b"body.role".len())
        .rposition(|window| window == b"body.role")
        .expect("shadowed request-body alias use");
    let use_end = use_start + b"body.role".len();
    let value = result
        .value_for_range(use_start, use_end)
        .expect("shadow-derived body alias must remain fail-visible");
    assert_eq!(value.origin_kind(), ValueOriginKind::Unknown);
}

#[test]
fn predeclaration_request_use_in_shadowed_block_is_not_treated_as_handler_parameter() {
    let source = br#"export function handler(req) {
  {
    const before = req.params.id;
    const req = fakeRequest;
    return before;
  }
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/request-tdz.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect request parameter TDZ shadow");

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

    let use_start = source
        .windows(b"req.params.id".len())
        .position(|window| window == b"req.params.id")
        .expect("predeclaration request member use");
    let use_end = use_start + b"req.params.id".len();
    let value = result
        .value_for_range(use_start, use_end)
        .expect("TDZ-shadowed request use must remain fail-visible");
    assert_eq!(value.origin_kind(), ValueOriginKind::Unknown);
}
