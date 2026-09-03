use sentrdel_review::business_logic::model::{BusinessLogicLimits, ValueOriginKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::business_logic::value::{
    STATIC_VALUE_DERIVATION_PROVES_RUNTIME_VALUE, ValueCoverageGapReason, ValueExtractionError,
    extract_value_origins,
};
use sentrdel_review::structural::{StructuralError, StructuralLanguage};
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn express_direct_request_and_authenticated_origins_are_typed_separately() {
    let source = br#"export function handler(req, res) {
  const a = req.params.accountId;
  const b = req.query.filter;
  const c = req.body.display_name;
  const d = req.headers.authorization;
  const e = req.user.id;
  const f = req.user.tenant_id;
  const g = req.user.role;
  return res.json({ a, b, c, d, e, f, g });
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/values.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract Express values");

    for kind in [
        ValueOriginKind::RequestPath,
        ValueOriginKind::RequestQuery,
        ValueOriginKind::RequestBody,
        ValueOriginKind::RequestHeader,
        ValueOriginKind::AuthenticatedUserId,
        ValueOriginKind::AuthenticatedTenantId,
        ValueOriginKind::AuthenticatedRole,
    ] {
        assert!(result.values().iter().any(|value| value.origin_kind() == kind));
    }
    const { assert!(!STATIC_VALUE_DERIVATION_PROVES_RUNTIME_VALUE) };
}

#[test]
fn const_alias_chain_is_supported_derivation_with_explicit_inputs() {
    let source = br#"export function handler(req) {
  const accountId = req.params.accountId;
  const selected = accountId;
  return selected;
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/alias.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract alias derivation");

    assert!(result.values().iter().any(|value| {
        value.origin_kind() == ValueOriginKind::SupportedDerived
            && value.semantic_key() == "binding:selected"
            && !value.derivation_inputs().is_empty()
            && value.derivation_depth() >= 2
    }));
}

#[test]
fn object_destructuring_links_supported_request_sources() {
    let source = br#"export function handler(req) {
  const { accountId: id } = req.params;
  const { display_name } = req.body;
  return { id, display_name };
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/destructure.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract destructured values");

    assert!(result.values().iter().any(|value| {
        value.origin_kind() == ValueOriginKind::SupportedDerived
            && value.semantic_key() == "binding:id"
    }));
    assert!(result.values().iter().any(|value| {
        value.origin_kind() == ValueOriginKind::SupportedDerived
            && value.semantic_key() == "binding:display_name"
    }));
}

#[test]
fn next_app_request_and_authenticated_sources_remain_distinct() {
    let source = br#"export async function GET(request, context) {
  const body = await request.json();
  const session = await auth();
  const user = session.user;
  const a = context.params.accountId;
  const b = request.nextUrl.searchParams.get("q");
  const c = request.headers.get("authorization");
  const d = body.display_name;
  const e = user.id;
  const f = user.tenantId;
  const g = user.role;
  return Response.json({ a, b, c, d, e, f, g });
}
"#;
    let result = extract_value_origins(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/accounts/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract Next App values");

    for kind in [
        ValueOriginKind::RequestPath,
        ValueOriginKind::RequestQuery,
        ValueOriginKind::RequestHeader,
        ValueOriginKind::RequestBody,
        ValueOriginKind::AuthenticatedUserId,
        ValueOriginKind::AuthenticatedTenantId,
        ValueOriginKind::AuthenticatedRole,
    ] {
        assert!(result.values().iter().any(|value| value.origin_kind() == kind));
    }
}

#[test]
fn supabase_edge_verified_user_and_request_sources_are_bounded() {
    let source = br#"Deno.serve(async (request) => {
  const body = await request.json();
  const userResult = await supabase.auth.getUser("token");
  const user = userResult.data.user;
  const owner = user.id;
  const tenant = user.tenant_id;
  const role = user.role;
  const header = request.headers.get("x-request-id");
  return Response.json({ body, owner, tenant, role, header });
});
"#;
    let result = extract_value_origins(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/private/index.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract Supabase Edge values");

    for kind in [
        ValueOriginKind::RequestBody,
        ValueOriginKind::RequestHeader,
        ValueOriginKind::AuthenticatedUserId,
        ValueOriginKind::AuthenticatedTenantId,
        ValueOriginKind::AuthenticatedRole,
    ] {
        assert!(result.values().iter().any(|value| value.origin_kind() == kind));
    }
}

#[test]
fn dynamic_member_and_transform_call_terminate_in_unknown() {
    let source = br#"export function handler(req, key) {
  const selected = req.params[key];
  const transformed = transform(req.params.accountId);
  return { selected, transformed };
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/dynamic.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect dynamic values");

    assert!(result.values().iter().any(|value| {
        value.origin_kind() == ValueOriginKind::Unknown
            && value.semantic_key() == "binding:selected"
    }));
    assert!(result.values().iter().any(|value| {
        value.origin_kind() == ValueOriginKind::Unknown
            && value.semantic_key() == "binding:transformed"
    }));
    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == ValueCoverageGapReason::DynamicExpression));
}

#[test]
fn duplicate_or_reassigned_bindings_never_gain_supported_equivalence() {
    let source = br#"export function handler(req, flag) {
  let accountId = req.params.accountId;
  accountId = flag ? req.params.other : "constant";
  const outer = req.query.accountId;
  {
    const outer = req.body.accountId;
    consume(outer);
  }
  return { accountId, outer };
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/ambiguous.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect ambiguous bindings");

    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == ValueCoverageGapReason::AmbiguousBinding));
    assert!(!result.values().iter().any(|value| {
        value.semantic_key() == "binding:accountId"
            && value.origin_kind() == ValueOriginKind::SupportedDerived
    }));
    assert!(!result.values().iter().any(|value| {
        value.semantic_key() == "binding:outer"
            && value.origin_kind() == ValueOriginKind::SupportedDerived
    }));
}

#[test]
fn static_string_subscript_is_supported_but_dynamic_subscript_is_not() {
    let source = br#"export function handler(req, key) {
  const supported = req.params["accountId"];
  const unknown = req.params[key];
  return { supported, unknown };
}
"#;
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/subscript.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect subscript values");

    assert!(result
        .values()
        .iter()
        .any(|value| value.origin_kind() == ValueOriginKind::RequestPath));
    assert!(result.values().iter().any(|value| {
        value.origin_kind() == ValueOriginKind::Unknown
            && value.semantic_key() == "binding:unknown"
    }));
}

#[test]
fn derivation_depth_cap_fails_visible_instead_of_inventing_equivalence() {
    let source = br#"export function handler(req) {
  const a = req.params.id;
  const b = a;
  const c = b;
  const d = c;
  return d;
}
"#;
    let limits = BusinessLogicLimits {
        max_derivation_depth: 2,
        ..BusinessLogicLimits::default()
    };
    let result = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/depth.js"),
        source,
        limits,
    )
    .expect("bounded depth extraction");

    assert!(result
        .gaps()
        .iter()
        .any(|gap| gap.reason() == ValueCoverageGapReason::DerivationDepthExceeded));
    assert!(result
        .values()
        .iter()
        .all(|value| value.derivation_depth() <= limits.max_derivation_depth));
}

#[test]
fn malformed_source_fails_before_value_interpretation() {
    let error = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/broken.js"),
        b"export function handler(req) { const x = req.params.id;",
        BusinessLogicLimits::default(),
    )
    .expect_err("malformed source must fail");

    assert!(matches!(
        error,
        ValueExtractionError::Structural(StructuralError::MalformedSyntax)
    ));
}

#[test]
fn equivalent_inputs_replay_deterministically() {
    let source = br#"export function handler(req) {
  const accountId = req.params.accountId;
  const selected = accountId;
  return selected;
}
"#;
    let first = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/replay.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("first extraction");
    let replay = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/replay.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("replay extraction");

    assert_eq!(first, replay);
}
