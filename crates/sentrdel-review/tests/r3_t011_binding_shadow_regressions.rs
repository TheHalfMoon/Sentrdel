use sentrdel_review::business_logic::guard::{GuardCoverageGapReason, extract_guard_observations};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, GuardKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized binding-shadow path")
}

fn assert_no_allowlist_with_visible_gap(source: &[u8], file: &str) {
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path(file),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect ambiguous request-body binding");

    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != GuardKind::PropertyAllowlist)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn request_body_alias_is_not_trusted_through_nested_parameter_shadow() {
    let source = br#"export function handler(req, res) {
  const body = req.body;
  function helper(body) {
    const { is_admin } = body;
    return is_admin;
  }
  return res.json({ value: helper({ is_admin: true }) });
}
"#;

    assert_no_allowlist_with_visible_gap(source, "src/parameter-shadow.js");
}

#[test]
fn auth_alias_is_not_trusted_through_nested_parameter_shadow() {
    let source = br#"export async function GET() {
  const session = await auth();
  function helper(session) {
    if (session.user.role !== "admin") {
      return new Response(null, { status: 403 });
    }
    return Response.json({ ok: true });
  }
  return helper({ user: { role: "admin" } });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/parameter-shadow/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect ambiguous auth binding");

    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != GuardKind::RequiredRole)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn catch_binding_shadow_is_not_trusted_as_request_body() {
    let source = br#"export function handler(req, res) {
  const body = req.body;
  try {
    return res.json({ ok: true });
  } catch (body) {
    const { is_admin } = body;
    return res.json({ is_admin });
  }
}
"#;

    assert_no_allowlist_with_visible_gap(source, "src/catch-shadow.js");
}

#[test]
fn destructuring_binding_shadow_is_not_trusted_as_request_body() {
    let source = br#"export function handler(req, res, local) {
  const body = req.body;
  {
    const { body } = local;
    const { is_admin } = body;
    return res.json({ is_admin });
  }
}
"#;

    assert_no_allowlist_with_visible_gap(source, "src/destructuring-shadow.js");
}

#[test]
fn function_binding_shadow_is_not_trusted_as_request_body() {
    let source = br#"export function handler(req, res) {
  const body = req.body;
  {
    function body() { return { is_admin: true }; }
    const { is_admin } = body;
    return res.json({ is_admin });
  }
}
"#;

    assert_no_allowlist_with_visible_gap(source, "src/function-shadow.js");
}

#[test]
fn class_binding_shadow_is_not_trusted_as_request_body() {
    let source = br#"export function handler(req, res) {
  const body = req.body;
  {
    class body {}
    const { is_admin } = body;
    return res.json({ is_admin });
  }
}
"#;

    assert_no_allowlist_with_visible_gap(source, "src/class-shadow.js");
}

#[test]
fn function_local_request_body_alias_shadows_unrelated_import_binding() {
    let source = br#"import { body } from "./input.js";
export function handler(req, res) {
  const body = req.body;
  const { is_admin } = body;
  return res.json({ is_admin });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/import-shadow.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("resolve local request-body alias over import binding");

    assert!(
        result
            .guards()
            .iter()
            .any(|guard| guard.guard_kind() == GuardKind::PropertyAllowlist)
    );
    assert!(
        result
            .gaps()
            .iter()
            .all(|gap| gap.reason() != GuardCoverageGapReason::UnsupportedGuardShape)
    );
}
