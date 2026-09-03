use sentrdel_review::business_logic::guard::{GuardCoverageGapReason, extract_guard_observations};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, GuardKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized reassignment regression path")
}

fn assert_visible_gap_without_guard(
    source: &[u8],
    adapter: RouteAdapter,
    file: &str,
    forbidden: GuardKind,
) {
    let result = extract_guard_observations(
        adapter,
        StructuralLanguage::JavaScript,
        &path(file),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect destructuring reassignment");

    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != forbidden)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn object_destructuring_reassignment_invalidates_request_body_alias() {
    let source = br#"export function handler(req, res) {
  let body = req.body;
  ({ body } = { body: { is_admin: true } });
  const { is_admin } = body;
  return res.json({ is_admin });
}
"#;

    assert_visible_gap_without_guard(
        source,
        RouteAdapter::Express,
        "src/object-body-reassignment.js",
        GuardKind::PropertyAllowlist,
    );
}

#[test]
fn array_destructuring_reassignment_invalidates_request_body_alias() {
    let source = br#"export function handler(req, res) {
  let body = req.body;
  [body] = [{ is_admin: true }];
  const { is_admin } = body;
  return res.json({ is_admin });
}
"#;

    assert_visible_gap_without_guard(
        source,
        RouteAdapter::Express,
        "src/array-body-reassignment.js",
        GuardKind::PropertyAllowlist,
    );
}

#[test]
fn object_destructuring_reassignment_invalidates_auth_alias() {
    let source = br#"export async function GET() {
  let session = await auth();
  ({ session } = { session: { user: { role: "admin" } } });
  if (session.user.role !== "admin") {
    return new Response(null, { status: 403 });
  }
  return Response.json({ ok: true });
}
"#;

    assert_visible_gap_without_guard(
        source,
        RouteAdapter::NextApp,
        "app/api/object-auth-reassignment/route.js",
        GuardKind::RequiredRole,
    );
}

#[test]
fn array_destructuring_reassignment_invalidates_auth_alias() {
    let source = br#"export async function GET() {
  let session = await auth();
  [session] = [{ user: { role: "admin" } }];
  if (session.user.role !== "admin") {
    return new Response(null, { status: 403 });
  }
  return Response.json({ ok: true });
}
"#;

    assert_visible_gap_without_guard(
        source,
        RouteAdapter::NextApp,
        "app/api/array-auth-reassignment/route.js",
        GuardKind::RequiredRole,
    );
}
