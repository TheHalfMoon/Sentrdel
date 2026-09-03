use sentrdel_review::business_logic::guard::{
    GuardCoverageGapReason, extract_guard_observations,
};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, GuardKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized regression path")
}

#[test]
fn rest_element_destructuring_is_not_an_explicit_allowlist() {
    let source = br#"export function handler(req, res) {
  const { display_name, ...rest } = req.body;
  return res.json({ display_name, rest });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/rest-profile.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect request-body rest destructuring");

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
fn nested_callback_rejection_does_not_become_handler_exit_or_gap() {
    let source = br#"export function handler(req, res) {
  if (!req.user) {
    queue.on("fail", () => { throw new Error("boom"); });
  }
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/nested-callback.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect nested callback rejection");

    assert!(result.guards().is_empty());
    assert!(result.gaps().is_empty());
}

#[test]
fn comments_between_binary_operands_do_not_hide_required_role_guard() {
    let source = br#"export function handler(req, res) {
  if (req.user.role /* admin only */ !== "admin") return res.status(403).end();
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/commented-role.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract commented role comparison");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::RequiredRole && guard.required_values() == ["admin"]
    }));
}

#[test]
fn typescript_non_null_and_as_wrappers_preserve_verified_role_chain() {
    let source = br#"type Actor = { role: string };
export async function GET() {
  const session = await auth();
  if ((session!.user as Actor).role !== "admin") {
    return new Response(null, { status: 403 });
  }
  return Response.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::TypeScript,
        &path("app/api/admin/route.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract TypeScript wrapped role comparison");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::RequiredRole && guard.required_values() == ["admin"]
    }));
}

#[test]
fn typescript_satisfies_wrapper_preserves_verified_role_chain() {
    let source = br#"type Actor = { role: string };
export async function GET() {
  const session = await auth();
  if ((session!.user satisfies Actor).role !== "admin") {
    return new Response(null, { status: 403 });
  }
  return Response.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::TypeScript,
        &path("app/api/admin/satisfies/route.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract TypeScript satisfies role comparison");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::RequiredRole && guard.required_values() == ["admin"]
    }));
}

#[test]
fn guard_fact_iteration_cap_is_fail_visible() {
    let source = br#"export function handler(req, res) {
  const body6 = body5;
  const body5 = body4;
  const body4 = body3;
  const body3 = body2;
  const body2 = body1;
  const body1 = req.body;
  return res.json(body6);
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/fact-iteration-cap.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect bounded fact propagation");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}
