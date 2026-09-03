use sentrdel_review::business_logic::guard::{GuardCoverageGapReason, extract_guard_observations};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, GuardKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized lexical-binding regression path")
}

#[test]
fn completed_nested_const_shadow_does_not_poison_outer_request_body_alias() {
    let source = br#"export function handler(req, res, other) {
  const body = req.body;
  {
    const { body } = other;
    void body;
  }
  const { display_name } = body;
  return res.json({ display_name });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/nested-const-request-body-shadow.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve outer request-body alias after nested const shadow ends");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::PropertyAllowlist
            && guard.required_values() == ["display_name"]
    }));
    assert!(
        result
            .gaps()
            .iter()
            .all(|gap| gap.reason() != GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn completed_nested_let_shadow_does_not_poison_outer_session_alias() {
    let source = br#"export async function GET(other) {
  const session = await auth();
  {
    let { session } = other;
    void session;
  }
  if (!session) return new Response(null, { status: 401 });
  return Response.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/nested-let-session-shadow/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("preserve outer session alias after nested let shadow ends");

    assert!(
        result
            .guards()
            .iter()
            .any(|guard| guard.guard_kind() == GuardKind::Authentication)
    );
    assert!(
        result
            .gaps()
            .iter()
            .all(|gap| gap.reason() != GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn active_nested_const_shadow_still_blocks_outer_request_body_alias_inside_block() {
    let source = br#"export function handler(req, res, other) {
  const body = req.body;
  {
    const { body } = other;
    const { display_name } = body;
    return res.json({ display_name });
  }
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/active-nested-const-request-body-shadow.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject request-body alias while nested const shadow is active");

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
