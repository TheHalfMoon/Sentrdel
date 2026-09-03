use sentrdel_review::business_logic::guard::{GuardCoverageGapReason, extract_guard_observations};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, GuardKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized origin-shadow path")
}

#[test]
fn next_app_auth_parameter_cannot_seed_authentication_or_role_guard() {
    let source = br#"export async function GET(auth) {
  const session = await auth();
  if (!session || session.user.role !== "admin") {
    return new Response(null, { status: 403 });
  }
  return Response.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/shadowed-auth/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed auth origin");

    assert!(result.guards().iter().all(|guard| !matches!(
        guard.guard_kind(),
        GuardKind::Authentication | GuardKind::RequiredRole
    )));
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn supabase_parameter_cannot_seed_verified_user_authentication_guard() {
    let source = br#"Deno.serve(async (request, supabase) => {
  const userResult = await supabase.auth.getUser(request.headers.get("Authorization"));
  const user = userResult.data.user;
  if (!user) return new Response(null, { status: 401 });
  return Response.json({ ok: true });
});
"#;
    let result = extract_guard_observations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/shadowed-origin/index.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect shadowed Supabase origin");

    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != GuardKind::Authentication)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}
