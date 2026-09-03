use sentrdel_review::business_logic::guard::{GuardCoverageGapReason, extract_guard_observations};
use sentrdel_review::business_logic::model::{BusinessLogicLimits, GuardKind};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized import-alias regression path")
}

#[test]
fn aliased_named_auth_import_does_not_shadow_unbound_next_app_origin() {
    let source = br#"import { auth as importedAuth } from \"./other.js\";

export async function GET() {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  return Response.json({ ok: importedAuth !== null });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/aliased-auth-import/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("keep unbound auth origin despite aliased import source name");

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
fn aliased_named_supabase_import_does_not_shadow_unbound_edge_origin() {
    let source = br#"import { supabase as importedSupabase } from \"./other.ts\";

Deno.serve(async (request) => {
  const userResult = await supabase.auth.getUser(request.headers.get("Authorization"));
  const user = userResult.data.user;
  if (!user) return new Response(null, { status: 401 });
  return Response.json({ ok: importedSupabase !== null });
});
"#;
    let result = extract_guard_observations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/aliased-supabase-import/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("keep unbound Supabase origin despite aliased import source name");

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
fn direct_named_auth_import_still_shadows_next_app_origin() {
    let source = br#"import { auth } from \"./other.js\";

export async function GET() {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  return Response.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/direct-auth-import/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject locally imported auth origin");

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

#[test]
fn namespace_supabase_import_still_shadows_edge_origin() {
    let source = br#"import * as supabase from \"./other.ts\";

Deno.serve(async (request) => {
  const userResult = await supabase.auth.getUser(request.headers.get("Authorization"));
  const user = userResult.data.user;
  if (!user) return new Response(null, { status: 401 });
  return Response.json({ ok: true });
});
"#;
    let result = extract_guard_observations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/namespace-supabase-import/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("reject locally imported Supabase namespace origin");

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
