use sentrdel_review::business_logic::actor::extract_actor_contexts;
use sentrdel_review::business_logic::data::extract_supabase_data_operations;
use sentrdel_review::business_logic::guard::extract_guard_observations;
use sentrdel_review::business_logic::model::{
    ActorIdentityKind, BusinessLogicLimits, DataOperationKind, GuardKind, ValueOriginKind,
};
use sentrdel_review::business_logic::route::{RouteAdapter, extract_routes};
use sentrdel_review::business_logic::value::extract_value_origins;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::coverage::CoverageState;

const EXPRESS_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/safe-tenant/src/routes/accounts.js"
);
const NEXT_APP_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-app/safe-role/app/api/admin/users/[id]/route.js"
);

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn supported_static_baselines_remain_positive_across_all_r3_extractors() {
    let limits = BusinessLogicLimits::default();
    let express_path = path("src/routes/accounts.js");

    let routes = extract_routes(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &express_path,
        EXPRESS_SAFE.as_bytes(),
        limits,
    )
    .expect("extract supported Express route baseline");
    assert!(routes.gaps().is_empty());
    assert_eq!(routes.routes().len(), 1);
    assert_eq!(routes.routes()[0].coverage_state(), &CoverageState::Covered);

    let actors = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &express_path,
        EXPRESS_SAFE.as_bytes(),
        limits,
    )
    .expect("extract supported Express actor baseline");
    assert!(actors.gaps().is_empty());
    assert!(
        actors
            .actors()
            .iter()
            .any(|actor| actor.identity_kind() == ActorIdentityKind::AuthenticatedUser)
    );
    assert!(
        actors
            .actors()
            .iter()
            .any(|actor| actor.identity_kind() == ActorIdentityKind::RequestControlled)
    );

    let guards = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/users/[id]/route.js"),
        NEXT_APP_SAFE.as_bytes(),
        limits,
    )
    .expect("extract supported Next App guard baseline");
    assert!(guards.gaps().is_empty());
    assert!(
        guards
            .guards()
            .iter()
            .any(|guard| guard.guard_kind() == GuardKind::Authentication)
    );
    assert!(
        guards
            .guards()
            .iter()
            .any(|guard| guard.guard_kind() == GuardKind::RequiredRole)
    );

    let value_source = br#"export function handler(req, res) {
  const accountId = req.params.accountId;
  const actorId = req.user.id;
  return res.json({ accountId, actorId });
}
export function register(app) {
  app.get("/accounts/:accountId", handler);
}
"#;
    let values = extract_value_origins(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/positive-values.js"),
        value_source,
        limits,
    )
    .expect("extract supported value-origin baseline");
    assert!(
        values
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::RequestPath)
    );
    assert!(
        values
            .values()
            .iter()
            .any(|value| value.origin_kind() == ValueOriginKind::AuthenticatedUserId)
    );

    let data_source = br#"Deno.serve(async (request) => {
  const body = await request.json();
  return supabase
    .from("profiles")
    .select("id, display_name")
    .eq("user_id", body.user_id)
    .maybeSingle();
});
"#;
    let data = extract_supabase_data_operations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/profile/index.ts"),
        data_source,
        limits,
    )
    .expect("extract supported Supabase data-operation baseline");
    assert_eq!(data.operations().len(), 1);
    assert_eq!(data.operations()[0].operation_kind(), DataOperationKind::Read);
    assert_eq!(data.operations()[0].resource().resource_name(), "profiles");
}
