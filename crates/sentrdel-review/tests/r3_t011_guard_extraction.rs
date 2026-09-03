use sentrdel_review::business_logic::guard::{
    GuardCoverageGapReason, GuardExtractionError,
    STATIC_GUARD_RECOGNITION_PROVES_RUNTIME_AUTHORIZATION, extract_guard_observations,
};
use sentrdel_review::business_logic::model::{
    BusinessLogicLimits, ComparisonShape, DominanceScope, GuardKind,
};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::{StructuralError, StructuralLanguage};
use sentrdel_review::view::NormalizedRepoPath;

const NEXT_APP_SAFE_ROLE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-app/safe-role/app/api/admin/users/[id]/route.js"
);
const SUPABASE_EDGE_SAFE_OWNER: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/supabase-edge/safe-owner/supabase/functions/private-doc/index.ts"
);
const SAFE_PROPERTIES: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/supabase-data/safe-properties/src/profile.js"
);
const UNSAFE_PROPERTIES: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/supabase-data/unsafe-properties/src/profile.js"
);
const EXPRESS_SAFE_TENANT: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/safe-tenant/src/routes/accounts.js"
);
const DYNAMIC_GUARD: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-pages/unknown-dynamic-guard/pages/api/accounts/[id].js"
);
const MALFORMED: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/malformed-source/src/broken.js"
);

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn next_app_authentication_and_required_role_are_distinct_guards() {
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/users/[id]/route.js"),
        NEXT_APP_SAFE_ROLE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Next App guards");

    assert!(result.gaps().is_empty());
    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::Authentication
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::RequiredRole
            && guard.comparison_shape() == ComparisonShape::Equal
            && guard.required_values() == ["admin"]
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
    const {
        assert!(!STATIC_GUARD_RECOGNITION_PROVES_RUNTIME_AUTHORIZATION);
    }
}

#[test]
fn supabase_verified_user_rejection_is_authentication_guard_only() {
    let result = extract_guard_observations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/private-doc/index.ts"),
        SUPABASE_EDGE_SAFE_OWNER.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Supabase Edge guards");

    assert!(result.gaps().is_empty());
    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::Authentication
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != GuardKind::OwnershipBinding)
    );
}

#[test]
fn direct_owner_and_tenant_rejection_checks_are_typed_separately() {
    let source = br#"export function handler(req, res, resource) {
  if (resource.owner_id !== req.user.id) return res.status(403).end();
  if (resource.tenant_id !== req.user.tenant_id) return res.status(403).end();
  return res.json(resource);
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/direct-bindings.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract direct binding guards");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::OwnershipBinding
            && guard.comparison_shape() == ComparisonShape::Equal
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::TenantBinding
            && guard.comparison_shape() == ComparisonShape::Equal
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
}

#[test]
fn direct_membership_rejection_is_object_membership_guard() {
    let source = br#"export function handler(req, res, allowedIds) {
  if (!allowedIds.includes(req.user.id)) return res.status(403).end();
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/membership.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract membership guard");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::ObjectMembership
            && guard.comparison_shape() == ComparisonShape::Membership
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
}

#[test]
fn request_body_destructuring_is_explicit_property_allowlist() {
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/profile.js"),
        SAFE_PROPERTIES.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract property allowlist");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::PropertyAllowlist
            && guard.comparison_shape() == ComparisonShape::ExplicitAllowlist
            && guard.required_values() == ["display_name", "timezone"]
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
}

#[test]
fn broad_request_body_mutation_does_not_invent_property_allowlist() {
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/profile.js"),
        UNSAFE_PROPERTIES.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("inspect broad request body mutation");

    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != GuardKind::PropertyAllowlist)
    );
}

#[test]
fn request_json_alias_destructuring_is_property_allowlist() {
    let source = br#"export async function POST(request) {
  const body = await request.json();
  const { display_name, timezone } = body;
  return Response.json({ display_name, timezone });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/profile/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract request-json property allowlist");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::PropertyAllowlist
            && guard.required_values() == ["display_name", "timezone"]
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
}

#[test]
fn explicit_elevated_authorization_marker_is_bounded_boundary_guard() {
    let source = br#"export function handler(req, res, authorization, elevatedClient) {
  if (!authorization.elevatedClient) return res.status(403).end();
  return elevatedClient.from("users").select("id");
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/elevated-boundary.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract explicit elevated boundary guard");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::ElevatedClientBoundary
            && guard.comparison_shape() == ComparisonShape::OtherSupported
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
}

#[test]
fn lexical_express_middleware_name_is_not_promoted_to_guard() {
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE_TENANT.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("inspect Express route middleware");

    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.guard_kind() != GuardKind::Authentication)
    );
}

#[test]
fn request_selected_dynamic_guard_fails_visible_without_supported_guard() {
    let result = extract_guard_observations(
        RouteAdapter::NextPagesApi,
        StructuralLanguage::JavaScript,
        &path("pages/api/accounts/[id].js"),
        DYNAMIC_GUARD.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract dynamic guard coverage");

    assert!(result.guards().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::DynamicGuard)
    );
}

#[test]
fn computed_request_selected_guard_callback_fails_visible() {
    let source = br#"export async function handler(req, res, guards) {
  const allowed = await guards[req.query.guard](req);
  if (!allowed) return res.status(403).end();
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/computed-guard.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect computed request-selected guard");

    assert!(result.guards().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::DynamicGuard)
    );
}

#[test]
fn dynamic_auth_property_guard_fails_visible_as_unsupported() {
    let source = br#"export async function GET(selector) {
  const session = await auth();
  if (!session[selector]) return new Response(null, { status: 403 });
  return Response.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/private/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract dynamic auth guard coverage");

    assert!(result.guards().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape })
    );
}

#[test]
fn rejection_conjunction_does_not_invent_independent_guards() {
    let source = br#"export function handler(req, res) {
  if (!req.user && req.user.role !== "admin") return res.status(403).end();
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/conjunction.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect conjunction guard");

    assert!(result.guards().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn tenant_and_ownership_bindings_require_matching_authenticated_identity_kind() {
    let source = br#"export function handler(req, res, resource) {
  if (resource.tenant_id !== req.user.id) return res.status(403).end();
  if (resource.owner_id !== req.user.role) return res.status(403).end();
  return res.json(resource);
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/mismatched-bindings.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect mismatched identity bindings");

    assert!(result.guards().iter().all(|guard| !matches!(
        guard.guard_kind(),
        GuardKind::TenantBinding | GuardKind::OwnershipBinding
    )));
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == GuardCoverageGapReason::UnsupportedGuardShape)
    );
}

#[test]
fn nested_rejection_does_not_prove_same_handler_prefix_dominance() {
    let source = br#"export function handler(req, res) {
  if (!req.user) {
    if (req.query.debug) return res.status(401).end();
    performSensitiveWork();
  }
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/nested-rejection.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect nested rejection");

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
fn file_wide_observations_do_not_claim_handler_prefix_dominance() {
    let source = br#"export function guarded(req, res) {
  if (!req.user) return res.status(401).end();
  return res.json({ ok: true });
}
export function unguarded(req, res) {
  performSensitiveWork();
  return res.json({ ok: true });
}
"#;
    let result = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/two-handlers.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect two handlers");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::Authentication
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.dominance_scope() != DominanceScope::SameHandlerPrefix)
    );
}

#[test]
fn nested_callback_guard_does_not_claim_handler_prefix_dominance() {
    let source = br#"export function handler(req, res, work) {
  work.forEach(() => {
    if (!req.user) return res.status(401).end();
  });
  performSensitiveWork();
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
    .expect("inspect nested callback guard");

    assert!(result.guards().iter().any(|guard| {
        guard.guard_kind() == GuardKind::Authentication
            && guard.dominance_scope() == DominanceScope::Unknown
    }));
    assert!(
        result
            .guards()
            .iter()
            .all(|guard| guard.dominance_scope() != DominanceScope::SameHandlerPrefix)
    );
}

#[test]
fn malformed_source_fails_before_guard_interpretation() {
    let error = extract_guard_observations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/broken.js"),
        MALFORMED.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect_err("malformed source must fail");

    assert!(matches!(
        error,
        GuardExtractionError::Structural(StructuralError::MalformedSyntax)
    ));
}

#[test]
fn equivalent_inputs_replay_deterministically() {
    let first = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/users/[id]/route.js"),
        NEXT_APP_SAFE_ROLE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("first extraction");
    let replay = extract_guard_observations(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/users/[id]/route.js"),
        NEXT_APP_SAFE_ROLE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("replay extraction");

    assert_eq!(first, replay);
}
