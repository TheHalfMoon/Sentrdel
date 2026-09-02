use sentrdel_review::business_logic::actor::{
    ActorCoverageGapReason, ActorExtractionError, STATIC_AUTH_RECOGNITION_PROVES_RUNTIME_IDENTITY,
    extract_actor_contexts,
};
use sentrdel_review::business_logic::model::{
    ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, TrustBasis,
};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::{StructuralError, StructuralLanguage};
use sentrdel_review::view::NormalizedRepoPath;

const EXPRESS_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/express/safe-tenant/src/routes/accounts.js"
);
const NEXT_APP_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/next-app/safe-role/app/api/admin/users/[id]/route.js"
);
const SUPABASE_EDGE_SAFE: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/supabase-edge/safe-owner/supabase/functions/private-doc/index.ts"
);
const MALFORMED: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/adversarial/malformed-source/src/broken.js"
);

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn express_request_param_and_authenticated_user_are_distinct_static_contexts() {
    let result = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Express actor contexts");

    assert!(result.gaps().is_empty());
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::RequestControlled
            && actor.source_kind() == ActorSourceKind::RequestParam
            && actor.semantic_key() == "req.params.id"
            && actor.trust_basis() == TrustBasis::DirectObservation
    }));
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::AuthenticatedUser
            && actor.source_kind() == ActorSourceKind::VerifiedAuthAdapter
            && actor.semantic_key() == "req.user.id"
            && actor.trust_basis() == TrustBasis::DirectObservation
    }));
}

#[test]
fn request_query_remains_request_controlled_under_frozen_actor_source_model() {
    let source = b"export function handler(req) { const accountId = req.query.accountId; return accountId; }\n";
    let result = extract_actor_contexts(
        RouteAdapter::NextPagesApi,
        StructuralLanguage::JavaScript,
        &path("pages/api/accounts.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract request query context");

    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::RequestControlled
            && actor.source_kind() == ActorSourceKind::RequestParam
            && actor.semantic_key() == "req.query.accountId"
    }));
}

#[test]
fn next_app_auth_session_role_and_route_param_are_static_only() {
    let result = extract_actor_contexts(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/users/[id]/route.js"),
        NEXT_APP_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Next App actor contexts");

    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Role
            && actor.source_kind() == ActorSourceKind::VerifiedAuthAdapter
            && actor.semantic_key() == "session.user.role"
            && actor.trust_basis() == TrustBasis::DirectObservation
    }));
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::RequestControlled
            && actor.source_kind() == ActorSourceKind::RequestParam
            && actor.semantic_key() == "context.params.id"
    }));
    const {
        assert!(!STATIC_AUTH_RECOGNITION_PROVES_RUNTIME_IDENTITY);
    }
}

#[test]
fn supabase_get_user_alias_and_request_header_are_bounded_static_sources() {
    let result = extract_actor_contexts(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/private-doc/index.ts"),
        SUPABASE_EDGE_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("extract Supabase Edge actor contexts");

    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::AuthenticatedUser
            && actor.source_kind() == ActorSourceKind::VerifiedAuthAdapter
            && actor.semantic_key() == "user.id"
    }));
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::RequestControlled
            && actor.source_kind() == ActorSourceKind::RequestHeader
            && actor.semantic_key() == "request.headers.get"
    }));
}

#[test]
fn request_json_binding_is_request_controlled_body_context() {
    let source = br#"export async function POST(request) {
  const body = await request.json();
  return Response.json({ owner: body.owner_id });
}
"#;
    let result = extract_actor_contexts(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/items/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract request body binding");

    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::RequestControlled
            && actor.source_kind() == ActorSourceKind::RequestBody
            && actor.semantic_key() == "body.owner_id"
    }));
}

#[test]
fn dynamic_request_body_alias_access_fails_visible_as_unknown() {
    let source = br#"export async function POST(request, selector) {
  const body = await request.json();
  return body[selector];
}
"#;
    let result = extract_actor_contexts(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/items/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract dynamic request body gap");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ActorCoverageGapReason::DynamicRequestAccess)
    );
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Unknown
            && actor.source_kind() == ActorSourceKind::Unknown
            && actor.trust_basis() == TrustBasis::Unknown
    }));
}

#[test]
fn next_app_dynamic_session_root_access_fails_visible_as_unknown() {
    let source = br#"export async function GET(selector) {
  const session = await auth();
  return session[selector];
}
"#;
    let result = extract_actor_contexts(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/session/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract dynamic Next App auth-result gap");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ActorCoverageGapReason::DynamicAuthIdentity)
    );
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Unknown
            && actor.source_kind() == ActorSourceKind::Unknown
            && actor.trust_basis() == TrustBasis::Unknown
    }));
}

#[test]
fn supabase_dynamic_auth_result_access_fails_visible_as_unknown() {
    let source = br#"Deno.serve(async (request) => {
  const authResult = await supabase.auth.getUser();
  const selected = authResult.data.user[request.method];
  return Response.json({ selected });
});
"#;
    let result = extract_actor_contexts(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::TypeScript,
        &path("supabase/functions/dynamic-auth/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract dynamic Supabase auth-result gap");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == ActorCoverageGapReason::DynamicAuthIdentity)
    );
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Unknown
            && actor.source_kind() == ActorSourceKind::Unknown
            && actor.trust_basis() == TrustBasis::Unknown
    }));
}

#[test]
fn literal_binding_is_recorded_without_promoting_lexical_identity() {
    let source = b"const actorKey = 'admin';\nexport function handler(req) { return req.params.id ?? actorKey; }\n";
    let result = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/constants.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract constant binding");

    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Unknown
            && actor.source_kind() == ActorSourceKind::Constant
            && actor.semantic_key() == "constant-binding:actorKey"
    }));
}

#[test]
fn dynamic_request_and_auth_property_access_fail_visible_as_unknown() {
    let source = br#"export function handler(req, selector) {
  const requestValue = req[selector];
  const actorValue = req.user[selector];
  return { requestValue, actorValue };
}
"#;
    let result = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/dynamic.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract dynamic gaps");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == ActorCoverageGapReason::DynamicRequestAccess })
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == ActorCoverageGapReason::DynamicAuthIdentity })
    );
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Unknown
            && actor.source_kind() == ActorSourceKind::Unknown
            && actor.trust_basis() == TrustBasis::Unknown
    }));
}

#[test]
fn destructured_auth_result_is_explicitly_unsupported_not_runtime_verified() {
    let source =
        b"export async function DELETE() { const { user } = await auth(); return user?.id; }\n";
    let result = extract_actor_contexts(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/admin/route.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("classify unsupported auth binding");

    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| { gap.reason() == ActorCoverageGapReason::UnsupportedAuthShape })
    );
    assert!(result.actors().iter().any(|actor| {
        actor.identity_kind() == ActorIdentityKind::Unknown
            && actor.source_kind() == ActorSourceKind::Unknown
    }));
}

#[test]
fn unsupported_auth_shape_recognition_is_scoped_to_active_adapter() {
    let express_source =
        b"export async function handler() { const { value } = await auth(); return value; }\n";
    let express = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/unrelated-auth.js"),
        express_source,
        BusinessLogicLimits::default(),
    )
    .expect("ignore unrelated Express auth call");
    assert!(
        express
            .gaps()
            .iter()
            .all(|gap| gap.reason() != ActorCoverageGapReason::UnsupportedAuthShape)
    );

    let next_app_source = b"export async function GET() { const { data } = await supabase.auth.getUser(); return data; }\n";
    let next_app = extract_actor_contexts(
        RouteAdapter::NextApp,
        StructuralLanguage::JavaScript,
        &path("app/api/unrelated/route.js"),
        next_app_source,
        BusinessLogicLimits::default(),
    )
    .expect("ignore unrelated Next App Supabase auth call");
    assert!(
        next_app
            .gaps()
            .iter()
            .all(|gap| gap.reason() != ActorCoverageGapReason::UnsupportedAuthShape)
    );
}

#[test]
fn malformed_source_fails_before_actor_interpretation() {
    let error = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/broken.js"),
        MALFORMED.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect_err("malformed source must fail");

    assert!(matches!(
        error,
        ActorExtractionError::Structural(StructuralError::MalformedSyntax)
    ));
}

#[test]
fn equivalent_inputs_replay_deterministically() {
    let first = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("first extraction");
    let replay = extract_actor_contexts(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/routes/accounts.js"),
        EXPRESS_SAFE.as_bytes(),
        BusinessLogicLimits::default(),
    )
    .expect("replay extraction");

    assert_eq!(first, replay);
}
