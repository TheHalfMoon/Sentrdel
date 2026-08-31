use std::collections::BTreeSet;

use sentrdel_review::reconcile::{ReconcileError, ReconciliationRule, reconcile_evidence};
use sentrdel_review::supabase::function_authority::{
    FunctionAuthorityLimits, observe_function_authority,
};
use sentrdel_review::supabase::grants::{ApiRoleGrantLimits, observe_api_role_grants};
use sentrdel_review::supabase::policy::{PolicyPostureLimits, observe_policy_posture};
use sentrdel_review::supabase::posture::{
    ApiExposureSource, ApiSchemaExposureInput, ApiSchemaExposureSnapshot, ConfigExposureProvenance,
    SUPABASE_CONFIG_PATH, observe_api_schema_exposure,
};
use sentrdel_review::supabase::rls::{RlsPostureLimits, observe_api_relevant_rls};
use sentrdel_review::supabase::sql::SqlScanLimits;
use sentrdel_review::supabase::state::{MigrationSqlInput, reduce_repository_posture};
use sentrdel_review::supabase::storage::{
    StoragePostureLimits, observe_storage_authorization_posture,
};
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::evidence::Evidence;
use sentrdel_schema::finding::{ReconcilerAuthority, Severity};

const CAPTURED_AT: &str = "2026-08-31T20:00:00Z";
const MIGRATION_DIGEST: &str = "sha256:r2-t016-migration";
const CONFIG_DIGEST: &str = "sha256:r2-t016-config";

fn migration(sql: &str) -> MigrationSqlInput {
    MigrationSqlInput {
        path: NormalizedRepoPath::parse("supabase/migrations/20260831000100_t016.sql", 4096)
            .unwrap(),
        order_key: "20260831000100".to_owned(),
        content_digest: MIGRATION_DIGEST.to_owned(),
        sql: sql.to_owned(),
    }
}

fn exposure() -> ApiSchemaExposureSnapshot {
    let input = ApiSchemaExposureInput {
        api_enabled: true,
        schemas: BTreeSet::from(["public".to_owned()]),
        source: ApiExposureSource::ExplicitConfig,
        provenance: ConfigExposureProvenance {
            path: NormalizedRepoPath::parse(SUPABASE_CONFIG_PATH, 4096).unwrap(),
            content_digest: CONFIG_DIGEST.to_owned(),
            line: Some(3),
        },
    };
    observe_api_schema_exposure(&input, CAPTURED_AT).unwrap().0
}

fn supported_state(sql: &str) -> sentrdel_review::supabase::state::RepositoryPostureState {
    reduce_repository_posture(&[migration(sql)], SqlScanLimits::default()).unwrap()
}

fn categories(evidence: &[Evidence]) -> BTreeSet<String> {
    evidence
        .iter()
        .map(|item| item.claim().category.clone())
        .collect()
}

#[test]
fn independent_controls_preserve_their_own_evidence_and_provenance() {
    let state = supported_state(
        "create table public.accounts(id bigint); \
         alter table public.accounts enable row level security; \
         create policy accounts_read on public.accounts for select to authenticated using (true); \
         grant select on table public.accounts to authenticated; \
         create function public.lookup() returns void language sql security definer set search_path = '' as $$ select 1 $$; \
         grant execute on function public.lookup() to authenticated; \
         create table storage.objects(id bigint); \
         alter table storage.objects enable row level security; \
         create policy objects_read on storage.objects for select to authenticated using (true);",
    );
    let exposure = exposure();

    let rls = observe_api_relevant_rls(&state, &exposure, CAPTURED_AT, RlsPostureLimits::default())
        .unwrap();
    let grants = observe_api_role_grants(
        &state,
        &exposure,
        CAPTURED_AT,
        ApiRoleGrantLimits::default(),
    )
    .unwrap();
    let policies =
        observe_policy_posture(&state, CAPTURED_AT, PolicyPostureLimits::default()).unwrap();
    let functions = observe_function_authority(
        &state,
        &exposure,
        CAPTURED_AT,
        FunctionAuthorityLimits::default(),
    )
    .unwrap();
    let storage =
        observe_storage_authorization_posture(&state, CAPTURED_AT, StoragePostureLimits::default())
            .unwrap();

    assert_eq!(
        categories(&rls),
        BTreeSet::from(["supabase_rls_posture".to_owned()])
    );
    assert_eq!(
        categories(&grants),
        BTreeSet::from(["supabase_api_role_grant".to_owned()])
    );
    assert_eq!(
        categories(&policies),
        BTreeSet::from(["supabase_policy_posture".to_owned()])
    );
    assert_eq!(
        categories(&functions),
        BTreeSet::from([
            "supabase_function_execute_grant".to_owned(),
            "supabase_function_schema_exposure".to_owned(),
            "supabase_function_search_path".to_owned(),
            "supabase_function_security_mode".to_owned(),
        ])
    );
    assert_eq!(
        categories(&storage),
        BTreeSet::from([
            "supabase_storage_policy_posture".to_owned(),
            "supabase_storage_relation_posture".to_owned(),
        ])
    );

    for item in rls
        .iter()
        .chain(grants.iter())
        .chain(policies.iter())
        .chain(functions.iter())
        .chain(storage.iter())
    {
        assert!(item.claim().security_interpretation.is_none());
        assert!(
            item.claim()
                .input_digests
                .iter()
                .any(|digest| digest == MIGRATION_DIGEST)
        );
    }
    assert!(
        rls.iter()
            .chain(grants.iter())
            .chain(functions.iter())
            .any(|item| item
                .claim()
                .input_digests
                .iter()
                .any(|digest| digest == CONFIG_DIGEST))
    );
}

#[test]
fn revoking_one_control_does_not_erase_independent_control_evidence() {
    let state = supported_state(
        "create table public.accounts(id bigint); \
         alter table public.accounts enable row level security; \
         create policy accounts_read on public.accounts for select to authenticated using (true); \
         grant select on table public.accounts to authenticated; \
         revoke select on table public.accounts from authenticated; \
         create function public.lookup() returns void language sql security definer set search_path = '' as $$ select 1 $$; \
         grant execute on function public.lookup() to authenticated; \
         revoke execute on function public.lookup() from authenticated;",
    );
    let exposure = exposure();

    let rls = observe_api_relevant_rls(&state, &exposure, CAPTURED_AT, RlsPostureLimits::default())
        .unwrap();
    let grants = observe_api_role_grants(
        &state,
        &exposure,
        CAPTURED_AT,
        ApiRoleGrantLimits::default(),
    )
    .unwrap();
    let policies =
        observe_policy_posture(&state, CAPTURED_AT, PolicyPostureLimits::default()).unwrap();
    let functions = observe_function_authority(
        &state,
        &exposure,
        CAPTURED_AT,
        FunctionAuthorityLimits::default(),
    )
    .unwrap();

    assert_eq!(rls.len(), 1);
    assert!(grants.is_empty());
    assert_eq!(policies.len(), 1);
    assert!(
        functions
            .iter()
            .all(|item| { item.claim().category != "supabase_function_execute_grant" })
    );
    assert!(
        functions
            .iter()
            .any(|item| { item.claim().category == "supabase_function_security_mode" })
    );
    assert!(
        functions
            .iter()
            .any(|item| { item.claim().category == "supabase_function_search_path" })
    );
}

#[test]
fn only_existing_reconciler_authority_turns_one_evidence_category_into_findings() {
    let state = supported_state(
        "create table public.accounts(id bigint); \
         alter table public.accounts disable row level security; \
         create policy accounts_read on public.accounts for select to authenticated using (true);",
    );
    let exposure = exposure();
    let rls = observe_api_relevant_rls(&state, &exposure, CAPTURED_AT, RlsPostureLimits::default())
        .unwrap();
    assert_eq!(rls.len(), 1);

    let rule = ReconciliationRule::from_runtime(
        "supabase_rls_posture",
        "supabase-static-posture",
        "Runtime-owned RLS posture rule",
        "Runtime reconciliation interprets supported RLS posture evidence",
        Severity::High,
    )
    .unwrap();
    let reconciler = ReconcilerAuthority::from_runtime(
        "sentrdel-reconciler",
        "sha256:r2-t016-reconciler-config",
    )
    .unwrap();

    let findings = reconcile_evidence(&rls, &rule, &reconciler, CAPTURED_AT).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        findings[0].draft().evidence_ids,
        vec![rls[0].evidence_id().to_owned()]
    );
    assert_eq!(findings[0].draft().title, "Runtime-owned RLS posture rule");
    assert_eq!(findings[0].draft().severity, Severity::High);

    let policies =
        observe_policy_posture(&state, CAPTURED_AT, PolicyPostureLimits::default()).unwrap();
    assert_eq!(policies.len(), 1);
    assert!(matches!(
        reconcile_evidence(
            &[rls[0].clone(), policies[0].clone()],
            &rule,
            &reconciler,
            CAPTURED_AT,
        ),
        Err(ReconcileError::UnexpectedEvidenceCategory { .. })
    ));
}
