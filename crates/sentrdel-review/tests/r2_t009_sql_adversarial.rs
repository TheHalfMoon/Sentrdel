use sentrdel_review::supabase::sql::SqlScanLimits;
use sentrdel_review::supabase::sql_model::{SqlParseCoverage, parse_sql_model};
use sentrdel_review::supabase::state::{
    MigrationSqlInput, PostureCoverageGapKind, PostureCoverageState, RlsState, SupabaseObjectId,
    SupabaseObjectKind, reduce_repository_posture,
};
use sentrdel_review::view::NormalizedRepoPath;

fn migration(path: &str, order_key: &str, digest: &str, sql: &str) -> MigrationSqlInput {
    MigrationSqlInput {
        path: NormalizedRepoPath::parse(path, 4096).expect("fixture path must be canonical"),
        order_key: order_key.to_owned(),
        content_digest: digest.to_owned(),
        sql: sql.to_owned(),
    }
}

fn accounts_table() -> SupabaseObjectId {
    SupabaseObjectId {
        schema: "public".to_owned(),
        name: "accounts".to_owned(),
        kind: SupabaseObjectKind::Table,
    }
}

#[test]
fn dynamic_sql_is_coverage_gap_and_cannot_override_known_rls_state() {
    let state = reduce_repository_posture(
        &[
            migration(
                "supabase/migrations/20260829000100_enable.sql",
                "20260829000100",
                "digest-enable",
                "create table public.accounts(id bigint); alter table public.accounts enable row level security;",
            ),
            migration(
                "supabase/migrations/20260829000200_dynamic.sql",
                "20260829000200",
                "digest-dynamic",
                "do $$ begin execute 'alter table public.accounts disable row level security'; end $$;",
            ),
        ],
        SqlScanLimits::default(),
    )
    .expect("bounded replay must complete");

    let relation = state
        .relations
        .get(&accounts_table())
        .expect("supported table state must remain present");
    assert_eq!(relation.rls_state.value, RlsState::Enabled);
    assert_eq!(state.coverage_state, PostureCoverageState::Partial);
    assert!(state.coverage_gaps.iter().any(|gap| {
        gap.kind == PostureCoverageGapKind::UnsupportedSecurityRelevant
            && gap.path.as_str() == "supabase/migrations/20260829000200_dynamic.sql"
    }));
}

#[test]
fn quoted_dynamic_sql_is_not_reparsed_as_a_supported_statement() {
    let scan = parse_sql_model(
        "do $$ begin execute 'alter table public.accounts disable row level security'; end $$;",
        SqlScanLimits::default(),
    )
    .expect("lexically bounded SQL must scan");

    assert_eq!(scan.statements.len(), 1);
    assert_eq!(
        scan.statements[0].coverage,
        SqlParseCoverage::UnsupportedSecurityRelevant
    );
    assert!(scan.statements[0].supported.is_none());
}

#[test]
fn unsupported_force_rls_cannot_be_invented_as_enabled_or_clean() {
    let state = reduce_repository_posture(
        &[
            migration(
                "supabase/migrations/20260829000100_disable.sql",
                "20260829000100",
                "digest-disable",
                "create table public.accounts(id bigint); alter table public.accounts disable row level security;",
            ),
            migration(
                "supabase/migrations/20260829000200_force.sql",
                "20260829000200",
                "digest-force",
                "alter table public.accounts force row level security;",
            ),
        ],
        SqlScanLimits::default(),
    )
    .expect("bounded replay must complete");

    let relation = state
        .relations
        .get(&accounts_table())
        .expect("supported prior state must remain present");
    assert_eq!(relation.rls_state.value, RlsState::Disabled);
    assert_eq!(state.coverage_state, PostureCoverageState::Partial);
    assert!(state
        .coverage_gaps
        .iter()
        .any(|gap| gap.kind == PostureCoverageGapKind::UnsupportedSecurityRelevant));
}

#[test]
fn malformed_security_sql_preserves_unknown_instead_of_clean_posture() {
    let state = reduce_repository_posture(
        &[migration(
            "supabase/migrations/20260829000100_malformed.sql",
            "20260829000100",
            "digest-malformed",
            "create table public.accounts(id bigint); create policy broken on public.accounts using ('unterminated",
        )],
        SqlScanLimits::default(),
    )
    .expect("diagnostics are coverage, not replay failure");

    assert_eq!(state.coverage_state, PostureCoverageState::Partial);
    assert!(state.relations.is_empty());
    assert!(state.coverage_gaps.iter().any(|gap| {
        gap.kind == PostureCoverageGapKind::MalformedOrBoundedRejection
    }));
}

#[test]
fn statement_cap_rejection_cannot_leave_a_clean_partial_replay() {
    let limits = SqlScanLimits {
        max_statements: 1,
        ..SqlScanLimits::default()
    };
    let state = reduce_repository_posture(
        &[migration(
            "supabase/migrations/20260829000100_capped.sql",
            "20260829000100",
            "digest-capped",
            "create table public.accounts(id bigint); alter table public.accounts enable row level security;",
        )],
        limits,
    )
    .expect("bounded scanner rejection must become coverage");

    assert_eq!(state.coverage_state, PostureCoverageState::Partial);
    assert_eq!(state.coverage_gaps.len(), 1);
    assert_eq!(
        state.coverage_gaps[0].kind,
        PostureCoverageGapKind::BoundedScanRejection
    );
    assert!(state.relations.is_empty());
}

#[test]
fn token_cap_rejection_cannot_materialize_security_state() {
    let limits = SqlScanLimits {
        max_tokens: 3,
        ..SqlScanLimits::default()
    };
    let state = reduce_repository_posture(
        &[migration(
            "supabase/migrations/20260829000100_tokens.sql",
            "20260829000100",
            "digest-tokens",
            "create table public.accounts(id bigint);",
        )],
        limits,
    )
    .expect("bounded scanner rejection must become coverage");

    assert_eq!(state.coverage_state, PostureCoverageState::Partial);
    assert!(state.relations.is_empty());
    assert_eq!(
        state.coverage_gaps[0].kind,
        PostureCoverageGapKind::BoundedScanRejection
    );
}

#[test]
fn ignored_query_scope_does_not_mask_unsupported_security_scope() {
    let state = reduce_repository_posture(
        &[migration(
            "supabase/migrations/20260829000100_mixed.sql",
            "20260829000100",
            "digest-mixed",
            "select 1; do $$ begin execute 'grant all on table public.accounts to anon'; end $$; select 2;",
        )],
        SqlScanLimits::default(),
    )
    .expect("bounded replay must complete");

    assert_eq!(state.coverage_state, PostureCoverageState::Partial);
    assert!(state.relations.is_empty());
    assert!(state.coverage_gaps.iter().any(|gap| {
        gap.kind == PostureCoverageGapKind::UnsupportedSecurityRelevant
    }));
}
