//! Repository-derived Supabase relation grant posture for API-facing roles.
//!
//! This producer consumes only bounded migration state plus repository-derived
//! API exposure. It reports supported grants that remain present after replay.
//! A supported REVOKE therefore removes the corresponding grant observation;
//! absence is never promoted into a security conclusion. Grants remain
//! independent from RLS and policy Evidence, hosted/live state remains unknown,
//! and this producer never creates Findings.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};
use serde_json::Value;

use super::posture::{ApiSchemaExposureSnapshot, ConfigExposureProvenance};
use super::state::{
    ExposureState, GrantKey, PostureCoverageState, RepositoryPostureState, StatementProvenance,
    SupabaseObjectKind,
};

pub const DEFAULT_MAX_API_ROLE_GRANTS: usize = 8_192;
const PRODUCER_ID: &str = "sentrdel.supabase.api-role-grants";
const PRODUCER_VERSION: &str = "1";
const API_FACING_ROLES: &[&str] = &["anon", "authenticated", "public"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiRoleGrantLimits {
    pub max_grants: usize,
}

impl Default for ApiRoleGrantLimits {
    fn default() -> Self {
        Self {
            max_grants: DEFAULT_MAX_API_ROLE_GRANTS,
        }
    }
}

#[derive(Debug)]
pub enum ApiRoleGrantError {
    InvalidLimits,
    EmptyCapturedAt,
    TooManyGrants { max: usize },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for ApiRoleGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("API role grant limits must be non-zero"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::TooManyGrants { max } => {
                write!(formatter, "API role grant count exceeds bounded cap {max}")
            }
            Self::Evidence(error) => {
                write!(formatter, "cannot seal API role grant evidence: {error}")
            }
        }
    }
}

impl Error for ApiRoleGrantError {}

impl From<EvidenceValidationError> for ApiRoleGrantError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_api_role_grants(
    state: &RepositoryPostureState,
    exposure: &ApiSchemaExposureSnapshot,
    captured_at: &str,
    limits: ApiRoleGrantLimits,
) -> Result<Vec<Evidence>, ApiRoleGrantError> {
    if limits.max_grants == 0 {
        return Err(ApiRoleGrantError::InvalidLimits);
    }
    if captured_at.trim().is_empty() {
        return Err(ApiRoleGrantError::EmptyCapturedAt);
    }

    let Some(exposure_provenance) = exposure.provenance() else {
        return Ok(Vec::new());
    };
    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let mut evidence = Vec::new();

    for (object, relation) in &state.relations {
        if object.kind != SupabaseObjectKind::Table
            || exposure.repository_schema_exposure(&object.schema) != ExposureState::ApiRelevant
        {
            continue;
        }

        for (grant, provenance) in &relation.grants {
            if !is_api_facing_role(&grant.role) {
                continue;
            }
            if evidence.len() >= limits.max_grants {
                return Err(ApiRoleGrantError::TooManyGrants {
                    max: limits.max_grants,
                });
            }
            evidence.push(seal_grant(
                &authority,
                state,
                object.normalized(),
                grant,
                provenance,
                exposure_provenance,
                captured_at,
            )?);
        }
    }

    Ok(evidence)
}

fn seal_grant(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    relation: String,
    grant: &GrantKey,
    provenance: &StatementProvenance,
    exposure_provenance: &ConfigExposureProvenance,
    captured_at: &str,
) -> Result<Evidence, ApiRoleGrantError> {
    let mut attributes = BTreeMap::new();
    attributes.insert("relation".to_owned(), Value::String(relation.clone()));
    attributes.insert("role".to_owned(), Value::String(grant.role.clone()));
    attributes.insert(
        "privilege".to_owned(),
        Value::String(grant.privilege.clone()),
    );
    attributes.insert("api_relevant".to_owned(), Value::Bool(true));
    attributes.insert("api_facing_role".to_owned(), Value::Bool(true));
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "repository_posture_coverage".to_owned(),
        Value::String(coverage_name(state.coverage_state).to_owned()),
    );
    attributes.insert(
        "hosted_grant_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "live_posture".to_owned(),
        Value::String("NOT_EXECUTED".to_owned()),
    );
    attributes.insert(
        "rls_interpretation".to_owned(),
        Value::String("INDEPENDENT_CONTROL".to_owned()),
    );
    attributes.insert(
        "policy_interpretation".to_owned(),
        Value::String("INDEPENDENT_CONTROL".to_owned()),
    );

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: input_digests(provenance, exposure_provenance),
        observation: format!(
            "Repository-derived migration state grants {} on API-relevant relation {relation} to API-facing role {}",
            grant.privilege, grant.role
        ),
        security_interpretation: None,
        category: "supabase_api_role_grant".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![
            EvidenceSubject {
                kind: "supabase_relation".to_owned(),
                id: relation,
            },
            EvidenceSubject {
                kind: "supabase_role".to_owned(),
                id: grant.role.clone(),
            },
        ],
        locations: vec![
            statement_location(provenance),
            config_location(exposure_provenance),
        ],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn is_api_facing_role(role: &str) -> bool {
    API_FACING_ROLES.contains(&role)
}

fn coverage_name(state: PostureCoverageState) -> &'static str {
    match state {
        PostureCoverageState::Complete => "COMPLETE",
        PostureCoverageState::Partial => "PARTIAL",
    }
}

fn input_digests(
    grant: &StatementProvenance,
    exposure: &ConfigExposureProvenance,
) -> Vec<String> {
    BTreeSet::from([
        grant.content_digest.clone(),
        exposure.content_digest.clone(),
    ])
    .into_iter()
    .collect()
}

fn statement_location(provenance: &StatementProvenance) -> EvidenceLocation {
    EvidenceLocation {
        repo_relative_path: provenance.path.as_str().to_owned(),
        start_line: None,
        start_column: None,
        end_line: None,
        end_column: None,
        symbol: None,
        content_digest: Some(provenance.content_digest.clone()),
    }
}

fn config_location(provenance: &ConfigExposureProvenance) -> EvidenceLocation {
    EvidenceLocation {
        repo_relative_path: provenance.path.as_str().to_owned(),
        start_line: provenance.line,
        start_column: None,
        end_line: provenance.line,
        end_column: None,
        symbol: None,
        content_digest: Some(provenance.content_digest.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supabase::posture::{
        ApiExposureSource, ApiSchemaExposureInput, SUPABASE_CONFIG_PATH,
        observe_api_schema_exposure,
    };
    use crate::supabase::sql::SqlScanLimits;
    use crate::supabase::state::{MigrationSqlInput, RlsState, reduce_repository_posture};
    use crate::view::NormalizedRepoPath;

    fn migration(order: &str, name: &str, digest: &str, sql: &str) -> MigrationSqlInput {
        MigrationSqlInput {
            path: NormalizedRepoPath::parse(
                &format!("supabase/migrations/{order}_{name}.sql"),
                4096,
            )
            .unwrap(),
            order_key: order.to_owned(),
            content_digest: digest.to_owned(),
            sql: sql.to_owned(),
        }
    }

    fn exposure(schemas: &[&str]) -> ApiSchemaExposureSnapshot {
        observe_api_schema_exposure(
            &ApiSchemaExposureInput {
                api_enabled: true,
                schemas: schemas.iter().map(|value| (*value).to_owned()).collect(),
                source: ApiExposureSource::ExplicitConfig,
                provenance: ConfigExposureProvenance {
                    path: NormalizedRepoPath::parse(SUPABASE_CONFIG_PATH, 4096).unwrap(),
                    content_digest: "sha256:config".to_owned(),
                    line: Some(4),
                },
            },
            "2026-08-29T14:00:00Z",
        )
        .unwrap()
        .0
    }

    #[test]
    fn supported_grant_and_revoke_leave_only_final_api_role_grant_posture() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "grants",
                "sha256:grants",
                "create table public.accounts(id bigint); grant select, insert on table public.accounts to anon; revoke insert on table public.accounts from anon; grant update on table public.accounts to authenticated;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let evidence = observe_api_role_grants(
            &state,
            &exposure(&["public"]),
            "2026-08-29T14:00:00Z",
            ApiRoleGrantLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 2);
        let privileges: BTreeSet<_> = evidence
            .iter()
            .filter_map(|item| item.claim().attributes.get("privilege"))
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(privileges, BTreeSet::from(["SELECT", "UPDATE"]));
        assert!(evidence.iter().all(|item| {
            item.claim().security_interpretation.is_none()
                && item.claim().attributes.get("hosted_grant_state")
                    == Some(&Value::String("UNKNOWN".to_owned()))
        }));
    }

    #[test]
    fn grants_remain_independent_from_rls_and_policy_state() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "independent",
                "sha256:independent",
                "create table public.accounts(id bigint); alter table public.accounts disable row level security; create policy account_read on public.accounts for select to authenticated using (true); grant select on table public.accounts to authenticated;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();
        let relation = state.relations.values().next().unwrap();
        assert_eq!(relation.rls_state.value, RlsState::Disabled);
        assert_eq!(relation.policy_ids.len(), 1);

        let evidence = observe_api_role_grants(
            &state,
            &exposure(&["public"]),
            "2026-08-29T14:00:00Z",
            ApiRoleGrantLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].claim().attributes.get("rls_interpretation"),
            Some(&Value::String("INDEPENDENT_CONTROL".to_owned()))
        );
        assert_eq!(
            evidence[0].claim().attributes.get("policy_interpretation"),
            Some(&Value::String("INDEPENDENT_CONTROL".to_owned()))
        );
    }

    #[test]
    fn non_api_schema_unknown_exposure_and_non_api_role_are_skipped() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "skip",
                "sha256:skip",
                "create table private.accounts(id bigint); grant select on table private.accounts to authenticated; create table public.internal(id bigint); grant select on table public.internal to backoffice;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        assert!(
            observe_api_role_grants(
                &state,
                &exposure(&["public"]),
                "2026-08-29T14:00:00Z",
                ApiRoleGrantLimits::default(),
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            observe_api_role_grants(
                &state,
                &ApiSchemaExposureSnapshot::unknown(),
                "2026-08-29T14:00:00Z",
                ApiRoleGrantLimits::default(),
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn parser_gap_remains_visible_without_erasing_supported_grant() {
        let state = reduce_repository_posture(
            &[
                migration(
                    "20260829000100",
                    "grant",
                    "sha256:grant",
                    "create table public.accounts(id bigint); grant select on table public.accounts to authenticated;",
                ),
                migration(
                    "20260829000200",
                    "dynamic",
                    "sha256:dynamic",
                    "do $$ begin execute 'revoke select on table public.accounts from authenticated'; end $$;",
                ),
            ],
            SqlScanLimits::default(),
        )
        .unwrap();
        assert_eq!(state.coverage_state, PostureCoverageState::Partial);

        let evidence = observe_api_role_grants(
            &state,
            &exposure(&["public"]),
            "2026-08-29T14:00:00Z",
            ApiRoleGrantLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0]
                .claim()
                .attributes
                .get("repository_posture_coverage"),
            Some(&Value::String("PARTIAL".to_owned()))
        );
    }

    #[test]
    fn public_role_is_api_facing_and_resource_caps_fail_closed() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "public",
                "sha256:public",
                "create table public.accounts(id bigint); grant select, insert on table public.accounts to public;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            observe_api_role_grants(
                &state,
                &exposure(&["public"]),
                "2026-08-29T14:00:00Z",
                ApiRoleGrantLimits { max_grants: 1 },
            ),
            Err(ApiRoleGrantError::TooManyGrants { max: 1 })
        ));
        assert!(matches!(
            observe_api_role_grants(
                &state,
                &exposure(&["public"]),
                "2026-08-29T14:00:00Z",
                ApiRoleGrantLimits { max_grants: 0 },
            ),
            Err(ApiRoleGrantError::InvalidLimits)
        ));
    }
}