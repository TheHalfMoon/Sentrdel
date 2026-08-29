//! Repository-derived Supabase RLS posture Evidence for API-relevant tables.
//!
//! This producer consumes only already-bounded migration state plus the
//! repository-derived API exposure snapshot. It never claims hosted/live RLS
//! state, never creates Findings, and keeps direct RLS observations free of
//! security interpretation.

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
    ExposureState, PostureCoverageState, RelationPosture, RepositoryPostureState, RlsState,
    StatementProvenance, SupabaseObjectKind,
};

pub const DEFAULT_MAX_RLS_RELATIONS: usize = 4_096;
const PRODUCER_ID: &str = "sentrdel.supabase.rls-posture";
const PRODUCER_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RlsPostureLimits {
    pub max_relations: usize,
}

impl Default for RlsPostureLimits {
    fn default() -> Self {
        Self {
            max_relations: DEFAULT_MAX_RLS_RELATIONS,
        }
    }
}

#[derive(Debug)]
pub enum RlsPostureError {
    InvalidLimits,
    EmptyCapturedAt,
    TooManyApiRelevantRelations { max: usize },
    MissingStateProvenance { relation: String },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for RlsPostureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("RLS posture limits must be non-zero"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::TooManyApiRelevantRelations { max } => write!(
                formatter,
                "API-relevant RLS relation count exceeds bounded cap {max}"
            ),
            Self::MissingStateProvenance { relation } => write!(
                formatter,
                "repository-derived RLS state for {relation} is missing statement provenance"
            ),
            Self::Evidence(error) => write!(formatter, "cannot seal RLS posture evidence: {error}"),
        }
    }
}

impl Error for RlsPostureError {}

impl From<EvidenceValidationError> for RlsPostureError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_api_relevant_rls(
    state: &RepositoryPostureState,
    exposure: &ApiSchemaExposureSnapshot,
    captured_at: &str,
    limits: RlsPostureLimits,
) -> Result<Vec<Evidence>, RlsPostureError> {
    if limits.max_relations == 0 {
        return Err(RlsPostureError::InvalidLimits);
    }
    if captured_at.trim().is_empty() {
        return Err(RlsPostureError::EmptyCapturedAt);
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
        if relation.rls_state.value == RlsState::Unknown
            && !relation.exists_in_supported_history.value
        {
            continue;
        }
        if evidence.len() >= limits.max_relations {
            return Err(RlsPostureError::TooManyApiRelevantRelations {
                max: limits.max_relations,
            });
        }

        let relation_id = object.normalized();
        let state_provenance = state_provenance(relation).ok_or_else(|| {
            RlsPostureError::MissingStateProvenance {
                relation: relation_id.clone(),
            }
        })?;
        let rls_state = rls_state_name(relation.rls_state.value);
        let mut attributes = BTreeMap::new();
        attributes.insert("relation".to_owned(), Value::String(relation_id.clone()));
        attributes.insert("schema".to_owned(), Value::String(object.schema.clone()));
        attributes.insert("rls_state".to_owned(), Value::String(rls_state.to_owned()));
        attributes.insert("api_relevant".to_owned(), Value::Bool(true));
        attributes.insert("repository_derived".to_owned(), Value::Bool(true));
        attributes.insert(
            "repository_posture_coverage".to_owned(),
            Value::String(coverage_name(state.coverage_state).to_owned()),
        );
        attributes.insert(
            "hosted_rls_state".to_owned(),
            Value::String("UNKNOWN".to_owned()),
        );
        attributes.insert(
            "live_posture".to_owned(),
            Value::String("NOT_EXECUTED".to_owned()),
        );

        evidence.push(authority.seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: input_digests(state_provenance, exposure_provenance),
            observation: format!(
                "RLS state is {rls_state} for API-relevant relation {relation_id} in repository-derived migration state"
            ),
            security_interpretation: None,
            category: "supabase_rls_posture".to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: vec![EvidenceSubject {
                kind: "supabase_relation".to_owned(),
                id: relation_id,
            }],
            locations: vec![
                statement_location(state_provenance),
                config_location(exposure_provenance),
            ],
            attributes,
            reproduction: None,
            captured_at: captured_at.to_owned(),
        })?);
    }

    Ok(evidence)
}

fn state_provenance(relation: &RelationPosture) -> Option<&StatementProvenance> {
    relation
        .rls_state
        .provenance
        .as_ref()
        .or_else(|| relation.exists_in_supported_history.provenance.as_ref())
}

fn rls_state_name(state: RlsState) -> &'static str {
    match state {
        RlsState::Enabled => "ENABLED",
        RlsState::Disabled => "DISABLED",
        RlsState::Unknown => "UNKNOWN",
    }
}

fn coverage_name(state: PostureCoverageState) -> &'static str {
    match state {
        PostureCoverageState::Complete => "COMPLETE",
        PostureCoverageState::Partial => "PARTIAL",
    }
}

fn input_digests(
    state: &StatementProvenance,
    exposure: &ConfigExposureProvenance,
) -> Vec<String> {
    BTreeSet::from([
        state.content_digest.clone(),
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
    use crate::supabase::state::{MigrationSqlInput, reduce_repository_posture};
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
        let input = ApiSchemaExposureInput {
            api_enabled: true,
            schemas: schemas.iter().map(|value| (*value).to_owned()).collect(),
            source: ApiExposureSource::ExplicitConfig,
            provenance: ConfigExposureProvenance {
                path: NormalizedRepoPath::parse(SUPABASE_CONFIG_PATH, 4096).unwrap(),
                content_digest: "sha256:config".to_owned(),
                line: Some(4),
            },
        };
        observe_api_schema_exposure(&input, "2026-08-29T13:00:00Z")
            .unwrap()
            .0
    }

    #[test]
    fn emits_direct_enabled_and_disabled_facts_for_api_relevant_tables() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "rls",
                "sha256:migration",
                "create table public.accounts(id bigint); alter table public.accounts enable row level security; create table public.audit(id bigint); alter table public.audit disable row level security;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let evidence = observe_api_relevant_rls(
            &state,
            &exposure(&["public"]),
            "2026-08-29T13:00:00Z",
            RlsPostureLimits::default(),
        )
        .unwrap();

        assert_eq!(evidence.len(), 2);
        let records: Vec<_> = evidence.iter().map(Evidence::to_record).collect();
        assert_eq!(
            records[0].claim.attributes.get("rls_state"),
            Some(&Value::String("ENABLED".to_owned()))
        );
        assert_eq!(
            records[1].claim.attributes.get("rls_state"),
            Some(&Value::String("DISABLED".to_owned()))
        );
        assert!(records.iter().all(|record| {
            record.claim.security_interpretation.is_none()
                && record.claim.attributes.get("hosted_rls_state")
                    == Some(&Value::String("UNKNOWN".to_owned()))
                && record.claim.attributes.get("live_posture")
                    == Some(&Value::String("NOT_EXECUTED".to_owned()))
        }));
    }

    #[test]
    fn created_api_table_without_supported_rls_transition_emits_unknown() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "table",
                "sha256:table",
                "create table public.accounts(id bigint);",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let evidence = observe_api_relevant_rls(
            &state,
            &exposure(&["public"]),
            "2026-08-29T13:00:00Z",
            RlsPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].claim().attributes.get("rls_state"),
            Some(&Value::String("UNKNOWN".to_owned()))
        );
        assert!(evidence[0].claim().security_interpretation.is_none());
    }

    #[test]
    fn non_api_schema_and_unknown_exposure_emit_no_rls_evidence() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "private",
                "sha256:private",
                "create table private.accounts(id bigint); alter table private.accounts disable row level security;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        assert!(
            observe_api_relevant_rls(
                &state,
                &exposure(&["public"]),
                "2026-08-29T13:00:00Z",
                RlsPostureLimits::default(),
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            observe_api_relevant_rls(
                &state,
                &ApiSchemaExposureSnapshot::unknown(),
                "2026-08-29T13:00:00Z",
                RlsPostureLimits::default(),
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn parser_gaps_remain_visible_on_supported_rls_fact() {
        let state = reduce_repository_posture(
            &[
                migration(
                    "20260829000100",
                    "known",
                    "sha256:known",
                    "create table public.accounts(id bigint); alter table public.accounts enable row level security;",
                ),
                migration(
                    "20260829000200",
                    "dynamic",
                    "sha256:dynamic",
                    "do $$ begin execute 'alter table public.accounts disable row level security'; end $$;",
                ),
            ],
            SqlScanLimits::default(),
        )
        .unwrap();
        assert_eq!(state.coverage_state, PostureCoverageState::Partial);

        let evidence = observe_api_relevant_rls(
            &state,
            &exposure(&["public"]),
            "2026-08-29T13:00:00Z",
            RlsPostureLimits::default(),
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
        assert_eq!(
            evidence[0].claim().attributes.get("rls_state"),
            Some(&Value::String("ENABLED".to_owned()))
        );
    }

    #[test]
    fn relation_cap_fails_closed() {
        let state = reduce_repository_posture(
            &[migration(
                "20260829000100",
                "two",
                "sha256:two",
                "create table public.accounts(id bigint); create table public.audit(id bigint);",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        assert!(matches!(
            observe_api_relevant_rls(
                &state,
                &exposure(&["public"]),
                "2026-08-29T13:00:00Z",
                RlsPostureLimits { max_relations: 1 },
            ),
            Err(RlsPostureError::TooManyApiRelevantRelations { max: 1 })
        ));
        assert!(matches!(
            observe_api_relevant_rls(
                &state,
                &exposure(&["public"]),
                "2026-08-29T13:00:00Z",
                RlsPostureLimits { max_relations: 0 },
            ),
            Err(RlsPostureError::InvalidLimits)
        ));
    }
}
