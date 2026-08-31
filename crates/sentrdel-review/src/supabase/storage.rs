//! Storage-specific projection of supported repository-derived Supabase policy state.
//!
//! Storage authorization remains backed by the same bounded relation and policy
//! substrate used for database posture. This module does not parse a second SQL
//! dialect, execute Storage operations, or claim hosted state. It emits direct
//! FACT Evidence with Storage-specific subjects while preserving parser coverage
//! and keeping security interpretation with the existing reconciler.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    EvidenceValidationError, ProducerKind,
};
use serde_json::Value;

use super::state::{
    ExpressionPresence, PolicyCommandScope, PolicyPosture, PostureCoverageState, RelationPosture,
    RepositoryPostureState, RlsState, StatementProvenance, SupabaseObjectKind,
};

pub const STORAGE_SCHEMA: &str = "storage";
pub const DEFAULT_MAX_STORAGE_RELATIONS: usize = 4_096;
pub const DEFAULT_MAX_STORAGE_POLICIES: usize = 8_192;
const PRODUCER_ID: &str = "sentrdel.supabase.storage-posture";
const PRODUCER_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoragePostureLimits {
    pub max_relations: usize,
    pub max_policies: usize,
}

impl Default for StoragePostureLimits {
    fn default() -> Self {
        Self {
            max_relations: DEFAULT_MAX_STORAGE_RELATIONS,
            max_policies: DEFAULT_MAX_STORAGE_POLICIES,
        }
    }
}

#[derive(Debug)]
pub enum StoragePostureError {
    InvalidLimits,
    EmptyCapturedAt,
    TooManyRelations { max: usize },
    TooManyPolicies { max: usize },
    MissingRelationProvenance { relation: String },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for StoragePostureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("Storage posture limits must be non-zero"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::TooManyRelations { max } => {
                write!(
                    formatter,
                    "Storage relation count exceeds bounded cap {max}"
                )
            }
            Self::TooManyPolicies { max } => {
                write!(formatter, "Storage policy count exceeds bounded cap {max}")
            }
            Self::MissingRelationProvenance { relation } => write!(
                formatter,
                "Storage relation {relation} lacks supported repository provenance"
            ),
            Self::Evidence(error) => {
                write!(formatter, "cannot seal Storage posture evidence: {error}")
            }
        }
    }
}

impl Error for StoragePostureError {}

impl From<EvidenceValidationError> for StoragePostureError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_storage_authorization_posture(
    state: &RepositoryPostureState,
    captured_at: &str,
    limits: StoragePostureLimits,
) -> Result<Vec<Evidence>, StoragePostureError> {
    if limits.max_relations == 0 || limits.max_policies == 0 {
        return Err(StoragePostureError::InvalidLimits);
    }
    if captured_at.trim().is_empty() {
        return Err(StoragePostureError::EmptyCapturedAt);
    }

    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let mut evidence = Vec::new();
    let mut relation_count = 0_usize;
    let mut policy_count = 0_usize;

    for (object, relation) in &state.relations {
        if object.kind != SupabaseObjectKind::Table || object.schema != STORAGE_SCHEMA {
            continue;
        }
        let has_relation_posture =
            relation.exists_in_supported_history.value || relation.rls_state.provenance.is_some();
        let has_policy_posture = !relation.policy_ids.is_empty();
        if !has_relation_posture && !has_policy_posture {
            continue;
        }
        relation_count = relation_count.saturating_add(1);
        if relation_count > limits.max_relations {
            return Err(StoragePostureError::TooManyRelations {
                max: limits.max_relations,
            });
        }
        if has_relation_posture {
            evidence.push(seal_relation(&authority, state, relation, captured_at)?);
        }

        for policy_id in &relation.policy_ids {
            let Some(policy) = state.policies.get(policy_id) else {
                continue;
            };
            policy_count = policy_count.saturating_add(1);
            if policy_count > limits.max_policies {
                return Err(StoragePostureError::TooManyPolicies {
                    max: limits.max_policies,
                });
            }
            evidence.push(seal_policy(&authority, state, policy, captured_at)?);
        }
    }

    Ok(evidence)
}

fn seal_relation(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    relation: &RelationPosture,
    captured_at: &str,
) -> Result<Evidence, StoragePostureError> {
    let relation_id = relation.object.normalized();
    let provenance = relation
        .rls_state
        .provenance
        .as_ref()
        .or(relation.exists_in_supported_history.provenance.as_ref())
        .ok_or_else(|| StoragePostureError::MissingRelationProvenance {
            relation: relation_id.clone(),
        })?;
    let mut attributes = BTreeMap::new();
    attributes.insert("relation".to_owned(), Value::String(relation_id.clone()));
    attributes.insert(
        "rls_state".to_owned(),
        Value::String(rls_name(relation.rls_state.value).to_owned()),
    );
    attributes.insert("storage_schema".to_owned(), Value::Bool(true));
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "repository_posture_coverage".to_owned(),
        Value::String(coverage_name(state.coverage_state).to_owned()),
    );
    attributes.insert(
        "hosted_storage_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "live_posture".to_owned(),
        Value::String("NOT_EXECUTED".to_owned()),
    );

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![provenance.content_digest.clone()],
        observation: format!(
            "Repository-derived Storage relation {relation_id} has RLS state {}",
            rls_name(relation.rls_state.value)
        ),
        security_interpretation: None,
        category: "supabase_storage_relation_posture".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![EvidenceSubject {
            kind: "supabase_storage_relation".to_owned(),
            id: relation_id,
        }],
        locations: vec![location(provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn seal_policy(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    policy: &PolicyPosture,
    captured_at: &str,
) -> Result<Evidence, StoragePostureError> {
    let policy_id = format!(
        "{}::{}",
        policy.identity.relation.normalized(),
        policy.identity.name
    );
    let relation_exists_in_history = state
        .relations
        .get(&policy.identity.relation)
        .is_some_and(|relation| relation.exists_in_supported_history.value);
    let repository_policy_existence = if policy.command_scope.provenance.is_some() {
        "OBSERVED_IN_SUPPORTED_HISTORY"
    } else {
        "NOT_PROVEN"
    };
    let mut attributes = BTreeMap::new();
    attributes.insert("policy".to_owned(), Value::String(policy_id.clone()));
    attributes.insert(
        "relation".to_owned(),
        Value::String(policy.identity.relation.normalized()),
    );
    attributes.insert(
        "command_scope".to_owned(),
        Value::String(command_name(policy.command_scope.value).to_owned()),
    );
    attributes.insert(
        "roles".to_owned(),
        Value::Array(
            policy
                .roles
                .value
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    attributes.insert(
        "using_clause".to_owned(),
        Value::String(expression_name(policy.using_expression.value).to_owned()),
    );
    attributes.insert(
        "with_check_clause".to_owned(),
        Value::String(expression_name(policy.check_expression.value).to_owned()),
    );
    attributes.insert("storage_schema".to_owned(), Value::Bool(true));
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "repository_relation_existence".to_owned(),
        Value::String(
            if relation_exists_in_history {
                "OBSERVED_IN_SUPPORTED_HISTORY"
            } else {
                "NOT_PROVEN"
            }
            .to_owned(),
        ),
    );
    attributes.insert(
        "repository_policy_existence".to_owned(),
        Value::String(repository_policy_existence.to_owned()),
    );
    attributes.insert(
        "repository_posture_coverage".to_owned(),
        Value::String(coverage_name(state.coverage_state).to_owned()),
    );
    attributes.insert(
        "expression_semantic_equivalence".to_owned(),
        Value::String("NOT_EVALUATED".to_owned()),
    );
    attributes.insert(
        "hosted_storage_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "live_posture".to_owned(),
        Value::String("NOT_EXECUTED".to_owned()),
    );

    let observation = if repository_policy_existence == "OBSERVED_IN_SUPPORTED_HISTORY" {
        format!(
            "Supported repository-derived Storage authorization policy posture is present for {policy_id}"
        )
    } else {
        format!(
            "Supported repository-derived Storage policy attributes were observed without proving policy creation for {policy_id}"
        )
    };

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: policy_digests(policy),
        observation,
        security_interpretation: None,
        category: "supabase_storage_policy_posture".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![
            EvidenceSubject {
                kind: "supabase_storage_relation".to_owned(),
                id: policy.identity.relation.normalized(),
            },
            EvidenceSubject {
                kind: "supabase_storage_policy".to_owned(),
                id: policy_id,
            },
        ],
        locations: vec![location(&policy.provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn policy_digests(policy: &PolicyPosture) -> Vec<String> {
    let mut digests = BTreeSet::from([policy.provenance.content_digest.clone()]);
    for provenance in [
        policy.command_scope.provenance.as_ref(),
        policy.roles.provenance.as_ref(),
        policy.using_expression.provenance.as_ref(),
        policy.check_expression.provenance.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        digests.insert(provenance.content_digest.clone());
    }
    digests.into_iter().collect()
}

fn location(provenance: &StatementProvenance) -> EvidenceLocation {
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

fn coverage_name(value: PostureCoverageState) -> &'static str {
    match value {
        PostureCoverageState::Complete => "COMPLETE",
        PostureCoverageState::Partial => "PARTIAL",
    }
}

fn rls_name(value: RlsState) -> &'static str {
    match value {
        RlsState::Enabled => "ENABLED",
        RlsState::Disabled => "DISABLED",
        RlsState::Unknown => "UNKNOWN",
    }
}

fn command_name(value: PolicyCommandScope) -> &'static str {
    match value {
        PolicyCommandScope::All => "ALL",
        PolicyCommandScope::Select => "SELECT",
        PolicyCommandScope::Insert => "INSERT",
        PolicyCommandScope::Update => "UPDATE",
        PolicyCommandScope::Delete => "DELETE",
        PolicyCommandScope::Unknown => "UNKNOWN",
    }
}

fn expression_name(value: ExpressionPresence) -> &'static str {
    match value {
        ExpressionPresence::Present => "PRESENT",
        ExpressionPresence::Absent => "ABSENT",
        ExpressionPresence::Unknown => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supabase::sql::SqlScanLimits;
    use crate::supabase::state::{MigrationSqlInput, reduce_repository_posture};
    use crate::view::NormalizedRepoPath;

    fn migration(order: &str, digest: &str, sql: &str) -> MigrationSqlInput {
        MigrationSqlInput {
            path: NormalizedRepoPath::parse(
                &format!("supabase/migrations/{order}_storage.sql"),
                4096,
            )
            .unwrap(),
            order_key: order.to_owned(),
            content_digest: digest.to_owned(),
            sql: sql.to_owned(),
        }
    }

    fn state(sql: &str) -> RepositoryPostureState {
        reduce_repository_posture(
            &[migration("20260829000100", "sha256:storage", sql)],
            SqlScanLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn maps_storage_relation_and_policy_through_existing_state_substrate() {
        let state = state(
            "create table storage.objects_fixture(id uuid, owner_id uuid); alter table storage.objects_fixture enable row level security; create policy storage_owner_select on storage.objects_fixture for select to authenticated using (owner_id = auth.uid());",
        );
        let evidence = observe_storage_authorization_posture(
            &state,
            "2026-08-29T14:00:00Z",
            StoragePostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 2);
        assert_eq!(
            evidence[0].claim().category,
            "supabase_storage_relation_posture"
        );
        assert_eq!(
            evidence[1].claim().category,
            "supabase_storage_policy_posture"
        );
        assert_eq!(
            evidence[1]
                .claim()
                .attributes
                .get("repository_policy_existence"),
            Some(&Value::String("OBSERVED_IN_SUPPORTED_HISTORY".to_owned()))
        );
        assert!(evidence.iter().all(|item| {
            item.claim().security_interpretation.is_none()
                && item.claim().attributes.get("hosted_storage_state")
                    == Some(&Value::String("UNKNOWN".to_owned()))
        }));
    }

    #[test]
    fn provider_managed_storage_table_policy_is_not_dropped_without_create_table() {
        let state = state(
            "create policy storage_owner_select on storage.objects for select to authenticated using (owner_id = auth.uid());",
        );
        let evidence = observe_storage_authorization_posture(
            &state,
            "2026-08-29T14:00:00Z",
            StoragePostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].claim().category,
            "supabase_storage_policy_posture"
        );
        assert_eq!(
            evidence[0]
                .claim()
                .attributes
                .get("repository_relation_existence"),
            Some(&Value::String("NOT_PROVEN".to_owned()))
        );
        assert_eq!(
            evidence[0]
                .claim()
                .attributes
                .get("repository_policy_existence"),
            Some(&Value::String("OBSERVED_IN_SUPPORTED_HISTORY".to_owned()))
        );
        assert_eq!(
            evidence[0].claim().attributes.get("hosted_storage_state"),
            Some(&Value::String("UNKNOWN".to_owned()))
        );
    }

    #[test]
    fn alter_only_storage_policy_does_not_claim_policy_existence() {
        let state = state(
            "alter policy storage_owner_select on storage.objects to authenticated using (true);",
        );
        let evidence = observe_storage_authorization_posture(
            &state,
            "2026-08-29T14:00:00Z",
            StoragePostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        let policy = &evidence[0];
        assert_eq!(policy.claim().category, "supabase_storage_policy_posture");
        assert_eq!(
            policy.claim().attributes.get("repository_policy_existence"),
            Some(&Value::String("NOT_PROVEN".to_owned()))
        );
        assert_eq!(
            policy
                .claim()
                .attributes
                .get("repository_relation_existence"),
            Some(&Value::String("NOT_PROVEN".to_owned()))
        );
        assert!(
            policy
                .claim()
                .observation
                .contains("without proving policy creation")
        );
    }

    #[test]
    fn broad_storage_policy_is_observation_only_not_direct_finding() {
        let state = state(
            "create table storage.objects_fixture(id uuid); alter table storage.objects_fixture enable row level security; create policy storage_open on storage.objects_fixture for all to public using (true) with check (true);",
        );
        let evidence = observe_storage_authorization_posture(
            &state,
            "2026-08-29T14:00:00Z",
            StoragePostureLimits::default(),
        )
        .unwrap();
        let policy = evidence
            .iter()
            .find(|item| item.claim().category == "supabase_storage_policy_posture")
            .unwrap();
        assert_eq!(
            policy.claim().attributes.get("command_scope"),
            Some(&Value::String("ALL".to_owned()))
        );
        assert_eq!(
            policy.claim().attributes.get("roles"),
            Some(&Value::Array(vec![Value::String("public".to_owned())]))
        );
        assert!(policy.claim().security_interpretation.is_none());
    }

    #[test]
    fn non_storage_relations_are_not_reclassified_as_storage() {
        let state = state(
            "create table public.objects_fixture(id uuid); alter table public.objects_fixture enable row level security; create policy object_read on public.objects_fixture for select to authenticated using (true);",
        );
        assert!(
            observe_storage_authorization_posture(
                &state,
                "2026-08-29T14:00:00Z",
                StoragePostureLimits::default(),
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn parser_gaps_remain_visible_on_supported_storage_facts() {
        let state = reduce_repository_posture(
            &[
                migration(
                    "20260829000100",
                    "sha256:known",
                    "create table storage.objects_fixture(id uuid); alter table storage.objects_fixture enable row level security; create policy storage_owner on storage.objects_fixture for select to authenticated using (true);",
                ),
                migration(
                    "20260829000200",
                    "sha256:dynamic",
                    "do $$ begin execute 'drop policy storage_owner on storage.objects_fixture'; end $$;",
                ),
            ],
            SqlScanLimits::default(),
        )
        .unwrap();
        assert_eq!(state.coverage_state, PostureCoverageState::Partial);
        let evidence = observe_storage_authorization_posture(
            &state,
            "2026-08-29T14:00:00Z",
            StoragePostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.iter().all(|item| {
            item.claim().attributes.get("repository_posture_coverage")
                == Some(&Value::String("PARTIAL".to_owned()))
        }));
    }

    #[test]
    fn caps_and_empty_capture_time_fail_closed() {
        let state = state("create table storage.one(id uuid); create table storage.two(id uuid);");
        assert!(matches!(
            observe_storage_authorization_posture(
                &state,
                "2026-08-29T14:00:00Z",
                StoragePostureLimits {
                    max_relations: 1,
                    max_policies: 1,
                },
            ),
            Err(StoragePostureError::TooManyRelations { max: 1 })
        ));
        assert!(matches!(
            observe_storage_authorization_posture(&state, "", StoragePostureLimits::default(),),
            Err(StoragePostureError::EmptyCapturedAt)
        ));
        assert!(matches!(
            observe_storage_authorization_posture(
                &state,
                "2026-08-29T14:00:00Z",
                StoragePostureLimits {
                    max_relations: 0,
                    max_policies: 1,
                },
            ),
            Err(StoragePostureError::InvalidLimits)
        ));
    }
}
