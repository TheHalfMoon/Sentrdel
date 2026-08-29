//! Supported Supabase policy posture and bounded structural delta Evidence.
//!
//! Policy SQL expressions remain opaque beyond the presence shape already
//! represented by the supported SQL model. This producer compares only
//! repository-derived supported state, reports direct structural observations,
//! and never claims arbitrary boolean equivalence, hosted state, or a Finding.

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
    ExpressionPresence, PolicyCommandScope, PolicyIdentity, PolicyPosture, PostureCoverageState,
    RepositoryPostureState, StatementProvenance,
};

pub const DEFAULT_MAX_POLICY_POSTURES: usize = 4_096;
pub const DEFAULT_MAX_POLICY_DELTAS: usize = 8_192;
const PRODUCER_ID: &str = "sentrdel.supabase.policy-posture";
const PRODUCER_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyPostureLimits {
    pub max_postures: usize,
    pub max_deltas: usize,
}

impl Default for PolicyPostureLimits {
    fn default() -> Self {
        Self {
            max_postures: DEFAULT_MAX_POLICY_POSTURES,
            max_deltas: DEFAULT_MAX_POLICY_DELTAS,
        }
    }
}

#[derive(Debug)]
pub enum PolicyPostureError {
    InvalidLimits,
    EmptyCapturedAt,
    TooManyPostures { max: usize },
    TooManyDeltas { max: usize },
    MissingRemovalProvenance { policy: String },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for PolicyPostureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("policy posture limits must be non-zero"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::TooManyPostures { max } => {
                write!(formatter, "policy posture count exceeds bounded cap {max}")
            }
            Self::TooManyDeltas { max } => {
                write!(formatter, "policy delta count exceeds bounded cap {max}")
            }
            Self::MissingRemovalProvenance { policy } => write!(
                formatter,
                "removed policy {policy} lacks exact repository removal provenance"
            ),
            Self::Evidence(error) => {
                write!(formatter, "cannot seal policy posture evidence: {error}")
            }
        }
    }
}

impl Error for PolicyPostureError {}

impl From<EvidenceValidationError> for PolicyPostureError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_policy_posture(
    state: &RepositoryPostureState,
    captured_at: &str,
    limits: PolicyPostureLimits,
) -> Result<Vec<Evidence>, PolicyPostureError> {
    validate_inputs(captured_at, limits)?;
    if state.policies.len() > limits.max_postures {
        return Err(PolicyPostureError::TooManyPostures {
            max: limits.max_postures,
        });
    }

    let authority = authority()?;
    state
        .policies
        .values()
        .map(|policy| seal_posture(&authority, state, policy, captured_at))
        .collect()
}

pub fn observe_policy_delta(
    before: &RepositoryPostureState,
    after: &RepositoryPostureState,
    captured_at: &str,
    limits: PolicyPostureLimits,
) -> Result<Vec<Evidence>, PolicyPostureError> {
    validate_inputs(captured_at, limits)?;
    let authority = authority()?;
    let identities: BTreeSet<_> = before
        .policies
        .keys()
        .chain(after.policies.keys())
        .cloned()
        .collect();
    let mut evidence = Vec::new();

    for identity in identities {
        match (
            before.policies.get(&identity),
            after.policies.get(&identity),
        ) {
            (Some(old), None) => {
                if old.command_scope.provenance.is_none() {
                    continue;
                }
                let after_provenance = removal_provenance(after, &identity).ok_or_else(|| {
                    PolicyPostureError::MissingRemovalProvenance {
                        policy: policy_id(&identity),
                    }
                })?;
                push_delta(
                    &mut evidence,
                    limits,
                    seal_delta(
                        &authority,
                        before,
                        after,
                        &identity,
                        "POLICY_REMOVED",
                        "Supported repository-derived policy is absent from the after state",
                        &old.provenance,
                        after_provenance,
                        BTreeMap::new(),
                        captured_at,
                    )?,
                )?;
            }
            (None, Some(_)) => {
                // Presence in the after state does not by itself provide a bounded
                // before-input provenance anchor for an absence claim. R2-T012
                // therefore does not emit POLICY_ADDED from state absence alone.
            }
            (Some(old), Some(new)) => {
                append_supported_changes(
                    &authority,
                    before,
                    after,
                    old,
                    new,
                    captured_at,
                    limits,
                    &mut evidence,
                )?;
            }
            (None, None) => unreachable!("identity union contains at least one policy"),
        }
    }

    Ok(evidence)
}

fn append_supported_changes(
    authority: &EvidenceAuthority,
    before: &RepositoryPostureState,
    after: &RepositoryPostureState,
    old: &PolicyPosture,
    new: &PolicyPosture,
    captured_at: &str,
    limits: PolicyPostureLimits,
    evidence: &mut Vec<Evidence>,
) -> Result<(), PolicyPostureError> {
    if old.command_scope.provenance.is_none() || new.command_scope.provenance.is_none() {
        return Ok(());
    }

    if let (Some(old_provenance), Some(new_provenance)) = (
        old.command_scope.provenance.as_ref(),
        new.command_scope.provenance.as_ref(),
    ) && old.command_scope.value != PolicyCommandScope::All
        && old.command_scope.value != PolicyCommandScope::Unknown
        && new.command_scope.value == PolicyCommandScope::All
    {
        push_delta(
            evidence,
            limits,
            seal_delta(
                authority,
                before,
                after,
                &new.identity,
                "COMMAND_SCOPE_EXPANDED_TO_ALL",
                "Supported policy command scope changed to ALL",
                old_provenance,
                new_provenance,
                BTreeMap::from([
                    (
                        "before_command_scope".to_owned(),
                        Value::String(command_name(old.command_scope.value).to_owned()),
                    ),
                    (
                        "after_command_scope".to_owned(),
                        Value::String(command_name(new.command_scope.value).to_owned()),
                    ),
                ]),
                captured_at,
            )?,
        )?;
    }

    if let (Some(old_provenance), Some(new_provenance)) = (
        old.roles.provenance.as_ref(),
        new.roles.provenance.as_ref(),
    ) && role_scope_expanded(&old.roles.value, &new.roles.value)
    {
        let added_roles: Vec<String> = new
            .roles
            .value
            .difference(&old.roles.value)
            .cloned()
            .collect();
        let expansion_basis = if new.roles.value.contains("public") {
            "PUBLIC"
        } else {
            "STRICT_SUPERSET"
        };
        push_delta(
            evidence,
            limits,
            seal_delta(
                authority,
                before,
                after,
                &new.identity,
                "ROLE_SCOPE_EXPANDED",
                "Supported policy role scope expanded under bounded PostgreSQL role semantics",
                old_provenance,
                new_provenance,
                BTreeMap::from([
                    (
                        "added_roles".to_owned(),
                        Value::Array(added_roles.into_iter().map(Value::String).collect()),
                    ),
                    (
                        "scope_expansion_basis".to_owned(),
                        Value::String(expansion_basis.to_owned()),
                    ),
                ]),
                captured_at,
            )?,
        )?;
    }

    if let (Some(old_provenance), Some(new_provenance)) = (
        old.using_expression.provenance.as_ref(),
        new.using_expression.provenance.as_ref(),
    ) {
        append_expression_presence_change(
            authority,
            before,
            after,
            old,
            new,
            "USING",
            old.using_expression.value,
            new.using_expression.value,
            old_provenance,
            new_provenance,
            captured_at,
            limits,
            evidence,
        )?;
    }
    if let (Some(old_provenance), Some(new_provenance)) = (
        old.check_expression.provenance.as_ref(),
        new.check_expression.provenance.as_ref(),
    ) {
        append_expression_presence_change(
            authority,
            before,
            after,
            old,
            new,
            "WITH_CHECK",
            old.check_expression.value,
            new.check_expression.value,
            old_provenance,
            new_provenance,
            captured_at,
            limits,
            evidence,
        )?;
    }

    Ok(())
}

fn role_scope_expanded(old: &BTreeSet<String>, new: &BTreeSet<String>) -> bool {
    if old.contains("public") {
        return false;
    }
    if new.contains("public") {
        return true;
    }
    old.is_subset(new) && old != new
}

#[allow(clippy::too_many_arguments)]
fn append_expression_presence_change(
    authority: &EvidenceAuthority,
    before: &RepositoryPostureState,
    after: &RepositoryPostureState,
    old: &PolicyPosture,
    new: &PolicyPosture,
    clause: &str,
    old_value: ExpressionPresence,
    new_value: ExpressionPresence,
    old_provenance: &StatementProvenance,
    new_provenance: &StatementProvenance,
    captured_at: &str,
    limits: PolicyPostureLimits,
    evidence: &mut Vec<Evidence>,
) -> Result<(), PolicyPostureError> {
    if old_value == new_value {
        return Ok(());
    }
    let kind = match (clause, old_value, new_value) {
        ("USING", ExpressionPresence::Present, ExpressionPresence::Absent) => {
            "USING_CLAUSE_REMOVED"
        }
        ("WITH_CHECK", ExpressionPresence::Present, ExpressionPresence::Absent) => {
            "WITH_CHECK_CLAUSE_REMOVED"
        }
        ("USING", _, _) => "USING_CLAUSE_PRESENCE_CHANGED",
        ("WITH_CHECK", _, _) => "WITH_CHECK_CLAUSE_PRESENCE_CHANGED",
        _ => unreachable!("only supported policy expression clauses are passed"),
    };
    let observation = format!(
        "Supported policy {clause} clause presence changed from {} to {}",
        expression_name(old_value),
        expression_name(new_value)
    );
    push_delta(
        evidence,
        limits,
        seal_delta(
            authority,
            before,
            after,
            &new.identity,
            kind,
            &observation,
            old_provenance,
            new_provenance,
            BTreeMap::from([
                (
                    "before_presence".to_owned(),
                    Value::String(expression_name(old_value).to_owned()),
                ),
                (
                    "after_presence".to_owned(),
                    Value::String(expression_name(new_value).to_owned()),
                ),
            ]),
            captured_at,
        )?,
    )
}

fn seal_posture(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    policy: &PolicyPosture,
    captured_at: &str,
) -> Result<Evidence, PolicyPostureError> {
    let repository_policy_existence = if policy.command_scope.provenance.is_some() {
        "OBSERVED_IN_SUPPORTED_HISTORY"
    } else {
        "NOT_PROVEN"
    };
    let mut attributes = common_policy_attributes(&policy.identity);
    attributes.insert(
        "command_scope".to_owned(),
        Value::String(command_name(policy.command_scope.value).to_owned()),
    );
    attributes.insert("roles".to_owned(), string_array(&policy.roles.value));
    attributes.insert(
        "using_clause".to_owned(),
        Value::String(expression_name(policy.using_expression.value).to_owned()),
    );
    attributes.insert(
        "with_check_clause".to_owned(),
        Value::String(expression_name(policy.check_expression.value).to_owned()),
    );
    attributes.insert(
        "repository_posture_coverage".to_owned(),
        Value::String(coverage_name(state.coverage_state).to_owned()),
    );
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "repository_policy_existence".to_owned(),
        Value::String(repository_policy_existence.to_owned()),
    );
    attributes.insert(
        "hosted_policy_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "expression_semantic_equivalence".to_owned(),
        Value::String("NOT_EVALUATED".to_owned()),
    );

    let observation = if repository_policy_existence == "OBSERVED_IN_SUPPORTED_HISTORY" {
        format!(
            "Supported repository-derived policy posture is present for {}",
            policy_id(&policy.identity)
        )
    } else {
        format!(
            "Supported repository-derived policy attributes were observed without proving policy creation for {}",
            policy_id(&policy.identity)
        )
    };

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: property_digests(policy),
        observation,
        security_interpretation: None,
        category: "supabase_policy_posture".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![policy_subject(&policy.identity)],
        locations: vec![location(&policy.provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

#[allow(clippy::too_many_arguments)]
fn seal_delta(
    authority: &EvidenceAuthority,
    before: &RepositoryPostureState,
    after: &RepositoryPostureState,
    identity: &PolicyIdentity,
    delta_kind: &str,
    observation: &str,
    before_provenance: &StatementProvenance,
    after_provenance: &StatementProvenance,
    extra_attributes: BTreeMap<String, Value>,
    captured_at: &str,
) -> Result<Evidence, PolicyPostureError> {
    let mut attributes = common_policy_attributes(identity);
    attributes.insert(
        "delta_kind".to_owned(),
        Value::String(delta_kind.to_owned()),
    );
    attributes.insert(
        "before_repository_posture_coverage".to_owned(),
        Value::String(coverage_name(before.coverage_state).to_owned()),
    );
    attributes.insert(
        "after_repository_posture_coverage".to_owned(),
        Value::String(coverage_name(after.coverage_state).to_owned()),
    );
    attributes.insert("repository_derived".to_owned(), Value::Bool(true));
    attributes.insert(
        "hosted_policy_state".to_owned(),
        Value::String("UNKNOWN".to_owned()),
    );
    attributes.insert(
        "expression_semantic_equivalence".to_owned(),
        Value::String("NOT_EVALUATED".to_owned()),
    );
    attributes.extend(extra_attributes);

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: digests([before_provenance, after_provenance]),
        observation: format!("{observation}: {}", policy_id(identity)),
        security_interpretation: None,
        category: "supabase_policy_delta".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![policy_subject(identity)],
        locations: vec![location(before_provenance), location(after_provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn push_delta(
    evidence: &mut Vec<Evidence>,
    limits: PolicyPostureLimits,
    item: Evidence,
) -> Result<(), PolicyPostureError> {
    if evidence.len() >= limits.max_deltas {
        return Err(PolicyPostureError::TooManyDeltas {
            max: limits.max_deltas,
        });
    }
    evidence.push(item);
    Ok(())
}

fn removal_provenance<'a>(
    after: &'a RepositoryPostureState,
    identity: &PolicyIdentity,
) -> Option<&'a StatementProvenance> {
    after.policy_removals.get(identity)
}

fn validate_inputs(
    captured_at: &str,
    limits: PolicyPostureLimits,
) -> Result<(), PolicyPostureError> {
    if limits.max_postures == 0 || limits.max_deltas == 0 {
        return Err(PolicyPostureError::InvalidLimits);
    }
    if captured_at.trim().is_empty() {
        return Err(PolicyPostureError::EmptyCapturedAt);
    }
    Ok(())
}

fn authority() -> Result<EvidenceAuthority, PolicyPostureError> {
    Ok(EvidenceAuthority::from_runtime(
        PRODUCER_ID,
        PRODUCER_VERSION,
        ProducerKind::NativeRule,
    )?)
}

fn common_policy_attributes(identity: &PolicyIdentity) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("policy".to_owned(), Value::String(policy_id(identity))),
        (
            "relation".to_owned(),
            Value::String(identity.relation.normalized()),
        ),
        (
            "policy_name".to_owned(),
            Value::String(identity.name.clone()),
        ),
    ])
}

fn property_digests(policy: &PolicyPosture) -> Vec<String> {
    let mut values = vec![&policy.provenance];
    for provenance in [
        policy.command_scope.provenance.as_ref(),
        policy.roles.provenance.as_ref(),
        policy.using_expression.provenance.as_ref(),
        policy.check_expression.provenance.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        values.push(provenance);
    }
    digests(values)
}

fn digests<'a>(values: impl IntoIterator<Item = &'a StatementProvenance>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.content_digest.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn policy_subject(identity: &PolicyIdentity) -> EvidenceSubject {
    EvidenceSubject {
        kind: "supabase_policy".to_owned(),
        id: policy_id(identity),
    }
}

fn policy_id(identity: &PolicyIdentity) -> String {
    format!("{}::{}", identity.relation.normalized(), identity.name)
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

fn string_array(values: &BTreeSet<String>) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn coverage_name(value: PostureCoverageState) -> &'static str {
    match value {
        PostureCoverageState::Complete => "COMPLETE",
        PostureCoverageState::Partial => "PARTIAL",
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

    fn state(migrations: &[MigrationSqlInput]) -> RepositoryPostureState {
        reduce_repository_posture(migrations, SqlScanLimits::default()).unwrap()
    }

    #[test]
    fn posture_reports_supported_shape_without_expression_semantics() {
        let value = state(&[migration(
            "20260829000100",
            "policy",
            "sha256:policy",
            "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated using (owner_id = auth.uid());",
        )]);
        let evidence = observe_policy_posture(
            &value,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        let claim = evidence[0].claim();
        assert_eq!(
            claim.attributes.get("command_scope"),
            Some(&Value::String("SELECT".to_owned()))
        );
        assert_eq!(
            claim.attributes.get("using_clause"),
            Some(&Value::String("PRESENT".to_owned()))
        );
        assert_eq!(
            claim.attributes.get("repository_policy_existence"),
            Some(&Value::String("OBSERVED_IN_SUPPORTED_HISTORY".to_owned()))
        );
        assert_eq!(
            claim.attributes.get("expression_semantic_equivalence"),
            Some(&Value::String("NOT_EVALUATED".to_owned()))
        );
        assert!(claim.security_interpretation.is_none());
    }

    #[test]
    fn alter_only_posture_does_not_claim_policy_existence() {
        let value = state(&[migration(
            "20260829000100",
            "alter_only",
            "sha256:alter",
            "alter policy account_access on public.accounts to authenticated using (true);",
        )]);
        let evidence = observe_policy_posture(
            &value,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        let claim = evidence[0].claim();
        assert_eq!(
            claim.attributes.get("repository_policy_existence"),
            Some(&Value::String("NOT_PROVEN".to_owned()))
        );
        assert_eq!(
            claim.attributes.get("command_scope"),
            Some(&Value::String("UNKNOWN".to_owned()))
        );
        assert!(claim.observation.contains("without proving policy creation"));
    }

    #[test]
    fn alter_only_removal_does_not_invent_policy_delta() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "alter policy account_access on public.accounts to authenticated using (true);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "drop policy account_access on public.accounts;",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn alter_only_role_expansion_does_not_invent_policy_delta() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "alter policy account_access on public.accounts to authenticated using (true);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "alter policy account_access on public.accounts to authenticated, anon using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn removal_keeps_exact_drop_provenance_after_unrelated_security_change() {
        let first = migration(
            "20260829000100",
            "policy",
            "sha256:create",
            "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated using (true);",
        );
        let before = state(std::slice::from_ref(&first));
        let after = state(&[
            first,
            migration(
                "20260829000200",
                "drop",
                "sha256:drop",
                "drop policy account_select on public.accounts;",
            ),
            migration(
                "20260829000300",
                "rls",
                "sha256:rls",
                "alter table public.accounts enable row level security;",
            ),
        ]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].claim().attributes.get("delta_kind"),
            Some(&Value::String("POLICY_REMOVED".to_owned()))
        );
        assert!(
            evidence[0]
                .claim()
                .input_digests
                .contains(&"sha256:drop".to_owned())
        );
        assert!(
            !evidence[0]
                .claim()
                .input_digests
                .contains(&"sha256:rls".to_owned())
        );
    }

    #[test]
    fn new_policy_without_before_provenance_anchor_does_not_invent_added_delta() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn supported_role_and_command_expansion_are_structural_only() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to authenticated using (true);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for all to authenticated, anon using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        let kinds: BTreeSet<_> = evidence
            .iter()
            .filter_map(|item| item.claim().attributes.get("delta_kind"))
            .filter_map(Value::as_str)
            .collect();
        assert!(kinds.contains("COMMAND_SCOPE_EXPANDED_TO_ALL"));
        assert!(kinds.contains("ROLE_SCOPE_EXPANDED"));
        assert!(evidence.iter().all(|item| {
            item.claim().security_interpretation.is_none()
                && item
                    .claim()
                    .attributes
                    .get("expression_semantic_equivalence")
                    == Some(&Value::String("NOT_EVALUATED".to_owned()))
        }));
    }

    #[test]
    fn role_replacement_is_not_reported_as_structural_widening() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to authenticated using (true);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to anon using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn adding_roles_to_public_is_not_reported_as_authorization_widening() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to public using (true);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to public, anon, authenticated using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn transition_to_public_is_reported_as_authorization_widening() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to authenticated using (true);",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "create table public.accounts(id bigint); create policy account_access on public.accounts for select to public using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].claim().attributes.get("delta_kind"),
            Some(&Value::String("ROLE_SCOPE_EXPANDED".to_owned()))
        );
        assert_eq!(
            evidence[0]
                .claim()
                .attributes
                .get("scope_expansion_basis"),
            Some(&Value::String("PUBLIC".to_owned()))
        );
        assert_eq!(
            evidence[0].claim().attributes.get("added_roles"),
            Some(&Value::Array(vec![Value::String("public".to_owned())]))
        );
    }

    #[test]
    fn unknown_prior_property_state_does_not_invent_structural_delta() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "alter policy account_access on public.accounts to authenticated;",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "alter policy account_access on public.accounts to authenticated using (true);",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn expression_presence_change_does_not_claim_boolean_equivalence() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated using (owner_id = auth.uid());",
        )]);
        let after = state(&[migration(
            "20260829000100",
            "after",
            "sha256:after",
            "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated;",
        )]);
        let evidence = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].claim().attributes.get("delta_kind"),
            Some(&Value::String("USING_CLAUSE_REMOVED".to_owned()))
        );
        assert_eq!(
            evidence[0]
                .claim()
                .attributes
                .get("expression_semantic_equivalence"),
            Some(&Value::String("NOT_EVALUATED".to_owned()))
        );
    }

    #[test]
    fn parser_gap_coverage_is_preserved_in_posture_and_delta() {
        let before = state(&[migration(
            "20260829000100",
            "before",
            "sha256:before",
            "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated using (true);",
        )]);
        let after = state(&[
            migration(
                "20260829000100",
                "after",
                "sha256:after",
                "create table public.accounts(id bigint); create policy account_select on public.accounts for select to authenticated, anon using (true);",
            ),
            migration(
                "20260829000200",
                "dynamic",
                "sha256:dynamic",
                "do $$ begin execute 'drop policy account_select on public.accounts'; end $$;",
            ),
        ]);
        assert_eq!(after.coverage_state, PostureCoverageState::Partial);
        let posture = observe_policy_posture(
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            posture[0]
                .claim()
                .attributes
                .get("repository_posture_coverage"),
            Some(&Value::String("PARTIAL".to_owned()))
        );
        let delta = observe_policy_delta(
            &before,
            &after,
            "2026-08-29T13:40:00Z",
            PolicyPostureLimits::default(),
        )
        .unwrap();
        assert_eq!(
            delta[0]
                .claim()
                .attributes
                .get("after_repository_posture_coverage"),
            Some(&Value::String("PARTIAL".to_owned()))
        );
    }

    #[test]
    fn caps_and_empty_capture_time_fail_closed() {
        let value = state(&[migration(
            "20260829000100",
            "policy",
            "sha256:policy",
            "create table public.accounts(id bigint); create policy one on public.accounts using (true); create policy two on public.accounts using (true);",
        )]);
        assert!(matches!(
            observe_policy_posture(
                &value,
                "2026-08-29T13:40:00Z",
                PolicyPostureLimits {
                    max_postures: 1,
                    max_deltas: 1,
                },
            ),
            Err(PolicyPostureError::TooManyPostures { max: 1 })
        ));
        assert!(matches!(
            observe_policy_posture(&value, "", PolicyPostureLimits::default()),
            Err(PolicyPostureError::EmptyCapturedAt)
        ));
        assert!(matches!(
            observe_policy_posture(
                &value,
                "2026-08-29T13:40:00Z",
                PolicyPostureLimits {
                    max_postures: 0,
                    max_deltas: 1,
                },
            ),
            Err(PolicyPostureError::InvalidLimits)
        ));
    }
}
