//! Deterministic repository-derived Supabase posture state reduction.
//!
//! Repository SQL remains untrusted text. This reducer replays only the bounded
//! statement model produced by `supabase::sql_model`, records statement-level
//! provenance for every state mutation, and keeps unknown or unsupported
//! security-relevant state visible through explicit coverage gaps. It never
//! executes SQL or contacts a provider.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::view::NormalizedRepoPath;

use super::sql::SqlScanLimits;
use super::sql_model::{
    SqlFunctionSecurityMode, SqlGrantObjectKind, SqlObjectName, SqlParseCoverage, SqlPolicyCommand,
    SqlSearchPathAttribute, SupportedSqlStatement, parse_sql_model,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SupabaseObjectKind {
    Schema,
    Table,
    View,
    Function,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SupabaseObjectId {
    pub schema: String,
    pub name: String,
    pub kind: SupabaseObjectKind,
}

impl SupabaseObjectId {
    #[must_use]
    pub fn normalized(&self) -> String {
        format!("{}.{}", self.schema, self.name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatementProvenance {
    pub path: NormalizedRepoPath,
    pub migration_order: usize,
    pub statement_index: usize,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
    pub content_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostureProperty<T> {
    pub value: T,
    pub provenance: Option<StatementProvenance>,
}

impl<T> PostureProperty<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            provenance: None,
        }
    }

    fn set(&mut self, value: T, provenance: &StatementProvenance) {
        self.value = value;
        self.provenance = Some(provenance.clone());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RlsState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureState {
    ApiRelevant,
    NotProvenApiRelevant,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ViewSecurityInvokerState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyCommandScope {
    All,
    Select,
    Insert,
    Update,
    Delete,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionPresence {
    Present,
    Absent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionSecurityState {
    Invoker,
    Definer,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionSearchPathState {
    PinnedEmpty,
    PinnedExplicit(Vec<String>),
    UnpinnedOrMutable,
    Unknown,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GrantKey {
    pub role: String,
    pub privilege: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationPosture {
    pub object: SupabaseObjectId,
    pub exists_in_supported_history: PostureProperty<bool>,
    pub rls_state: PostureProperty<RlsState>,
    pub grants: BTreeMap<GrantKey, StatementProvenance>,
    pub last_revoke_by_role: BTreeMap<String, StatementProvenance>,
    pub policy_ids: BTreeSet<PolicyIdentity>,
    pub exposure_state: PostureProperty<ExposureState>,
    pub view_security_invoker: PostureProperty<ViewSecurityInvokerState>,
    pub last_security_change: Option<StatementProvenance>,
}

impl RelationPosture {
    fn new(object: SupabaseObjectId) -> Self {
        Self {
            object,
            exists_in_supported_history: PostureProperty::new(false),
            rls_state: PostureProperty::new(RlsState::Unknown),
            grants: BTreeMap::new(),
            last_revoke_by_role: BTreeMap::new(),
            policy_ids: BTreeSet::new(),
            exposure_state: PostureProperty::new(ExposureState::Unknown),
            view_security_invoker: PostureProperty::new(ViewSecurityInvokerState::Unknown),
            last_security_change: None,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PolicyIdentity {
    pub relation: SupabaseObjectId,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyPosture {
    pub identity: PolicyIdentity,
    pub command_scope: PostureProperty<PolicyCommandScope>,
    pub roles: PostureProperty<BTreeSet<String>>,
    pub using_expression: PostureProperty<ExpressionPresence>,
    pub check_expression: PostureProperty<ExpressionPresence>,
    pub provenance: StatementProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FunctionPosture {
    pub object: SupabaseObjectId,
    pub exists_in_supported_history: PostureProperty<bool>,
    pub security_mode: PostureProperty<FunctionSecurityState>,
    pub search_path: PostureProperty<FunctionSearchPathState>,
    pub schema_exposure: PostureProperty<ExposureState>,
    pub execute_grants: BTreeMap<String, StatementProvenance>,
    pub provenance: StatementProvenance,
}

impl FunctionPosture {
    fn new(object: SupabaseObjectId, provenance: &StatementProvenance) -> Self {
        Self {
            object,
            exists_in_supported_history: PostureProperty::new(false),
            security_mode: PostureProperty::new(FunctionSecurityState::Unknown),
            search_path: PostureProperty::new(FunctionSearchPathState::Unknown),
            schema_exposure: PostureProperty::new(ExposureState::Unknown),
            execute_grants: BTreeMap::new(),
            provenance: provenance.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GenericGrantTargetKind {
    Schema,
    Sequence,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GenericGrantTarget {
    pub kind: GenericGrantTargetKind,
    pub object: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostureCoverageState {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostureCoverageGapKind {
    UnsupportedSecurityRelevant,
    MalformedOrBoundedRejection,
    BoundedScanRejection,
    AmbiguousObjectIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostureCoverageGap {
    pub kind: PostureCoverageGapKind,
    pub path: NormalizedRepoPath,
    pub migration_order: usize,
    pub statement_index: Option<usize>,
    pub provenance: Option<StatementProvenance>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryPostureState {
    pub schemas: BTreeMap<String, StatementProvenance>,
    pub relations: BTreeMap<SupabaseObjectId, RelationPosture>,
    pub policies: BTreeMap<PolicyIdentity, PolicyPosture>,
    pub policy_removals: BTreeMap<PolicyIdentity, StatementProvenance>,
    pub functions: BTreeMap<SupabaseObjectId, FunctionPosture>,
    pub generic_grants: BTreeMap<GenericGrantTarget, BTreeMap<GrantKey, StatementProvenance>>,
    pub coverage_state: PostureCoverageState,
    pub coverage_gaps: Vec<PostureCoverageGap>,
}

impl Default for RepositoryPostureState {
    fn default() -> Self {
        Self {
            schemas: BTreeMap::new(),
            relations: BTreeMap::new(),
            policies: BTreeMap::new(),
            policy_removals: BTreeMap::new(),
            functions: BTreeMap::new(),
            generic_grants: BTreeMap::new(),
            coverage_state: PostureCoverageState::Complete,
            coverage_gaps: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationSqlInput {
    pub path: NormalizedRepoPath,
    pub order_key: String,
    pub content_digest: String,
    pub sql: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PostureReductionError {
    AmbiguousOrderKey {
        order_key: String,
        first: NormalizedRepoPath,
        second: NormalizedRepoPath,
    },
}

impl fmt::Display for PostureReductionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousOrderKey {
                order_key,
                first,
                second,
            } => write!(
                formatter,
                "Supabase posture replay order key {order_key} is ambiguous between {first} and {second}"
            ),
        }
    }
}

impl Error for PostureReductionError {}

pub fn reduce_repository_posture(
    migrations: &[MigrationSqlInput],
    limits: SqlScanLimits,
) -> Result<RepositoryPostureState, PostureReductionError> {
    let mut ordered = migrations.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.order_key
            .cmp(&right.order_key)
            .then_with(|| left.path.cmp(&right.path))
    });

    for pair in ordered.windows(2) {
        let [left, right] = pair else {
            continue;
        };
        if left.order_key == right.order_key {
            return Err(PostureReductionError::AmbiguousOrderKey {
                order_key: left.order_key.clone(),
                first: left.path.clone(),
                second: right.path.clone(),
            });
        }
    }

    let mut state = RepositoryPostureState::default();
    for (migration_order, migration) in ordered.into_iter().enumerate() {
        let scan = match parse_sql_model(&migration.sql, limits) {
            Ok(scan) => scan,
            Err(_) => {
                push_gap(
                    &mut state,
                    PostureCoverageGapKind::BoundedScanRejection,
                    migration,
                    migration_order,
                    None,
                    None,
                );
                continue;
            }
        };

        for statement in scan.statements {
            let provenance = StatementProvenance {
                path: migration.path.clone(),
                migration_order,
                statement_index: statement.statement_index,
                start_byte: Some(statement.span.start_byte),
                end_byte: Some(statement.span.end_byte),
                content_digest: migration.content_digest.clone(),
            };

            match statement.coverage {
                SqlParseCoverage::Supported => {
                    if let Some(supported) = statement.supported {
                        apply_supported_statement(&mut state, supported, &provenance);
                    } else {
                        push_gap(
                            &mut state,
                            PostureCoverageGapKind::MalformedOrBoundedRejection,
                            migration,
                            migration_order,
                            Some(statement.statement_index),
                            Some(provenance),
                        );
                    }
                }
                SqlParseCoverage::IgnoredSafeScope => {}
                SqlParseCoverage::UnsupportedSecurityRelevant => push_gap(
                    &mut state,
                    PostureCoverageGapKind::UnsupportedSecurityRelevant,
                    migration,
                    migration_order,
                    Some(statement.statement_index),
                    Some(provenance),
                ),
                SqlParseCoverage::MalformedOrBoundedRejection => push_gap(
                    &mut state,
                    PostureCoverageGapKind::MalformedOrBoundedRejection,
                    migration,
                    migration_order,
                    Some(statement.statement_index),
                    Some(provenance),
                ),
            }
        }
    }

    Ok(state)
}

fn push_gap(
    state: &mut RepositoryPostureState,
    kind: PostureCoverageGapKind,
    migration: &MigrationSqlInput,
    migration_order: usize,
    statement_index: Option<usize>,
    provenance: Option<StatementProvenance>,
) {
    state.coverage_state = PostureCoverageState::Partial;
    state.coverage_gaps.push(PostureCoverageGap {
        kind,
        path: migration.path.clone(),
        migration_order,
        statement_index,
        provenance,
    });
}

fn push_identity_gap(state: &mut RepositoryPostureState, provenance: &StatementProvenance) {
    state.coverage_state = PostureCoverageState::Partial;
    state.coverage_gaps.push(PostureCoverageGap {
        kind: PostureCoverageGapKind::AmbiguousObjectIdentity,
        path: provenance.path.clone(),
        migration_order: provenance.migration_order,
        statement_index: Some(provenance.statement_index),
        provenance: Some(provenance.clone()),
    });
}

fn apply_supported_statement(
    state: &mut RepositoryPostureState,
    statement: SupportedSqlStatement,
    provenance: &StatementProvenance,
) {
    match statement {
        SupportedSqlStatement::CreateSchema { schema } => {
            let Some(schema_name) = schema_name(&schema) else {
                push_identity_gap(state, provenance);
                return;
            };
            state.schemas.insert(schema_name, provenance.clone());
        }
        SupportedSqlStatement::CreateTable { relation } => {
            let Some(object) = qualified_object(&relation, SupabaseObjectKind::Table) else {
                push_identity_gap(state, provenance);
                return;
            };
            let posture = relation_posture_mut(state, object);
            posture.exists_in_supported_history.set(true, provenance);
            posture.last_security_change = Some(provenance.clone());
        }
        SupportedSqlStatement::AlterTableRls { relation, enabled } => {
            let Some(object) = qualified_object(&relation, SupabaseObjectKind::Table) else {
                push_identity_gap(state, provenance);
                return;
            };
            let posture = relation_posture_mut(state, object);
            posture.rls_state.set(
                if enabled {
                    RlsState::Enabled
                } else {
                    RlsState::Disabled
                },
                provenance,
            );
            posture.last_security_change = Some(provenance.clone());
        }
        SupportedSqlStatement::CreatePolicy {
            policy,
            relation,
            command,
            roles,
            has_using,
            has_with_check,
        } => {
            let Some(relation) = qualified_object(&relation, SupabaseObjectKind::Table) else {
                push_identity_gap(state, provenance);
                return;
            };
            let identity = PolicyIdentity {
                relation: relation.clone(),
                name: policy,
            };
            let posture = PolicyPosture {
                identity: identity.clone(),
                command_scope: PostureProperty {
                    value: policy_command(command),
                    provenance: Some(provenance.clone()),
                },
                roles: PostureProperty {
                    value: roles.into_iter().collect(),
                    provenance: Some(provenance.clone()),
                },
                using_expression: PostureProperty {
                    value: expression_presence(has_using),
                    provenance: Some(provenance.clone()),
                },
                check_expression: PostureProperty {
                    value: expression_presence(has_with_check),
                    provenance: Some(provenance.clone()),
                },
                provenance: provenance.clone(),
            };
            state.policy_removals.remove(&identity);
            state.policies.insert(identity.clone(), posture);
            let relation_posture = relation_posture_mut(state, relation);
            relation_posture.policy_ids.insert(identity);
            relation_posture.last_security_change = Some(provenance.clone());
        }
        SupportedSqlStatement::AlterPolicy {
            policy,
            relation,
            roles,
            has_using,
            has_with_check,
        } => {
            let Some(relation) = qualified_object(&relation, SupabaseObjectKind::Table) else {
                push_identity_gap(state, provenance);
                return;
            };
            let identity = PolicyIdentity {
                relation: relation.clone(),
                name: policy,
            };
            let posture = state
                .policies
                .entry(identity.clone())
                .or_insert_with(|| PolicyPosture {
                    identity: identity.clone(),
                    command_scope: PostureProperty::new(PolicyCommandScope::Unknown),
                    roles: PostureProperty::new(BTreeSet::new()),
                    using_expression: PostureProperty::new(ExpressionPresence::Unknown),
                    check_expression: PostureProperty::new(ExpressionPresence::Unknown),
                    provenance: provenance.clone(),
                });
            if let Some(roles) = roles {
                posture.roles.set(roles.into_iter().collect(), provenance);
            }
            if has_using {
                posture
                    .using_expression
                    .set(ExpressionPresence::Present, provenance);
            }
            if has_with_check {
                posture
                    .check_expression
                    .set(ExpressionPresence::Present, provenance);
            }
            posture.provenance = provenance.clone();
            let relation_posture = relation_posture_mut(state, relation);
            relation_posture.policy_ids.insert(identity);
            relation_posture.last_security_change = Some(provenance.clone());
        }
        SupportedSqlStatement::DropPolicy { policy, relation } => {
            let Some(relation) = qualified_object(&relation, SupabaseObjectKind::Table) else {
                push_identity_gap(state, provenance);
                return;
            };
            let identity = PolicyIdentity {
                relation: relation.clone(),
                name: policy,
            };
            state.policies.remove(&identity);
            state
                .policy_removals
                .insert(identity.clone(), provenance.clone());
            let relation_posture = relation_posture_mut(state, relation);
            relation_posture.policy_ids.remove(&identity);
            relation_posture.last_security_change = Some(provenance.clone());
        }
        SupportedSqlStatement::Grant {
            privileges,
            object_kind,
            objects,
            roles,
        } => apply_grant_change(
            state,
            false,
            privileges,
            object_kind,
            objects,
            roles,
            provenance,
        ),
        SupportedSqlStatement::Revoke {
            privileges,
            object_kind,
            objects,
            roles,
        } => apply_grant_change(
            state,
            true,
            privileges,
            object_kind,
            objects,
            roles,
            provenance,
        ),
        SupportedSqlStatement::CreateFunction {
            function,
            security_mode,
            search_path,
        } => {
            let Some(object) = qualified_object(&function, SupabaseObjectKind::Function) else {
                push_identity_gap(state, provenance);
                return;
            };
            let posture = state
                .functions
                .entry(object.clone())
                .or_insert_with(|| FunctionPosture::new(object, provenance));
            posture.exists_in_supported_history.set(true, provenance);
            posture
                .security_mode
                .set(function_security(security_mode), provenance);
            posture
                .search_path
                .set(function_search_path(search_path), provenance);
            posture.provenance = provenance.clone();
        }
        SupportedSqlStatement::AlterFunction {
            function,
            security_mode,
            search_path,
        } => {
            let Some(object) = qualified_object(&function, SupabaseObjectKind::Function) else {
                push_identity_gap(state, provenance);
                return;
            };
            let posture = state
                .functions
                .entry(object.clone())
                .or_insert_with(|| FunctionPosture::new(object, provenance));
            if security_mode != SqlFunctionSecurityMode::Unspecified {
                posture
                    .security_mode
                    .set(function_security(security_mode), provenance);
            }
            if search_path != SqlSearchPathAttribute::Unspecified {
                posture
                    .search_path
                    .set(function_search_path(search_path), provenance);
            }
            posture.provenance = provenance.clone();
        }
        SupportedSqlStatement::DropFunction { function } => {
            let Some(object) = qualified_object(&function, SupabaseObjectKind::Function) else {
                push_identity_gap(state, provenance);
                return;
            };
            state.functions.remove(&object);
        }
        SupportedSqlStatement::CreateView {
            view,
            security_invoker,
        } => {
            let Some(object) = qualified_object(&view, SupabaseObjectKind::View) else {
                push_identity_gap(state, provenance);
                return;
            };
            let posture = relation_posture_mut(state, object);
            posture.exists_in_supported_history.set(true, provenance);
            posture.view_security_invoker.set(
                match security_invoker {
                    Some(true) => ViewSecurityInvokerState::Enabled,
                    Some(false) => ViewSecurityInvokerState::Disabled,
                    None => ViewSecurityInvokerState::Unknown,
                },
                provenance,
            );
            posture.last_security_change = Some(provenance.clone());
        }
    }
}

fn relation_posture_mut(
    state: &mut RepositoryPostureState,
    object: SupabaseObjectId,
) -> &mut RelationPosture {
    state
        .relations
        .entry(object.clone())
        .or_insert_with(|| RelationPosture::new(object))
}

fn apply_grant_change(
    state: &mut RepositoryPostureState,
    revoke: bool,
    privileges: Vec<String>,
    object_kind: SqlGrantObjectKind,
    objects: Vec<SqlObjectName>,
    roles: Vec<String>,
    provenance: &StatementProvenance,
) {
    for object in objects {
        match object_kind {
            SqlGrantObjectKind::Relation | SqlGrantObjectKind::Table => {
                let Some(object) = qualified_object(&object, SupabaseObjectKind::Table) else {
                    push_identity_gap(state, provenance);
                    continue;
                };
                let posture = relation_posture_mut(state, object);
                if revoke {
                    for role in &roles {
                        posture
                            .last_revoke_by_role
                            .insert(role.clone(), provenance.clone());
                    }
                }
                mutate_grants(&mut posture.grants, revoke, &privileges, &roles, provenance);
                posture.last_security_change = Some(provenance.clone());
            }
            SqlGrantObjectKind::Function => {
                let Some(object) = qualified_object(&object, SupabaseObjectKind::Function) else {
                    push_identity_gap(state, provenance);
                    continue;
                };
                let posture = state
                    .functions
                    .entry(object.clone())
                    .or_insert_with(|| FunctionPosture::new(object, provenance));
                let changes_execute = privileges
                    .iter()
                    .any(|privilege| privilege == "EXECUTE" || privilege == "ALL");
                if changes_execute {
                    for role in &roles {
                        if revoke {
                            posture.execute_grants.remove(role);
                        } else {
                            posture
                                .execute_grants
                                .insert(role.clone(), provenance.clone());
                        }
                    }
                }
                posture.provenance = provenance.clone();
            }
            SqlGrantObjectKind::Schema | SqlGrantObjectKind::Sequence => {
                let target = GenericGrantTarget {
                    kind: if object_kind == SqlGrantObjectKind::Schema {
                        GenericGrantTargetKind::Schema
                    } else {
                        GenericGrantTargetKind::Sequence
                    },
                    object: object.normalized(),
                };
                let grants = state.generic_grants.entry(target).or_default();
                mutate_grants(grants, revoke, &privileges, &roles, provenance);
            }
        }
    }
}

fn mutate_grants(
    grants: &mut BTreeMap<GrantKey, StatementProvenance>,
    revoke: bool,
    privileges: &[String],
    roles: &[String],
    provenance: &StatementProvenance,
) {
    for role in roles {
        if revoke && privileges.iter().any(|privilege| privilege == "ALL") {
            grants.retain(|key, _| key.role != *role);
            continue;
        }
        for privilege in privileges {
            let key = GrantKey {
                role: role.clone(),
                privilege: privilege.clone(),
            };
            if revoke {
                grants.remove(&key);
            } else {
                grants.insert(key, provenance.clone());
            }
        }
    }
}

fn schema_name(object: &SqlObjectName) -> Option<String> {
    (object.parts.len() == 1).then(|| object.parts[0].clone())
}

fn qualified_object(object: &SqlObjectName, kind: SupabaseObjectKind) -> Option<SupabaseObjectId> {
    if object.parts.len() != 2 {
        return None;
    }
    Some(SupabaseObjectId {
        schema: object.parts[0].clone(),
        name: object.parts[1].clone(),
        kind,
    })
}

fn policy_command(command: SqlPolicyCommand) -> PolicyCommandScope {
    match command {
        SqlPolicyCommand::All => PolicyCommandScope::All,
        SqlPolicyCommand::Select => PolicyCommandScope::Select,
        SqlPolicyCommand::Insert => PolicyCommandScope::Insert,
        SqlPolicyCommand::Update => PolicyCommandScope::Update,
        SqlPolicyCommand::Delete => PolicyCommandScope::Delete,
    }
}

fn expression_presence(present: bool) -> ExpressionPresence {
    if present {
        ExpressionPresence::Present
    } else {
        ExpressionPresence::Absent
    }
}

fn function_security(mode: SqlFunctionSecurityMode) -> FunctionSecurityState {
    match mode {
        SqlFunctionSecurityMode::Invoker => FunctionSecurityState::Invoker,
        SqlFunctionSecurityMode::Definer => FunctionSecurityState::Definer,
        SqlFunctionSecurityMode::Unspecified => FunctionSecurityState::Unknown,
    }
}

fn function_search_path(search_path: SqlSearchPathAttribute) -> FunctionSearchPathState {
    match search_path {
        SqlSearchPathAttribute::PinnedEmpty => FunctionSearchPathState::PinnedEmpty,
        SqlSearchPathAttribute::PinnedExplicit(values) => {
            FunctionSearchPathState::PinnedExplicit(values)
        }
        SqlSearchPathAttribute::MutableOrDefault => FunctionSearchPathState::UnpinnedOrMutable,
        SqlSearchPathAttribute::Unspecified => FunctionSearchPathState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migration(path: &str, order_key: &str, digest: &str, sql: &str) -> MigrationSqlInput {
        MigrationSqlInput {
            path: NormalizedRepoPath::parse(path, 4096).unwrap(),
            order_key: order_key.to_owned(),
            content_digest: digest.to_owned(),
            sql: sql.to_owned(),
        }
    }

    #[test]
    fn replay_is_deterministic_and_latest_supported_property_change_wins() {
        let later = migration(
            "supabase/migrations/20260829000200_disable.sql",
            "20260829000200",
            "digest-b",
            "alter table public.accounts disable row level security;",
        );
        let earlier = migration(
            "supabase/migrations/20260829000100_create.sql",
            "20260829000100",
            "digest-a",
            "create table public.accounts(id bigint); alter table public.accounts enable row level security;",
        );

        let forward =
            reduce_repository_posture(&[earlier.clone(), later.clone()], SqlScanLimits::default())
                .unwrap();
        let reversed =
            reduce_repository_posture(&[later, earlier], SqlScanLimits::default()).unwrap();
        assert_eq!(forward, reversed);

        let object = SupabaseObjectId {
            schema: "public".to_owned(),
            name: "accounts".to_owned(),
            kind: SupabaseObjectKind::Table,
        };
        let relation = forward.relations.get(&object).unwrap();
        assert!(relation.exists_in_supported_history.value);
        assert_eq!(relation.rls_state.value, RlsState::Disabled);
        let provenance = relation.rls_state.provenance.as_ref().unwrap();
        assert_eq!(provenance.migration_order, 1);
        assert_eq!(provenance.content_digest, "digest-b");
        assert_eq!(forward.coverage_state, PostureCoverageState::Complete);
    }

    #[test]
    fn policy_state_preserves_property_provenance_and_drop_semantics() {
        let state = reduce_repository_posture(
            &[
                migration(
                    "supabase/migrations/20260829000100_policy.sql",
                    "20260829000100",
                    "digest-a",
                    "create table public.accounts(id bigint); create policy account_read on public.accounts for select to anon using (true);",
                ),
                migration(
                    "supabase/migrations/20260829000200_policy.sql",
                    "20260829000200",
                    "digest-b",
                    "alter policy account_read on public.accounts to authenticated with check (true);",
                ),
            ],
            SqlScanLimits::default(),
        )
        .unwrap();

        let relation = SupabaseObjectId {
            schema: "public".to_owned(),
            name: "accounts".to_owned(),
            kind: SupabaseObjectKind::Table,
        };
        let identity = PolicyIdentity {
            relation: relation.clone(),
            name: "account_read".to_owned(),
        };
        let policy = state.policies.get(&identity).unwrap();
        assert_eq!(policy.command_scope.value, PolicyCommandScope::Select);
        assert_eq!(
            policy.roles.value,
            BTreeSet::from(["authenticated".to_owned()])
        );
        assert_eq!(policy.using_expression.value, ExpressionPresence::Present);
        assert_eq!(policy.check_expression.value, ExpressionPresence::Present);
        assert_eq!(
            policy
                .command_scope
                .provenance
                .as_ref()
                .unwrap()
                .migration_order,
            0
        );
        assert_eq!(policy.roles.provenance.as_ref().unwrap().migration_order, 1);
        assert!(
            state
                .relations
                .get(&relation)
                .unwrap()
                .policy_ids
                .contains(&identity)
        );

        let dropped = reduce_repository_posture(
            &[
                migration(
                    "supabase/migrations/20260829000100_policy.sql",
                    "20260829000100",
                    "digest-a",
                    "create policy account_read on public.accounts using (true);",
                ),
                migration(
                    "supabase/migrations/20260829000200_drop.sql",
                    "20260829000200",
                    "digest-b",
                    "drop policy account_read on public.accounts;",
                ),
            ],
            SqlScanLimits::default(),
        )
        .unwrap();
        assert!(!dropped.policies.contains_key(&identity));
        assert!(
            !dropped
                .relations
                .get(&relation)
                .unwrap()
                .policy_ids
                .contains(&identity)
        );
    }

    #[test]
    fn grants_rls_and_function_authority_remain_independent_state() {
        let state = reduce_repository_posture(
            &[migration(
                "supabase/migrations/20260829000100_authority.sql",
                "20260829000100",
                "digest-a",
                "create table public.accounts(id bigint); alter table public.accounts enable row level security; grant select, insert on table public.accounts to anon; revoke insert on table public.accounts from anon; create function private.current_account_id() returns uuid language sql security definer set search_path = '' as $$ select null::uuid $$; revoke all on function private.current_account_id() from public; grant execute on function private.current_account_id() to authenticated;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let relation_id = SupabaseObjectId {
            schema: "public".to_owned(),
            name: "accounts".to_owned(),
            kind: SupabaseObjectKind::Table,
        };
        let relation = state.relations.get(&relation_id).unwrap();
        assert_eq!(relation.rls_state.value, RlsState::Enabled);
        assert!(relation.grants.contains_key(&GrantKey {
            role: "anon".to_owned(),
            privilege: "SELECT".to_owned(),
        }));
        assert!(!relation.grants.contains_key(&GrantKey {
            role: "anon".to_owned(),
            privilege: "INSERT".to_owned(),
        }));

        let function_id = SupabaseObjectId {
            schema: "private".to_owned(),
            name: "current_account_id".to_owned(),
            kind: SupabaseObjectKind::Function,
        };
        let function = state.functions.get(&function_id).unwrap();
        assert_eq!(function.security_mode.value, FunctionSecurityState::Definer);
        assert_eq!(
            function.search_path.value,
            FunctionSearchPathState::PinnedEmpty
        );
        assert_eq!(
            function.execute_grants.keys().cloned().collect::<Vec<_>>(),
            vec!["authenticated".to_owned()]
        );
    }

    #[test]
    fn missing_supported_property_information_stays_unknown() {
        let state = reduce_repository_posture(
            &[migration(
                "supabase/migrations/20260829000100_unknown.sql",
                "20260829000100",
                "digest-a",
                "create table public.accounts(id bigint); create function private.helper() returns void language sql as $$ select 1 $$;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let relation_id = SupabaseObjectId {
            schema: "public".to_owned(),
            name: "accounts".to_owned(),
            kind: SupabaseObjectKind::Table,
        };
        assert_eq!(
            state.relations.get(&relation_id).unwrap().rls_state.value,
            RlsState::Unknown
        );
        let function_id = SupabaseObjectId {
            schema: "private".to_owned(),
            name: "helper".to_owned(),
            kind: SupabaseObjectKind::Function,
        };
        let function = state.functions.get(&function_id).unwrap();
        assert_eq!(function.security_mode.value, FunctionSecurityState::Unknown);
        assert_eq!(function.search_path.value, FunctionSearchPathState::Unknown);
    }

    #[test]
    fn unsupported_or_malformed_sql_degrades_coverage_without_inventing_state() {
        let state = reduce_repository_posture(
            &[migration(
                "supabase/migrations/20260829000100_hostile.sql",
                "20260829000100",
                "digest-a",
                "do $$ begin execute 'alter table public.accounts disable row level security'; end $$; create policy broken on public.accounts using ('unterminated",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        assert_eq!(state.coverage_state, PostureCoverageState::Partial);
        assert!(!state.coverage_gaps.is_empty());
        assert!(state.relations.is_empty());
        assert!(state.policies.is_empty());
        assert!(state.functions.is_empty());
    }

    #[test]
    fn bounded_scan_rejection_is_partial_coverage_not_clean_posture() {
        let limits = SqlScanLimits {
            max_bytes: 16,
            ..SqlScanLimits::default()
        };
        let state = reduce_repository_posture(
            &[migration(
                "supabase/migrations/20260829000100_large.sql",
                "20260829000100",
                "digest-a",
                "create table public.accounts(id bigint);",
            )],
            limits,
        )
        .unwrap();

        assert_eq!(state.coverage_state, PostureCoverageState::Partial);
        assert_eq!(state.coverage_gaps.len(), 1);
        assert_eq!(
            state.coverage_gaps[0].kind,
            PostureCoverageGapKind::BoundedScanRejection
        );
        assert!(state.relations.is_empty());
    }

    #[test]
    fn ambiguous_replay_order_fails_closed() {
        let result = reduce_repository_posture(
            &[
                migration(
                    "supabase/migrations/20260829000100_a.sql",
                    "20260829000100",
                    "digest-a",
                    "select 1;",
                ),
                migration(
                    "supabase/migrations/20260829000100_b.sql",
                    "20260829000100",
                    "digest-b",
                    "select 2;",
                ),
            ],
            SqlScanLimits::default(),
        );
        assert!(matches!(
            result,
            Err(PostureReductionError::AmbiguousOrderKey { ref order_key, .. })
                if order_key == "20260829000100"
        ));
    }

    #[test]
    fn unqualified_security_object_identity_degrades_coverage() {
        let state = reduce_repository_posture(
            &[migration(
                "supabase/migrations/20260829000100_unqualified.sql",
                "20260829000100",
                "digest-a",
                "create table accounts(id bigint);",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();
        assert_eq!(state.coverage_state, PostureCoverageState::Partial);
        assert_eq!(
            state.coverage_gaps[0].kind,
            PostureCoverageGapKind::AmbiguousObjectIdentity
        );
        assert!(state.relations.is_empty());
    }
}
