//! Repository-derived Supabase function authority posture Evidence.
//!
//! This producer consumes only the bounded migration state plus repository-derived
//! API schema exposure. It emits independent FACT observations for supported
//! function security mode, search_path posture, schema exposure, and explicit
//! EXECUTE grants. It never labels SECURITY DEFINER alone exploitable, never
//! claims hosted/live state, and never creates Findings.

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
    ExposureState, FunctionPosture, FunctionSearchPathState, FunctionSecurityState,
    PostureCoverageState, RepositoryPostureState, StatementProvenance, SupabaseObjectKind,
};

pub const DEFAULT_MAX_FUNCTION_AUTHORITY_EVIDENCE: usize = 16_384;
const PRODUCER_ID: &str = "sentrdel.supabase.function-authority";
const PRODUCER_VERSION: &str = "1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FunctionAuthorityLimits {
    pub max_evidence: usize,
}

impl Default for FunctionAuthorityLimits {
    fn default() -> Self {
        Self {
            max_evidence: DEFAULT_MAX_FUNCTION_AUTHORITY_EVIDENCE,
        }
    }
}

#[derive(Debug)]
pub enum FunctionAuthorityError {
    InvalidLimits,
    EmptyCapturedAt,
    TooManyEvidence { max: usize },
    Evidence(EvidenceValidationError),
}

impl fmt::Display for FunctionAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("function authority limits must be non-zero"),
            Self::EmptyCapturedAt => formatter.write_str("captured_at must not be empty"),
            Self::TooManyEvidence { max } => {
                write!(formatter, "function authority evidence exceeds bounded cap {max}")
            }
            Self::Evidence(error) => {
                write!(formatter, "cannot seal function authority evidence: {error}")
            }
        }
    }
}

impl Error for FunctionAuthorityError {}

impl From<EvidenceValidationError> for FunctionAuthorityError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

pub fn observe_function_authority(
    state: &RepositoryPostureState,
    exposure: &ApiSchemaExposureSnapshot,
    captured_at: &str,
    limits: FunctionAuthorityLimits,
) -> Result<Vec<Evidence>, FunctionAuthorityError> {
    if limits.max_evidence == 0 {
        return Err(FunctionAuthorityError::InvalidLimits);
    }
    if captured_at.trim().is_empty() {
        return Err(FunctionAuthorityError::EmptyCapturedAt);
    }

    let authority =
        EvidenceAuthority::from_runtime(PRODUCER_ID, PRODUCER_VERSION, ProducerKind::NativeRule)?;
    let mut evidence = Vec::new();

    for function in state.functions.values() {
        if function.object.kind != SupabaseObjectKind::Function {
            continue;
        }

        if let Some(provenance) = function.security_mode.provenance.as_ref() {
            push_bounded(
                &mut evidence,
                limits,
                seal_security_mode(&authority, state, function, provenance, captured_at)?,
            )?;
        }

        if let Some(provenance) = function.search_path.provenance.as_ref() {
            push_bounded(
                &mut evidence,
                limits,
                seal_search_path(&authority, state, function, provenance, captured_at)?,
            )?;
        }

        if let (Some(function_provenance), Some(exposure_provenance)) =
            (identity_provenance(function), exposure.provenance())
        {
            push_bounded(
                &mut evidence,
                limits,
                seal_schema_exposure(
                    &authority,
                    state,
                    function,
                    exposure.repository_schema_exposure(&function.object.schema),
                    function_provenance,
                    exposure_provenance,
                    captured_at,
                )?,
            )?;
        }

        for (role, provenance) in &function.execute_grants {
            push_bounded(
                &mut evidence,
                limits,
                seal_execute_grant(
                    &authority,
                    state,
                    function,
                    role,
                    provenance,
                    captured_at,
                )?,
            )?;
        }
    }

    Ok(evidence)
}

fn push_bounded(
    evidence: &mut Vec<Evidence>,
    limits: FunctionAuthorityLimits,
    item: Evidence,
) -> Result<(), FunctionAuthorityError> {
    if evidence.len() >= limits.max_evidence {
        return Err(FunctionAuthorityError::TooManyEvidence {
            max: limits.max_evidence,
        });
    }
    evidence.push(item);
    Ok(())
}

fn seal_security_mode(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    function: &FunctionPosture,
    provenance: &StatementProvenance,
    captured_at: &str,
) -> Result<Evidence, FunctionAuthorityError> {
    let function_id = function.object.normalized();
    let mode = security_mode_name(function.security_mode.value);
    let mut attributes = common_attributes(state, &function_id);
    attributes.insert("security_mode".to_owned(), Value::String(mode.to_owned()));

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![provenance.content_digest.clone()],
        observation: format!(
            "Repository-derived migration state records function {function_id} with security mode {mode}"
        ),
        security_interpretation: None,
        category: "supabase_function_security_mode".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: function_subjects(function_id),
        locations: vec![statement_location(provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn seal_search_path(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    function: &FunctionPosture,
    provenance: &StatementProvenance,
    captured_at: &str,
) -> Result<Evidence, FunctionAuthorityError> {
    let function_id = function.object.normalized();
    let mut attributes = common_attributes(state, &function_id);
    attributes.insert(
        "search_path_posture".to_owned(),
        Value::String(search_path_name(&function.search_path.value).to_owned()),
    );
    if let FunctionSearchPathState::PinnedExplicit(values) = &function.search_path.value {
        attributes.insert(
            "search_path_values".to_owned(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
    }

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![provenance.content_digest.clone()],
        observation: format!(
            "Repository-derived migration state records function {function_id} with search_path posture {}",
            search_path_name(&function.search_path.value)
        ),
        security_interpretation: None,
        category: "supabase_function_search_path".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: function_subjects(function_id),
        locations: vec![statement_location(provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

#[allow(clippy::too_many_arguments)]
fn seal_schema_exposure(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    function: &FunctionPosture,
    exposure_state: ExposureState,
    function_provenance: &StatementProvenance,
    exposure_provenance: &ConfigExposureProvenance,
    captured_at: &str,
) -> Result<Evidence, FunctionAuthorityError> {
    let function_id = function.object.normalized();
    let exposure_name = exposure_name(exposure_state);
    let mut attributes = common_attributes(state, &function_id);
    attributes.insert(
        "schema".to_owned(),
        Value::String(function.object.schema.clone()),
    );
    attributes.insert(
        "schema_exposure".to_owned(),
        Value::String(exposure_name.to_owned()),
    );

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: input_digests(function_provenance, exposure_provenance),
        observation: format!(
            "Repository-derived schema exposure classifies function {function_id} as {exposure_name}"
        ),
        security_interpretation: None,
        category: "supabase_function_schema_exposure".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: function_subjects(function_id),
        locations: vec![
            statement_location(function_provenance),
            config_location(exposure_provenance),
        ],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn seal_execute_grant(
    authority: &EvidenceAuthority,
    state: &RepositoryPostureState,
    function: &FunctionPosture,
    role: &str,
    provenance: &StatementProvenance,
    captured_at: &str,
) -> Result<Evidence, FunctionAuthorityError> {
    let function_id = function.object.normalized();
    let mut attributes = common_attributes(state, &function_id);
    attributes.insert("role".to_owned(), Value::String(role.to_owned()));
    attributes.insert("privilege".to_owned(), Value::String("EXECUTE".to_owned()));

    Ok(authority.seal(EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: vec![provenance.content_digest.clone()],
        observation: format!(
            "Repository-derived migration state grants EXECUTE on function {function_id} to role {role}"
        ),
        security_interpretation: None,
        category: "supabase_function_execute_grant".to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: None,
        subjects: vec![
            EvidenceSubject {
                kind: "supabase_function".to_owned(),
                id: function_id,
            },
            EvidenceSubject {
                kind: "supabase_role".to_owned(),
                id: role.to_owned(),
            },
        ],
        locations: vec![statement_location(provenance)],
        attributes,
        reproduction: None,
        captured_at: captured_at.to_owned(),
    })?)
}

fn identity_provenance(function: &FunctionPosture) -> Option<&StatementProvenance> {
    function
        .exists_in_supported_history
        .provenance
        .as_ref()
        .or(function.security_mode.provenance.as_ref())
        .or(function.search_path.provenance.as_ref())
        .or_else(|| function.execute_grants.values().next())
}

fn common_attributes(
    state: &RepositoryPostureState,
    function: &str,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("function".to_owned(), Value::String(function.to_owned())),
        ("repository_derived".to_owned(), Value::Bool(true)),
        (
            "repository_posture_coverage".to_owned(),
            Value::String(coverage_name(state.coverage_state).to_owned()),
        ),
        (
            "hosted_function_state".to_owned(),
            Value::String("UNKNOWN".to_owned()),
        ),
        (
            "live_posture".to_owned(),
            Value::String("NOT_EXECUTED".to_owned()),
        ),
        (
            "finding_authority".to_owned(),
            Value::String("RECONCILER_ONLY".to_owned()),
        ),
    ])
}

fn function_subjects(function: String) -> Vec<EvidenceSubject> {
    vec![EvidenceSubject {
        kind: "supabase_function".to_owned(),
        id: function,
    }]
}

fn security_mode_name(state: FunctionSecurityState) -> &'static str {
    match state {
        FunctionSecurityState::Invoker => "INVOKER",
        FunctionSecurityState::Definer => "DEFINER",
        FunctionSecurityState::Unknown => "UNKNOWN",
    }
}

fn search_path_name(state: &FunctionSearchPathState) -> &'static str {
    match state {
        FunctionSearchPathState::PinnedEmpty => "PINNED_EMPTY",
        FunctionSearchPathState::PinnedExplicit(_) => "PINNED_EXPLICIT",
        FunctionSearchPathState::UnpinnedOrMutable => "UNPINNED_OR_MUTABLE",
        FunctionSearchPathState::Unknown => "UNKNOWN",
    }
}

fn exposure_name(state: ExposureState) -> &'static str {
    match state {
        ExposureState::ApiRelevant => "API_RELEVANT",
        ExposureState::NotProvenApiRelevant => "NOT_PROVEN_API_RELEVANT",
        ExposureState::Unknown => "UNKNOWN",
    }
}

fn coverage_name(state: PostureCoverageState) -> &'static str {
    match state {
        PostureCoverageState::Complete => "COMPLETE",
        PostureCoverageState::Partial => "PARTIAL",
    }
}

fn input_digests(
    function: &StatementProvenance,
    exposure: &ConfigExposureProvenance,
) -> Vec<String> {
    BTreeSet::from([
        function.content_digest.clone(),
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

    fn migration(sql: &str) -> MigrationSqlInput {
        MigrationSqlInput {
            path: NormalizedRepoPath::parse(
                "supabase/migrations/20260829000100_function.sql",
                4096,
            )
            .unwrap(),
            order_key: "20260829000100".to_owned(),
            content_digest: "sha256:function".to_owned(),
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
        observe_api_schema_exposure(&input, "2026-08-31T20:00:00Z")
            .unwrap()
            .0
    }

    #[test]
    fn emits_independent_function_authority_facts_without_exploitability_claims() {
        let state = reduce_repository_posture(
            &[migration(
                "create function public.lookup() returns void language sql security definer set search_path = '' as $$ select 1 $$; grant execute on function public.lookup() to anon;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let evidence = observe_function_authority(
            &state,
            &exposure(&["public"]),
            "2026-08-31T20:00:00Z",
            FunctionAuthorityLimits::default(),
        )
        .unwrap();
        let records: Vec<_> = evidence.iter().map(Evidence::to_record).collect();

        assert_eq!(records.len(), 4);
        assert!(
            records
                .iter()
                .all(|record| record.claim.security_interpretation.is_none())
        );
        let categories: BTreeSet<_> = records
            .iter()
            .map(|record| record.claim.category.as_str())
            .collect();
        assert_eq!(
            categories,
            BTreeSet::from([
                "supabase_function_execute_grant",
                "supabase_function_schema_exposure",
                "supabase_function_search_path",
                "supabase_function_security_mode",
            ])
        );
        assert!(records.iter().any(|record| {
            record.claim.category == "supabase_function_security_mode"
                && record.claim.attributes.get("security_mode")
                    == Some(&Value::String("DEFINER".to_owned()))
        }));
        assert!(records.iter().any(|record| {
            record.claim.category == "supabase_function_search_path"
                && record.claim.attributes.get("search_path_posture")
                    == Some(&Value::String("PINNED_EMPTY".to_owned()))
        }));
        assert!(records.iter().any(|record| {
            record.claim.category == "supabase_function_schema_exposure"
                && record.claim.attributes.get("schema_exposure")
                    == Some(&Value::String("API_RELEVANT".to_owned()))
        }));
    }

    #[test]
    fn reset_search_path_is_observed_as_mutable_without_direct_vulnerability_label() {
        let state = reduce_repository_posture(
            &[migration(
                "create function private.helper() returns void language sql security definer set search_path = '' as $$ select 1 $$; alter function private.helper() reset all;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let evidence = observe_function_authority(
            &state,
            &exposure(&["public"]),
            "2026-08-31T20:00:00Z",
            FunctionAuthorityLimits::default(),
        )
        .unwrap();
        let record = evidence
            .iter()
            .map(Evidence::to_record)
            .find(|record| record.claim.category == "supabase_function_search_path")
            .unwrap();

        assert_eq!(
            record.claim.attributes.get("search_path_posture"),
            Some(&Value::String("UNPINNED_OR_MUTABLE".to_owned()))
        );
        assert!(record.claim.security_interpretation.is_none());
    }

    #[test]
    fn later_revoke_removes_execute_grant_evidence() {
        let state = reduce_repository_posture(
            &[migration(
                "create function public.lookup() returns void language sql security invoker set search_path = '' as $$ select 1 $$; grant execute on function public.lookup() to anon; revoke execute on function public.lookup() from anon;",
            )],
            SqlScanLimits::default(),
        )
        .unwrap();

        let evidence = observe_function_authority(
            &state,
            &exposure(&["public"]),
            "2026-08-31T20:00:00Z",
            FunctionAuthorityLimits::default(),
        )
        .unwrap();

        assert!(
            evidence
                .iter()
                .map(Evidence::to_record)
                .all(|record| record.claim.category != "supabase_function_execute_grant")
        );
    }

    #[test]
    fn limits_and_capture_time_fail_closed() {
        let state = RepositoryPostureState::default();
        let exposure = exposure(&["public"]);

        assert!(matches!(
            observe_function_authority(
                &state,
                &exposure,
                "2026-08-31T20:00:00Z",
                FunctionAuthorityLimits { max_evidence: 0 },
            ),
            Err(FunctionAuthorityError::InvalidLimits)
        ));
        assert!(matches!(
            observe_function_authority(
                &state,
                &exposure,
                "   ",
                FunctionAuthorityLimits::default(),
            ),
            Err(FunctionAuthorityError::EmptyCapturedAt)
        ));
    }
}
