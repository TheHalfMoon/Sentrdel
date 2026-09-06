//! Bounded R3-T023 protected-property mutation invariant evaluation.
//!
//! The evaluator consumes only normalized R3 observations and a correlated path. It distinguishes
//! explicit mutation field sets from broad request-controlled, dynamic, and unknown field sets.
//! A clean result is never inferred from an unlinked allowlist or lexical property name. This
//! module never executes target code, accesses providers, creates Findings, or proves runtime field
//! safety or exploitability.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use super::model::{
    BusinessLogicLimits, ConfidenceBasis, CrossLayerPath, DataOperation, DataOperationKind,
    FieldSetMode, InvariantDefinition, InvariantEvaluation, InvariantEvaluationState,
    InvariantKind, InvariantRequirement, LinkBasis, ModelError, PathState, RouteObservation,
};

pub const R3_PROTECTED_PROPERTIES_CREATES_FINDINGS: bool = false;
pub const R3_PROTECTED_PROPERTIES_EXECUTES_TARGET_CODE: bool = false;
pub const R3_PROTECTED_PROPERTIES_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_PROTECTED_PROPERTIES_PROVES_RUNTIME_FIELD_SAFETY: bool = false;
pub const R3_PROTECTED_PROPERTIES_USES_UNLINKED_ALLOWLIST_AS_SAFETY_PROOF: bool = false;

pub struct ProtectedPropertiesInputs<'a> {
    pub invariant: &'a InvariantDefinition,
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub operation: &'a DataOperation,
}

#[derive(Debug)]
pub enum ProtectedPropertiesError {
    InvalidInvariantKind,
    PathRouteMismatch,
    PathOperationMismatch,
    Model(ModelError),
}

impl fmt::Display for ProtectedPropertiesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvariantKind => formatter.write_str(
                "protected-properties evaluator requires a protected-properties invariant",
            ),
            Self::PathRouteMismatch => {
                formatter.write_str("protected-properties path route does not match supplied route")
            }
            Self::PathOperationMismatch => formatter.write_str(
                "protected-properties path operation does not match supplied data operation",
            ),
            Self::Model(source) => write!(
                formatter,
                "protected-properties model validation failed: {source}"
            ),
        }
    }
}

impl Error for ProtectedPropertiesError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for ProtectedPropertiesError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn evaluate_protected_properties(
    inputs: ProtectedPropertiesInputs<'_>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, ProtectedPropertiesError> {
    let limits = limits.validate()?;
    if inputs.invariant.kind() != InvariantKind::ProtectedProperties {
        return Err(ProtectedPropertiesError::InvalidInvariantKind);
    }
    if inputs.path.route_id() != inputs.route.route_id() {
        return Err(ProtectedPropertiesError::PathRouteMismatch);
    }
    if inputs.path.data_operation_id() != inputs.operation.operation_id() {
        return Err(ProtectedPropertiesError::PathOperationMismatch);
    }

    let InvariantRequirement::ProtectedProperties {
        protected_properties,
        mutation_operations,
    } = inputs.invariant.requirements()
    else {
        return Err(ProtectedPropertiesError::InvalidInvariantKind);
    };

    if !scope_applies(
        inputs.invariant,
        inputs.path,
        inputs.route,
        inputs.operation,
    ) {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::NotApplicable,
            Vec::new(),
            Vec::new(),
            vec!["protected_properties_scope_not_applicable".to_owned()],
            limits,
        );
    }

    if !is_supported_property_mutation(inputs.operation.operation_kind())
        || !mutation_operations.contains(&inputs.operation.operation_kind())
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::NotApplicable,
            Vec::new(),
            Vec::new(),
            vec!["protected_properties_operation_not_applicable".to_owned()],
            limits,
        );
    }

    if inputs.path.path_state() != PathState::Supported
        || inputs.route.coverage_state() != &CoverageState::Covered
        || inputs.operation.coverage_state() != &CoverageState::Covered
        || path_has_non_authoritative_link(inputs.path)
    {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["protected_properties_path_or_operation_not_fully_supported".to_owned()],
            limits,
        );
    }

    let Some(field_set) = inputs.operation.mutation_fields() else {
        return evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["protected_properties_mutation_field_set_missing".to_owned()],
            limits,
        );
    };

    match field_set.mode() {
        FieldSetMode::Dynamic | FieldSetMode::Unknown => evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Unknown,
            Vec::new(),
            Vec::new(),
            vec!["protected_properties_mutation_field_set_unresolved".to_owned()],
            limits,
        ),
        FieldSetMode::BroadRequestObject => evaluation(
            inputs.invariant,
            inputs.path,
            InvariantEvaluationState::Violated,
            Vec::new(),
            vec![inputs.operation.operation_id().clone()],
            vec!["broad_request_controlled_mutation_may_reach_protected_properties".to_owned()],
            limits,
        ),
        FieldSetMode::Explicit => {
            let protected = protected_properties
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            let touches_protected = field_set
                .fields()
                .iter()
                .any(|field| protected.contains(field.as_str()));
            if touches_protected {
                evaluation(
                    inputs.invariant,
                    inputs.path,
                    InvariantEvaluationState::Violated,
                    Vec::new(),
                    vec![inputs.operation.operation_id().clone()],
                    vec!["explicit_mutation_includes_protected_properties".to_owned()],
                    limits,
                )
            } else {
                evaluation(
                    inputs.invariant,
                    inputs.path,
                    InvariantEvaluationState::Satisfied,
                    vec![inputs.operation.operation_id().clone()],
                    Vec::new(),
                    vec!["explicit_mutation_excludes_protected_properties".to_owned()],
                    limits,
                )
            }
        }
    }
}

fn path_has_non_authoritative_link(path: &CrossLayerPath) -> bool {
    path.links().iter().any(|link| {
        link.confidence_basis() != ConfidenceBasis::Extracted || link.basis() == LinkBasis::Unknown
    })
}

const fn is_supported_property_mutation(kind: DataOperationKind) -> bool {
    matches!(
        kind,
        DataOperationKind::Insert | DataOperationKind::Update | DataOperationKind::Upsert
    )
}

fn scope_applies(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    route: &RouteObservation,
    operation: &DataOperation,
) -> bool {
    let scope = invariant.scope();
    if scope
        .route_pattern()
        .is_some_and(|pattern| pattern != route.route_pattern())
    {
        return false;
    }
    if !scope.http_methods().is_empty() && !scope.http_methods().contains(&route.method()) {
        return false;
    }
    if scope
        .resource()
        .is_some_and(|resource| resource != operation.resource())
    {
        return false;
    }
    if !scope.operation_kinds().is_empty()
        && !scope
            .operation_kinds()
            .contains(&operation.operation_kind())
    {
        return false;
    }
    scope.target_paths().is_empty()
        || path
            .provenance()
            .iter()
            .any(|location| scope.target_paths().contains(location.path()))
}

fn evaluation(
    invariant: &InvariantDefinition,
    path: &CrossLayerPath,
    state: InvariantEvaluationState,
    supporting_observation_ids: Vec<super::model::StableSemanticId>,
    contradicting_observation_ids: Vec<super::model::StableSemanticId>,
    coverage_reasons: Vec<String>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, ProtectedPropertiesError> {
    let evaluation_id = super::model::StableSemanticId::from_parts(
        "r3-protected-properties-evaluation",
        &[invariant.invariant_id().as_str(), path.path_id().as_str()],
        limits,
    )?;
    let mut provenance = invariant.provenance().to_vec();
    provenance.extend(path.provenance().iter().cloned());
    provenance.sort();
    provenance.dedup();

    Ok(InvariantEvaluation::new(
        evaluation_id,
        invariant.invariant_id().clone(),
        Some(path.path_id().clone()),
        state,
        supporting_observation_ids,
        contradicting_observation_ids,
        coverage_reasons,
        provenance,
        limits,
    )?)
}
