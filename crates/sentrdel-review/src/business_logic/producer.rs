//! Canonical R3-T026 Evidence/Coverage mapping for bounded business-logic analysis.
//!
//! This module is a runtime-owned producer boundary. It maps already-bounded R3
//! invariant evaluations and business-logic coverage into canonical R1 Evidence
//! and Coverage records. It never creates Findings, executes target code, accesses
//! providers, performs network I/O, or grants repository-controlled authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::canonical::{CanonicalError, content_id};
use sentrdel_schema::coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension};
use sentrdel_schema::evidence::{
    ConfidenceBand, EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation,
    EvidenceSubject, EvidenceValidationError, ProducerKind,
};
use serde_json::{Value, json};

use super::coverage::{
    BusinessLogicCoverageAggregationError, aggregate_business_logic_coverage,
};
use super::model::{
    BusinessLogicCoverage, BusinessLogicCoverageArea, InvariantEvaluation, InvariantEvaluationState,
    SourceLocation,
};
use super::{COVERAGE_BUSINESS_LOGIC, COVERAGE_CROSS_LAYER_BUSINESS_LOGIC};

pub const R3_BUSINESS_LOGIC_PRODUCER_ID: &str = "sentrdel.r3.business-logic";
pub const R3_BUSINESS_LOGIC_PRODUCER_VERSION: &str = "1";
pub const R3_BUSINESS_LOGIC_CREATES_FINDINGS: bool = false;
pub const R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE: bool = false;
pub const R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS: bool = false;
pub const R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY: bool = false;

const OBSERVATION_CATEGORY: &str = "business_logic_invariant_observation";
const INTERPRETATION_CATEGORY: &str = "business_logic_invariant_interpretation";

#[derive(Clone, Debug, PartialEq)]
pub struct BusinessLogicProducerOutput {
    evidence: Vec<Evidence>,
    coverage: Vec<CoverageRecord>,
}

impl BusinessLogicProducerOutput {
    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    #[must_use]
    pub fn coverage(&self) -> &[CoverageRecord] {
        &self.coverage
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<Evidence>, Vec<CoverageRecord>) {
        (self.evidence, self.coverage)
    }
}

#[derive(Debug)]
pub enum BusinessLogicProducerError {
    EmptyObservedAt,
    DuplicateEvaluationId(String),
    UnexpectedCoverageProducer(String),
    DuplicateEvidenceId(String),
    DuplicateCoverageId(String),
    Evidence(EvidenceValidationError),
    CoverageAggregation(BusinessLogicCoverageAggregationError),
    Canonical(CanonicalError),
}

impl fmt::Display for BusinessLogicProducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyObservedAt => formatter.write_str("R3 producer observed_at must not be empty"),
            Self::DuplicateEvaluationId(value) => {
                write!(formatter, "duplicate R3 invariant evaluation id {value:?}")
            }
            Self::UnexpectedCoverageProducer(value) => write!(
                formatter,
                "R3 producer rejected unexpected internal coverage producer {value:?}"
            ),
            Self::DuplicateEvidenceId(value) => {
                write!(formatter, "duplicate R3 Evidence id {value:?}")
            }
            Self::DuplicateCoverageId(value) => {
                write!(formatter, "duplicate R3 Coverage id {value:?}")
            }
            Self::Evidence(error) => write!(formatter, "invalid R3 Evidence: {error}"),
            Self::CoverageAggregation(error) => {
                write!(formatter, "invalid R3 business-logic coverage matrix: {error}")
            }
            Self::Canonical(error) => write!(formatter, "R3 canonical identity failed: {error}"),
        }
    }
}

impl Error for BusinessLogicProducerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Evidence(error) => Some(error),
            Self::CoverageAggregation(error) => Some(error),
            Self::Canonical(error) => Some(error),
            _ => None,
        }
    }
}

impl From<EvidenceValidationError> for BusinessLogicProducerError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

impl From<BusinessLogicCoverageAggregationError> for BusinessLogicProducerError {
    fn from(value: BusinessLogicCoverageAggregationError) -> Self {
        Self::CoverageAggregation(value)
    }
}

impl From<CanonicalError> for BusinessLogicProducerError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

/// Map bounded invariant evaluations and the complete frozen R3 coverage matrix
/// to canonical Evidence/Coverage without consulting or creating Findings.
///
/// `observed_at` is runtime metadata supplied by the caller. Equivalent semantic
/// inputs with the same timestamp produce deterministic identities and ordering.
pub fn produce_business_logic_outputs(
    evaluations: &[InvariantEvaluation],
    coverage: &[BusinessLogicCoverage],
    observed_at: &str,
) -> Result<BusinessLogicProducerOutput, BusinessLogicProducerError> {
    if observed_at.trim().is_empty() {
        return Err(BusinessLogicProducerError::EmptyObservedAt);
    }

    let authority = EvidenceAuthority::from_runtime(
        R3_BUSINESS_LOGIC_PRODUCER_ID,
        R3_BUSINESS_LOGIC_PRODUCER_VERSION,
        ProducerKind::NativeRule,
    )?;

    let mut ordered_evaluations: Vec<&InvariantEvaluation> = evaluations.iter().collect();
    ordered_evaluations.sort_by(|left, right| {
        left.evaluation_id()
            .as_str()
            .cmp(right.evaluation_id().as_str())
    });

    let mut seen_evaluations = BTreeSet::new();
    let mut evidence = Vec::with_capacity(ordered_evaluations.len().saturating_mul(2));
    for evaluation in ordered_evaluations {
        if !seen_evaluations.insert(evaluation.evaluation_id().as_str().to_owned()) {
            return Err(BusinessLogicProducerError::DuplicateEvaluationId(
                evaluation.evaluation_id().as_str().to_owned(),
            ));
        }
        evidence.push(authority.seal(observation_claim(evaluation, observed_at))?);
        evidence.push(authority.seal(interpretation_claim(evaluation, observed_at))?);
    }
    evidence.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
    reject_duplicate_evidence(&evidence)?;

    for entry in coverage {
        if !entry.producer().starts_with("sentrdel.r3.") {
            return Err(BusinessLogicProducerError::UnexpectedCoverageProducer(
                entry.producer().to_owned(),
            ));
        }
    }
    let aggregate = aggregate_business_logic_coverage(coverage)?;
    let mut coverage_records = Vec::with_capacity(aggregate.areas().len().saturating_add(2));
    for entry in aggregate.areas() {
        coverage_records.push(area_coverage_record(entry, observed_at)?);
    }
    coverage_records.push(aggregate_coverage_record(
        COVERAGE_CROSS_LAYER_BUSINESS_LOGIC,
        &aggregate,
        observed_at,
    )?);
    coverage_records.push(aggregate_coverage_record(
        COVERAGE_BUSINESS_LOGIC,
        &aggregate,
        observed_at,
    )?);
    coverage_records.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
    reject_duplicate_coverage(&coverage_records)?;

    Ok(BusinessLogicProducerOutput {
        evidence,
        coverage: coverage_records,
    })
}

fn observation_claim(evaluation: &InvariantEvaluation, observed_at: &str) -> EvidenceClaim {
    let path = evaluation
        .path_id()
        .map_or("no correlated path", |value| value.as_str());
    let observation = format!(
        "R3 bounded invariant evaluation {} references {} supporting and {} contradicting observations on {}.",
        evaluation.evaluation_id().as_str(),
        evaluation.supporting_observation_ids().len(),
        evaluation.contradicting_observation_ids().len(),
        path,
    );

    let mut attributes = common_attributes(evaluation);
    attributes.insert(
        "observation_role".to_owned(),
        Value::String("direct_bounded_metadata".to_owned()),
    );

    EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: input_digests(evaluation.provenance()),
        observation,
        security_interpretation: None,
        category: OBSERVATION_CATEGORY.to_owned(),
        epistemic_class: EpistemicClass::Fact,
        confidence_band: Some(ConfidenceBand::High),
        subjects: subjects(evaluation),
        locations: evidence_locations(evaluation),
        attributes,
        reproduction: None,
        captured_at: observed_at.to_owned(),
    }
}

fn interpretation_claim(evaluation: &InvariantEvaluation, observed_at: &str) -> EvidenceClaim {
    let path = evaluation
        .path_id()
        .map_or("no correlated path", |value| value.as_str());
    let observation = format!(
        "R3 evaluated invariant {} against {} within the bounded static business-logic model.",
        evaluation.invariant_id().as_str(),
        path,
    );

    let mut attributes = common_attributes(evaluation);
    attributes.insert(
        "evaluation_state".to_owned(),
        Value::String(evaluation_state_name(evaluation.state()).to_owned()),
    );
    attributes.insert(
        "coverage_reasons".to_owned(),
        Value::Array(
            evaluation
                .coverage_reasons()
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );

    EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: input_digests(evaluation.provenance()),
        observation,
        security_interpretation: Some(interpretation_text(evaluation)),
        category: INTERPRETATION_CATEGORY.to_owned(),
        epistemic_class: EpistemicClass::Inference,
        confidence_band: Some(match evaluation.state() {
            InvariantEvaluationState::Unknown => ConfidenceBand::Low,
            InvariantEvaluationState::NotApplicable => ConfidenceBand::Medium,
            InvariantEvaluationState::Satisfied | InvariantEvaluationState::Violated => {
                ConfidenceBand::High
            }
        }),
        subjects: subjects(evaluation),
        locations: evidence_locations(evaluation),
        attributes,
        reproduction: None,
        captured_at: observed_at.to_owned(),
    }
}

fn interpretation_text(evaluation: &InvariantEvaluation) -> String {
    let reasons = if evaluation.coverage_reasons().is_empty() {
        String::new()
    } else {
        format!(
            " Coverage limitations: {}.",
            evaluation.coverage_reasons().join("; ")
        )
    };
    match evaluation.state() {
        InvariantEvaluationState::Satisfied => format!(
            "The invariant is SATISFIED within the declared bounded static scope.{reasons} This is not proof of runtime safety, hosted state, or absence of exploitability."
        ),
        InvariantEvaluationState::Violated => format!(
            "The invariant is VIOLATED within the declared bounded static scope.{reasons} This static interpretation does not claim runtime exploitability, actual cross-tenant access, or hosted state."
        ),
        InvariantEvaluationState::Unknown => format!(
            "The invariant is UNKNOWN within the declared bounded static scope.{reasons} UNKNOWN is not a clean or satisfied result and makes no runtime or hosted-state claim."
        ),
        InvariantEvaluationState::NotApplicable => format!(
            "The invariant is NOT_APPLICABLE to this bounded static scope.{reasons} This does not make a runtime, hosted-state, or exploitability claim."
        ),
    }
}

fn common_attributes(evaluation: &InvariantEvaluation) -> BTreeMap<String, Value> {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "evaluation_id".to_owned(),
        Value::String(evaluation.evaluation_id().as_str().to_owned()),
    );
    attributes.insert(
        "invariant_id".to_owned(),
        Value::String(evaluation.invariant_id().as_str().to_owned()),
    );
    if let Some(path_id) = evaluation.path_id() {
        attributes.insert(
            "path_id".to_owned(),
            Value::String(path_id.as_str().to_owned()),
        );
    }
    attributes.insert(
        "supporting_observation_ids".to_owned(),
        Value::Array(
            evaluation
                .supporting_observation_ids()
                .iter()
                .map(|value| Value::String(value.as_str().to_owned()))
                .collect(),
        ),
    );
    attributes.insert(
        "contradicting_observation_ids".to_owned(),
        Value::Array(
            evaluation
                .contradicting_observation_ids()
                .iter()
                .map(|value| Value::String(value.as_str().to_owned()))
                .collect(),
        ),
    );
    attributes.insert(
        "provenance_byte_ranges".to_owned(),
        Value::Array(
            evaluation
                .provenance()
                .iter()
                .map(|location| {
                    json!({
                        "path": location.path().as_str(),
                        "start_byte": location.start_byte(),
                        "end_byte": location.end_byte(),
                        "content_digest": location.content_digest(),
                    })
                })
                .collect(),
        ),
    );
    attributes
}

fn subjects(evaluation: &InvariantEvaluation) -> Vec<EvidenceSubject> {
    let mut subjects = vec![
        EvidenceSubject {
            kind: "invariant_evaluation".to_owned(),
            id: evaluation.evaluation_id().as_str().to_owned(),
        },
        EvidenceSubject {
            kind: "invariant".to_owned(),
            id: evaluation.invariant_id().as_str().to_owned(),
        },
    ];
    if let Some(path_id) = evaluation.path_id() {
        subjects.push(EvidenceSubject {
            kind: "cross_layer_path".to_owned(),
            id: path_id.as_str().to_owned(),
        });
    }
    subjects
}

fn evidence_locations(evaluation: &InvariantEvaluation) -> Vec<EvidenceLocation> {
    evaluation
        .provenance()
        .iter()
        .map(|location| EvidenceLocation {
            repo_relative_path: location.path().as_str().to_owned(),
            start_line: None,
            start_column: None,
            end_line: None,
            end_column: None,
            symbol: Some(format!(
                "invariant-evaluation:{}",
                evaluation.evaluation_id().as_str()
            )),
            content_digest: Some(location.content_digest().to_owned()),
        })
        .collect()
}

fn input_digests(provenance: &[SourceLocation]) -> Vec<String> {
    let mut digests: Vec<String> = provenance
        .iter()
        .map(|location| location.content_digest().to_owned())
        .collect();
    digests.sort();
    digests.dedup();
    digests
}

fn area_coverage_record(
    entry: &BusinessLogicCoverage,
    observed_at: &str,
) -> Result<CoverageRecord, BusinessLogicProducerError> {
    let capability = format!(
        "{COVERAGE_CROSS_LAYER_BUSINESS_LOGIC}:{}",
        coverage_area_name(entry.area())
    );
    let coverage_id = coverage_id(
        &capability,
        entry.scope(),
        entry.state(),
        entry.reason_code(),
        entry.input_digests(),
    )?;
    Ok(CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id,
        capability,
        scope: entry.scope().to_owned(),
        producer: Some(R3_BUSINESS_LOGIC_PRODUCER_ID.to_owned()),
        provider_dimension: Some(ProviderCoverageDimension::CrossLayerBusinessLogic),
        state: entry.state().clone(),
        reason_code: Some(entry.reason_code().to_owned()),
        details: Some(format!(
            "R3 bounded static business-logic coverage area {}; source producer {}. No runtime or hosted-state claim.",
            coverage_area_name(entry.area()),
            entry.producer(),
        )),
        input_digests: entry.input_digests().to_vec(),
        observed_at: observed_at.to_owned(),
    })
}

fn aggregate_coverage_record(
    capability: &str,
    aggregate: &super::coverage::BusinessLogicCoverageAggregate,
    observed_at: &str,
) -> Result<CoverageRecord, BusinessLogicProducerError> {
    let mut input_digests = Vec::new();
    let mut scopes = BTreeSet::new();
    for entry in aggregate.areas() {
        input_digests.extend(entry.input_digests().iter().cloned());
        scopes.insert(entry.scope().to_owned());
    }
    input_digests.sort();
    input_digests.dedup();
    let scope = if scopes.len() == 1 {
        scopes.into_iter().next().unwrap_or_else(|| ".".to_owned())
    } else {
        ".".to_owned()
    };
    let reason_code = if aggregate.is_complete() {
        "R3_BUSINESS_LOGIC_COVERED"
    } else {
        "R3_BUSINESS_LOGIC_GAPS_VISIBLE"
    };
    let details = if aggregate.is_complete() {
        "All ten required R3 bounded static business-logic coverage areas are covered. This does not claim runtime or hosted-state coverage."
            .to_owned()
    } else {
        let gaps = aggregate
            .gap_areas()
            .into_iter()
            .map(coverage_area_name)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "R3 bounded static business-logic coverage remains non-clean because required gap areas are visible: {gaps}."
        )
    };
    let coverage_id = coverage_id(
        capability,
        &scope,
        aggregate.state(),
        reason_code,
        &input_digests,
    )?;
    Ok(CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id,
        capability: capability.to_owned(),
        scope,
        producer: Some(R3_BUSINESS_LOGIC_PRODUCER_ID.to_owned()),
        provider_dimension: Some(ProviderCoverageDimension::CrossLayerBusinessLogic),
        state: aggregate.state().clone(),
        reason_code: Some(reason_code.to_owned()),
        details: Some(details),
        input_digests,
        observed_at: observed_at.to_owned(),
    })
}

fn coverage_id(
    capability: &str,
    scope: &str,
    state: &CoverageState,
    reason_code: &str,
    input_digests: &[String],
) -> Result<String, CanonicalError> {
    content_id(
        "coverage",
        &(
            R3_BUSINESS_LOGIC_PRODUCER_ID,
            capability,
            scope,
            state,
            reason_code,
            input_digests,
        ),
    )
}

fn coverage_area_name(area: BusinessLogicCoverageArea) -> &'static str {
    match area {
        BusinessLogicCoverageArea::Routes => "ROUTES",
        BusinessLogicCoverageArea::ActorIdentity => "ACTOR_IDENTITY",
        BusinessLogicCoverageArea::Guards => "GUARDS",
        BusinessLogicCoverageArea::ValueOrigins => "VALUE_ORIGINS",
        BusinessLogicCoverageArea::DataOperations => "DATA_OPERATIONS",
        BusinessLogicCoverageArea::LocalLinking => "LOCAL_LINKING",
        BusinessLogicCoverageArea::SemanticLinking => "SEMANTIC_LINKING",
        BusinessLogicCoverageArea::R2ProviderCorrelation => "R2_PROVIDER_CORRELATION",
        BusinessLogicCoverageArea::ProjectInvariants => "PROJECT_INVARIANTS",
        BusinessLogicCoverageArea::InvariantEvaluation => "INVARIANT_EVALUATION",
    }
}

fn evaluation_state_name(state: InvariantEvaluationState) -> &'static str {
    match state {
        InvariantEvaluationState::Satisfied => "SATISFIED",
        InvariantEvaluationState::Violated => "VIOLATED",
        InvariantEvaluationState::Unknown => "UNKNOWN",
        InvariantEvaluationState::NotApplicable => "NOT_APPLICABLE",
    }
}

fn reject_duplicate_evidence(evidence: &[Evidence]) -> Result<(), BusinessLogicProducerError> {
    let mut ids = BTreeSet::new();
    for item in evidence {
        if !ids.insert(item.evidence_id().to_owned()) {
            return Err(BusinessLogicProducerError::DuplicateEvidenceId(
                item.evidence_id().to_owned(),
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_coverage(
    coverage: &[CoverageRecord],
) -> Result<(), BusinessLogicProducerError> {
    let mut ids = BTreeSet::new();
    for item in coverage {
        if !ids.insert(item.coverage_id.clone()) {
            return Err(BusinessLogicProducerError::DuplicateCoverageId(
                item.coverage_id.clone(),
            ));
        }
    }
    Ok(())
}
