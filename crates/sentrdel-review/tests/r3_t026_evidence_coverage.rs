use sentrdel_review::business_logic::coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS;
use sentrdel_review::business_logic::model::{
    BusinessLogicCoverage, BusinessLogicCoverageArea, BusinessLogicLimits, InvariantEvaluation,
    InvariantEvaluationState, SourceLocation, StableSemanticId,
};
use sentrdel_review::business_logic::producer::{
    BusinessLogicProducerError, R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY,
    R3_BUSINESS_LOGIC_CREATES_FINDINGS, R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE,
    R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS, R3_BUSINESS_LOGIC_PRODUCER_ID,
    R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS, produce_business_logic_outputs,
};
use sentrdel_review::business_logic::{
    COVERAGE_BUSINESS_LOGIC, COVERAGE_CROSS_LAYER_BUSINESS_LOGIC,
};
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::coverage::{CoverageState, ProviderCoverageDimension};
use sentrdel_schema::evidence::{EpistemicClass, ProducerKind};

const OBSERVED_AT: &str = "2026-09-06T19:00:00Z";

fn semantic(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default()).unwrap()
}

fn provenance(path: &str, digest: &str) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse(path, 4096).unwrap(),
        12,
        48,
        digest,
    )
    .unwrap()
}

fn evaluation(value: &str, state: InvariantEvaluationState) -> InvariantEvaluation {
    InvariantEvaluation::new(
        semantic("test.evaluation", value),
        semantic("test.invariant", value),
        Some(semantic("test.path", value)),
        state,
        vec![semantic("test.observation.supporting", value)],
        vec![semantic("test.observation.contradicting", value)],
        if state == InvariantEvaluationState::Unknown {
            vec!["semantic linking is partial".to_owned()]
        } else {
            Vec::new()
        },
        vec![provenance(
            "src/routes/accounts.ts",
            &format!("sha256:{value}"),
        )],
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn coverage_entry(area: BusinessLogicCoverageArea, state: CoverageState) -> BusinessLogicCoverage {
    BusinessLogicCoverage::new(
        area,
        state,
        "R3_T026_FIXTURE",
        ".",
        vec!["sha256:fixture-input".to_owned()],
        "sentrdel.r3.fixture",
        BusinessLogicLimits::default(),
    )
    .unwrap()
}

fn complete_coverage() -> Vec<BusinessLogicCoverage> {
    REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
        .into_iter()
        .map(|area| coverage_entry(area, CoverageState::Covered))
        .collect()
}

#[test]
fn direct_observation_and_security_interpretation_are_separate_canonical_evidence() {
    let output = produce_business_logic_outputs(
        &[evaluation("violated", InvariantEvaluationState::Violated)],
        &complete_coverage(),
        OBSERVED_AT,
    )
    .unwrap();

    assert_eq!(output.evidence().len(), 2);
    let direct = output
        .evidence()
        .iter()
        .find(|item| item.claim().epistemic_class == EpistemicClass::Fact)
        .expect("direct FACT Evidence");
    let interpretation = output
        .evidence()
        .iter()
        .find(|item| item.claim().epistemic_class == EpistemicClass::Inference)
        .expect("INFERENCE Evidence");

    assert_eq!(direct.producer().kind, ProducerKind::NativeRule);
    assert_eq!(direct.producer().id, R3_BUSINESS_LOGIC_PRODUCER_ID);
    assert!(direct.claim().security_interpretation.is_none());
    assert_eq!(
        direct.claim().category,
        "business_logic_invariant_observation"
    );
    assert_eq!(direct.claim().input_digests, vec!["sha256:violated"]);
    assert_eq!(direct.claim().locations.len(), 1);
    assert_eq!(
        direct.claim().locations[0].repo_relative_path,
        "src/routes/accounts.ts"
    );
    assert_eq!(
        direct.claim().locations[0].content_digest.as_deref(),
        Some("sha256:violated")
    );
    assert!(direct.verify_identity().unwrap());

    assert_eq!(
        interpretation.claim().category,
        "business_logic_invariant_interpretation"
    );
    let wording = interpretation
        .claim()
        .security_interpretation
        .as_deref()
        .expect("separate interpretation wording");
    assert!(wording.contains("VIOLATED"));
    assert!(wording.contains("does not claim runtime exploitability"));
    assert!(wording.contains("actual cross-tenant access"));
    assert!(interpretation.verify_identity().unwrap());
}

#[test]
fn unknown_remains_non_clean_and_never_becomes_satisfied_wording() {
    let output = produce_business_logic_outputs(
        &[evaluation("unknown", InvariantEvaluationState::Unknown)],
        &complete_coverage(),
        OBSERVED_AT,
    )
    .unwrap();
    let interpretation = output
        .evidence()
        .iter()
        .find(|item| item.claim().epistemic_class == EpistemicClass::Inference)
        .unwrap();
    let wording = interpretation
        .claim()
        .security_interpretation
        .as_deref()
        .unwrap();
    assert!(wording.contains("UNKNOWN"));
    assert!(wording.contains("not a clean or satisfied result"));
    assert!(wording.contains("semantic linking is partial"));
    assert!(!wording.contains("is SATISFIED"));
}

#[test]
fn coverage_maps_all_areas_and_both_canonical_aggregate_capabilities() {
    let output = produce_business_logic_outputs(&[], &complete_coverage(), OBSERVED_AT).unwrap();
    assert_eq!(output.coverage().len(), 12);
    assert!(output.coverage().iter().all(|record| {
        record.producer.as_deref() == Some(R3_BUSINESS_LOGIC_PRODUCER_ID)
            && record.provider_dimension == Some(ProviderCoverageDimension::CrossLayerBusinessLogic)
    }));
    assert!(
        output
            .coverage()
            .iter()
            .any(|record| record.capability == COVERAGE_CROSS_LAYER_BUSINESS_LOGIC)
    );
    assert!(
        output
            .coverage()
            .iter()
            .any(|record| record.capability == COVERAGE_BUSINESS_LOGIC)
    );
    assert!(
        output
            .coverage()
            .iter()
            .all(|record| record.state == CoverageState::Covered)
    );
}

#[test]
fn a_required_coverage_gap_survives_area_and_aggregate_mapping() {
    let mut matrix = complete_coverage();
    let index = matrix
        .iter()
        .position(|entry| entry.area() == BusinessLogicCoverageArea::SemanticLinking)
        .unwrap();
    matrix[index] = coverage_entry(
        BusinessLogicCoverageArea::SemanticLinking,
        CoverageState::Partial,
    );

    let output = produce_business_logic_outputs(&[], &matrix, OBSERVED_AT).unwrap();
    for capability in [COVERAGE_CROSS_LAYER_BUSINESS_LOGIC, COVERAGE_BUSINESS_LOGIC] {
        let aggregate = output
            .coverage()
            .iter()
            .find(|record| record.capability == capability)
            .unwrap();
        assert_eq!(aggregate.state, CoverageState::Partial);
        assert_eq!(
            aggregate.reason_code.as_deref(),
            Some("R3_BUSINESS_LOGIC_GAPS_VISIBLE")
        );
        assert!(
            aggregate
                .details
                .as_deref()
                .unwrap()
                .contains("SEMANTIC_LINKING")
        );
    }
}

#[test]
fn equivalent_inputs_have_deterministic_evidence_and_coverage_ordering() {
    let first_eval = evaluation("a", InvariantEvaluationState::Satisfied);
    let second_eval = evaluation("b", InvariantEvaluationState::Violated);
    let first_matrix = complete_coverage();

    let first = produce_business_logic_outputs(
        &[first_eval.clone(), second_eval.clone()],
        &first_matrix,
        OBSERVED_AT,
    )
    .unwrap();

    let mut reversed_matrix = first_matrix.clone();
    reversed_matrix.reverse();
    let second =
        produce_business_logic_outputs(&[second_eval, first_eval], &reversed_matrix, OBSERVED_AT)
            .unwrap();

    let first_evidence_ids: Vec<_> = first
        .evidence()
        .iter()
        .map(|item| item.evidence_id())
        .collect();
    let second_evidence_ids: Vec<_> = second
        .evidence()
        .iter()
        .map(|item| item.evidence_id())
        .collect();
    assert_eq!(first_evidence_ids, second_evidence_ids);

    let first_coverage_ids: Vec<_> = first
        .coverage()
        .iter()
        .map(|item| item.coverage_id.as_str())
        .collect();
    let second_coverage_ids: Vec<_> = second
        .coverage()
        .iter()
        .map(|item| item.coverage_id.as_str())
        .collect();
    assert_eq!(first_coverage_ids, second_coverage_ids);
}

#[test]
fn repository_or_foreign_coverage_producer_cannot_choose_runtime_authority() {
    let mut matrix = complete_coverage();
    matrix[0] = BusinessLogicCoverage::new(
        BusinessLogicCoverageArea::Routes,
        CoverageState::Covered,
        "ATTACKER_FIXTURE",
        ".",
        Vec::new(),
        "repository.attacker",
        BusinessLogicLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        produce_business_logic_outputs(&[], &matrix, OBSERVED_AT),
        Err(BusinessLogicProducerError::UnexpectedCoverageProducer(value))
            if value == "repository.attacker"
    ));
}

#[test]
fn duplicate_evaluation_identity_fails_closed() {
    let value = evaluation("duplicate", InvariantEvaluationState::Violated);
    assert!(matches!(
        produce_business_logic_outputs(&[value.clone(), value], &complete_coverage(), OBSERVED_AT),
        Err(BusinessLogicProducerError::DuplicateEvaluationId(_))
    ));
}

#[test]
fn empty_runtime_timestamp_is_rejected() {
    assert!(matches!(
        produce_business_logic_outputs(&[], &complete_coverage(), "  "),
        Err(BusinessLogicProducerError::EmptyObservedAt)
    ));
}

#[test]
fn producer_authority_canaries_remain_false() {
    const { assert!(!R3_BUSINESS_LOGIC_CREATES_FINDINGS) };
    const { assert!(!R3_BUSINESS_LOGIC_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_BUSINESS_LOGIC_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_BUSINESS_LOGIC_REQUESTS_PROVIDER_CREDENTIALS) };
    const { assert!(!R3_BUSINESS_LOGIC_CLAIMS_RUNTIME_EXPLOITABILITY) };
}
