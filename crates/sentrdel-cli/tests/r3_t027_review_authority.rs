use sentrdel_cli::{CliDecision, CliRepository, CliTiming, review::ReviewOutput};
use sentrdel_review::business_logic::{
    coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS,
    model::{BusinessLogicCoverage, BusinessLogicLimits},
    producer::{R3_BUSINESS_LOGIC_PRODUCER_ID, produce_business_logic_outputs},
};
use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    finding::{
        EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity,
    },
};

fn prior_finding() -> Finding {
    let authority = ReconcilerAuthority::from_runtime(
        "r3-t027-review-authority-test",
        format!("sha256:{}", "d".repeat(64)),
    )
    .unwrap();
    Finding::new_reconciled(
        ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint: "fingerprint:r3-t027-prior".to_owned(),
            title: "Existing authoritative finding".to_owned(),
            impact_statement: "Existing impact statement must survive R3 registration.".to_owned(),
            category: "fixture".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Corroborated,
            evidence_ids: vec!["evidence:prior".to_owned()],
            contradiction_ids: Vec::new(),
            primary_location: Some("src/prior.ts".to_owned()),
            affected_subjects: vec!["file:src/prior.ts".to_owned()],
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: Some("Preserve this authoritative finding.".to_owned()),
            updated_at: "2026-09-07T00:00:00Z".to_owned(),
        },
        &authority,
    )
    .unwrap()
}

fn prior_coverage() -> CoverageRecord {
    CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: "coverage:r3-t027-prior".to_owned(),
        capability: "prior-review-capability".to_owned(),
        scope: ".".to_owned(),
        producer: Some("prior-review-producer".to_owned()),
        provider_dimension: None,
        state: CoverageState::Partial,
        reason_code: Some("PRIOR_REVIEW_PARTIAL".to_owned()),
        details: Some("Existing coverage must survive R3 registration.".to_owned()),
        input_digests: Vec::new(),
        observed_at: "2026-09-07T00:00:00Z".to_owned(),
    }
}

fn r3_producer() -> sentrdel_review::business_logic::producer::BusinessLogicProducerOutput {
    let coverage = REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
        .into_iter()
        .map(|area| {
            BusinessLogicCoverage::new(
                area,
                CoverageState::Covered,
                "R3_T027_AUTHORITY_TEST",
                ".",
                Vec::new(),
                R3_BUSINESS_LOGIC_PRODUCER_ID,
                BusinessLogicLimits::default(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    produce_business_logic_outputs(&[], &coverage, "2026-09-07T00:00:00Z").unwrap()
}

#[test]
fn integration_preserves_existing_findings_and_coverage_verbatim() {
    let baseline = ReviewOutput::new(
        CliRepository::new("repo:r3-t027-prior", ".").unwrap(),
        CliDecision::Ask,
        vec![prior_finding()],
        vec![prior_coverage()],
        Vec::new(),
        CliTiming::default(),
        Some(vec!["store:prior".to_owned()]),
    )
    .unwrap();
    let prior_decision = baseline.envelope().decision;
    let prior_findings = baseline.findings().to_vec();
    let prior_coverage = baseline.envelope().coverage.clone();
    let prior_store_refs = baseline.envelope().store_refs.clone();
    let producer = r3_producer();

    let registered = baseline
        .integrate_r3_business_logic(&producer, &[], &[], &[], &[])
        .unwrap();

    assert_eq!(registered.output().envelope().decision, prior_decision);
    assert_eq!(registered.output().findings(), prior_findings.as_slice());
    assert_eq!(registered.output().envelope().store_refs, prior_store_refs);
    assert_eq!(
        registered.output().envelope().coverage.len(),
        prior_coverage.len() + producer.coverage().len()
    );
    for expected in &prior_coverage {
        assert!(
            registered
                .output()
                .envelope()
                .coverage
                .iter()
                .any(|actual| actual == expected),
            "prior authoritative coverage was discarded or replaced: {expected:?}"
        );
    }
}
