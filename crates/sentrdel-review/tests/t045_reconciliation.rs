use sentrdel_review::reconcile::{ReconcileError, ReconciliationRule, reconcile_evidence};
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{
    EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation, EvidenceSubject,
    ProducerKind,
};
use sentrdel_schema::finding::{EpistemicState, ReconcilerAuthority, Severity, WorkflowState};
use serde_json::Value;
use std::collections::BTreeMap;

fn reconciler() -> ReconcilerAuthority {
    ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t045-config")
        .expect("reconciler authority")
}

fn rule() -> ReconciliationRule {
    ReconciliationRule::from_runtime(
        "github_actions",
        "workflow-security",
        "Trust-sensitive workflow change",
        "Changed workflow authority requires review",
        Severity::High,
    )
    .expect("runtime rule")
}

fn claim(class: EpistemicClass, line: u64, category: &str) -> EvidenceClaim {
    let mut attributes = BTreeMap::new();
    attributes.insert(
        "rule_id".to_owned(),
        Value::String("gha.permission-widening".to_owned()),
    );
    attributes.insert("severity".to_owned(), Value::String("BLOCK".to_owned()));
    attributes.insert(
        "title".to_owned(),
        Value::String("untrusted producer title".to_owned()),
    );
    EvidenceClaim {
        schema_version: SCHEMA_V1.to_owned(),
        input_digests: Vec::new(),
        observation: "bounded observation".to_owned(),
        security_interpretation: None,
        category: category.to_owned(),
        epistemic_class: class,
        confidence_band: None,
        subjects: vec![EvidenceSubject {
            kind: "repository_path".to_owned(),
            id: ".github/workflows/security.yml".to_owned(),
        }],
        locations: vec![EvidenceLocation {
            repo_relative_path: ".github/workflows/security.yml".to_owned(),
            start_line: Some(line),
            start_column: Some(1),
            end_line: Some(line),
            end_column: Some(20),
            symbol: None,
            content_digest: None,
        }],
        attributes,
        reproduction: None,
        captured_at: "2026-08-28T00:00:00Z".to_owned(),
    }
}

fn native_fact(line: u64) -> Evidence {
    EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
        .unwrap()
        .seal(claim(EpistemicClass::Fact, line, "github_actions"))
        .unwrap()
}

fn llm_inference(line: u64) -> Evidence {
    let mut value = claim(EpistemicClass::Inference, line, "github_actions");
    value.security_interpretation = Some("possible trust-boundary impact".to_owned());
    EvidenceAuthority::from_runtime("reasoner", "1", ProducerKind::LlmReasoner)
        .unwrap()
        .seal(value)
        .unwrap()
}

fn contradiction(line: u64) -> Evidence {
    EvidenceAuthority::from_runtime("runtime", "1", ProducerKind::RuntimeTest)
        .unwrap()
        .seal(claim(
            EpistemicClass::Contradiction,
            line,
            "github_actions",
        ))
        .unwrap()
}

#[test]
fn correlation_is_stable_across_line_shift_and_input_order() {
    let first = native_fact(10);
    let second = llm_inference(200);
    let forward = reconcile_evidence(
        &[first.clone(), second.clone()],
        &rule(),
        &reconciler(),
        "2026-08-28T01:00:00Z",
    )
    .unwrap();
    let reverse = reconcile_evidence(
        &[second, first],
        &rule(),
        &reconciler(),
        "2026-08-28T01:00:00Z",
    )
    .unwrap();

    assert_eq!(forward.len(), 1);
    assert_eq!(forward[0].to_record(), reverse[0].to_record());
    assert_eq!(forward[0].draft().epistemic_state, EpistemicState::Corroborated);
    assert_eq!(forward[0].workflow_state(), &WorkflowState::New);
}

#[test]
fn contradictions_are_retained_and_make_the_finding_contested() {
    let fact = native_fact(10);
    let inference = llm_inference(20);
    let contradiction = contradiction(30);
    let contradiction_id = contradiction.evidence_id().to_owned();
    let evidence_ids = [
        fact.evidence_id().to_owned(),
        inference.evidence_id().to_owned(),
        contradiction_id.clone(),
    ];

    let findings = reconcile_evidence(
        &[contradiction, inference, fact],
        &rule(),
        &reconciler(),
        "2026-08-28T01:00:00Z",
    )
    .unwrap();
    let draft = findings[0].draft();

    assert_eq!(draft.epistemic_state, EpistemicState::Contested);
    assert_eq!(draft.contradiction_ids, vec![contradiction_id]);
    for evidence_id in evidence_ids {
        assert!(draft.evidence_ids.contains(&evidence_id));
    }
    assert_eq!(draft.evidence_ids.len(), 3);
}

#[test]
fn runtime_rule_owns_canonical_semantics_not_evidence_attributes() {
    let finding = reconcile_evidence(
        &[native_fact(10)],
        &rule(),
        &reconciler(),
        "2026-08-28T01:00:00Z",
    )
    .unwrap()
    .remove(0);
    let draft = finding.draft();

    assert_eq!(draft.category, "workflow-security");
    assert_eq!(draft.title, "Trust-sensitive workflow change");
    assert_eq!(
        draft.impact_statement,
        "Changed workflow authority requires review"
    );
    assert_eq!(draft.severity, Severity::High);
    assert_ne!(draft.title, "untrusted producer title");
}

#[test]
fn interpretation_evidence_remains_linked_without_becoming_reconciler_authority() {
    let inference = llm_inference(20);
    let inference_id = inference.evidence_id().to_owned();
    let original_interpretation = inference
        .claim()
        .security_interpretation
        .clone()
        .expect("interpretation");
    let finding = reconcile_evidence(
        &[native_fact(10), inference.clone()],
        &rule(),
        &reconciler(),
        "2026-08-28T01:00:00Z",
    )
    .unwrap()
    .remove(0);

    assert!(finding.draft().evidence_ids.contains(&inference_id));
    assert_eq!(
        inference.claim().security_interpretation.as_deref(),
        Some(original_interpretation.as_str())
    );
    assert_ne!(finding.draft().impact_statement, original_interpretation);
}

#[test]
fn contradiction_only_and_mixed_categories_fail_closed() {
    assert!(matches!(
        reconcile_evidence(
            &[contradiction(30)],
            &rule(),
            &reconciler(),
            "2026-08-28T01:00:00Z",
        ),
        Err(ReconcileError::NoSupportingEvidence)
    ));

    let other = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
        .unwrap()
        .seal(claim(EpistemicClass::Fact, 10, "other"))
        .unwrap();
    assert!(matches!(
        reconcile_evidence(
            &[native_fact(10), other],
            &rule(),
            &reconciler(),
            "2026-08-28T01:00:00Z",
        ),
        Err(ReconcileError::UnexpectedEvidenceCategory { .. })
    ));
}

#[test]
fn empty_inputs_runtime_rule_and_timestamp_fail_closed() {
    assert!(matches!(
        ReconciliationRule::from_runtime("", "finding", "title", "impact", Severity::Info),
        Err(ReconcileError::InvalidRuntimeRule)
    ));
    assert!(matches!(
        reconcile_evidence(&[], &rule(), &reconciler(), "2026-08-28T01:00:00Z"),
        Err(ReconcileError::EmptyEvidence)
    ));
    assert!(matches!(
        reconcile_evidence(&[native_fact(10)], &rule(), &reconciler(), " "),
        Err(ReconcileError::EmptyUpdatedAt)
    ));
}
