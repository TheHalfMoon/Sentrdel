use sentrdel_cli::{CliRepository, CliTiming};
use sentrdel_schema::{
    SCHEMA_V1,
    finding::{
        EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity,
        WorkflowState,
    },
};

use crate::explain::{ExplainOutput, ImpactComponents};

fn canonical_finding() -> Finding {
    let reconciler = ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:t070-config")
        .expect("reconciler authority");
    Finding::new_reconciled(
        ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint: "t070:fingerprint".to_owned(),
            title: "Privileged workflow path".to_owned(),
            impact_statement: "A changed workflow grants a privileged capability.".to_owned(),
            category: "ci.workflow".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Corroborated,
            evidence_ids: vec!["evidence:a".to_owned(), "evidence:b".to_owned()],
            contradiction_ids: Vec::new(),
            primary_location: Some(".github/workflows/ci.yml:12".to_owned()),
            affected_subjects: vec!["workflow:ci".to_owned()],
            first_seen_commit: Some("commit:before".to_owned()),
            last_seen_commit: Some("commit:after".to_owned()),
            remediation: Some(
                "Reduce workflow permissions to the minimum required scope.".to_owned(),
            ),
            updated_at: "2026-08-29T00:00:00Z".to_owned(),
        },
        &reconciler,
    )
    .expect("finding")
}

fn output(finding: Finding) -> ExplainOutput {
    ExplainOutput::new(
        7,
        finding,
        CliRepository::new("sha256:repo", ".").expect("repository"),
        ImpactComponents::new(
            "an untrusted pull request actor",
            "obtain write-capable CI authority",
            "the repository",
        )
        .expect("impact components"),
        Vec::new(),
        CliTiming::default(),
        Some(vec!["graph:provenance-root".to_owned()]),
    )
    .expect("explain output")
}

#[test]
fn human_explanation_preserves_canonical_finding_record_and_authority_axes() {
    let finding = canonical_finding();
    let before = finding.to_record();
    let before_severity = finding.draft().severity.clone();
    let before_epistemic = finding.draft().epistemic_state.clone();
    let before_workflow = finding.workflow_state().clone();

    let output = output(finding);
    let rendered = output.render_human();

    assert!(rendered.contains("Impact:"));
    assert_eq!(output.finding().to_record(), before);
    assert_eq!(&output.finding().draft().severity, &before_severity);
    assert_eq!(
        &output.finding().draft().epistemic_state,
        &before_epistemic
    );
    assert_eq!(output.finding().workflow_state(), &before_workflow);
    assert_eq!(&output.finding().draft().severity, &Severity::High);
    assert_eq!(
        &output.finding().draft().epistemic_state,
        &EpistemicState::Corroborated
    );
    assert_eq!(output.finding().workflow_state(), &WorkflowState::New);
}

#[test]
fn json_explanation_preserves_canonical_finding_record_and_authority_axes() {
    let finding = canonical_finding();
    let before = finding.to_record();
    let before_severity = finding.draft().severity.clone();
    let before_epistemic = finding.draft().epistemic_state.clone();
    let before_workflow = finding.workflow_state().clone();

    let output = output(finding);
    let rendered = output.render_json().expect("json output");
    let value: serde_json::Value =
        serde_json::from_str(rendered.trim_end()).expect("parse json output");

    assert_eq!(value["command"], "explain");
    assert_eq!(value["decision"], "ALLOW");
    assert_eq!(output.finding().to_record(), before);
    assert_eq!(&output.finding().draft().severity, &before_severity);
    assert_eq!(
        &output.finding().draft().epistemic_state,
        &before_epistemic
    );
    assert_eq!(output.finding().workflow_state(), &before_workflow);
}
