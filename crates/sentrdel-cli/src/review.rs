use std::{collections::BTreeSet, error::Error, fmt};

use sentrdel_schema::{
    coverage::{CoverageRecord, CoverageState},
    finding::{EpistemicState, Finding, Severity},
};

use crate::{
    CliCommand, CliContractError, CliDecision, CliDiagnostic, CliDiagnosticLevel, CliEnvelope,
    CliFindingRef, CliRepository, CliTiming,
};

const COVERAGE_GAP_DIAGNOSTIC: &str = "REVIEW_COVERAGE_GAP";

/// Output-only coverage gap that has no authoritative `CoverageRecord`.
///
/// This is used for expected producers that did not report. It deliberately
/// carries no coverage id and cannot masquerade as a producer-issued record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReviewCoverageGap {
    pub capability: String,
    pub scope: String,
    pub producer: Option<String>,
    pub state: CoverageState,
    pub reason_code: String,
}

impl ReviewCoverageGap {
    pub fn new(
        capability: impl Into<String>,
        scope: impl Into<String>,
        producer: Option<String>,
        state: CoverageState,
        reason_code: impl Into<String>,
    ) -> Result<Self, ReviewOutputError> {
        let gap = Self {
            capability: capability.into().trim().to_owned(),
            scope: scope.into().trim().to_owned(),
            producer: producer.map(|value| value.trim().to_owned()),
            state,
            reason_code: reason_code.into().trim().to_owned(),
        };
        if gap.capability.is_empty()
            || gap.scope.is_empty()
            || gap.reason_code.is_empty()
            || gap.producer.as_deref().is_some_and(str::is_empty)
        {
            return Err(ReviewOutputError::InvalidCoverageGap);
        }
        if gap.state == CoverageState::Covered {
            return Err(ReviewOutputError::CoveredGap);
        }
        Ok(gap)
    }
}

/// Output-only view for the R1 `sentrdel review` command.
///
/// Canonical Finding and Coverage authority remains in `sentrdel-schema` and
/// review producers. This type only validates and renders already-authoritative
/// results plus explicit local coverage gaps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewOutput {
    envelope: CliEnvelope,
    findings: Vec<Finding>,
    missing_coverage: Vec<ReviewCoverageGap>,
}

impl ReviewOutput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: CliRepository,
        decision: CliDecision,
        mut findings: Vec<Finding>,
        observed_coverage: Vec<CoverageRecord>,
        mut missing_coverage: Vec<ReviewCoverageGap>,
        timing: CliTiming,
        store_refs: Option<Vec<String>>,
    ) -> Result<Self, ReviewOutputError> {
        findings.sort_by(|left, right| left.finding_id().cmp(right.finding_id()));
        reject_duplicate_findings(&findings)?;

        missing_coverage.sort();
        reject_duplicate_missing_coverage(&missing_coverage)?;

        let finding_refs = findings
            .iter()
            .map(|finding| {
                CliFindingRef::new(
                    finding.finding_id(),
                    finding.draft().evidence_ids.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut diagnostics = observed_coverage
            .iter()
            .filter(|record| record.is_gap())
            .map(diagnostic_for_observed_gap)
            .collect::<Result<Vec<_>, _>>()?;
        diagnostics.extend(
            missing_coverage
                .iter()
                .map(diagnostic_for_missing_gap)
                .collect::<Result<Vec<_>, _>>()?,
        );

        let envelope = CliEnvelope::new(
            CliCommand::Review,
            repository,
            decision,
            finding_refs,
            observed_coverage,
            diagnostics,
            timing,
            store_refs,
        )?;

        Ok(Self {
            envelope,
            findings,
            missing_coverage,
        })
    }

    pub fn envelope(&self) -> &CliEnvelope {
        &self.envelope
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn missing_coverage(&self) -> &[ReviewCoverageGap] {
        &self.missing_coverage
    }

    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        self.envelope.to_json_line()
    }

    /// Render the binding R1 human-output order:
    /// decision -> plain-language findings -> proof/evidence -> coverage gaps ->
    /// optional technical detail.
    pub fn render_human(&self, verbose: bool) -> String {
        let mut out = String::new();
        out.push_str("Decision: ");
        out.push_str(decision_name(self.envelope.decision));
        out.push('\n');

        out.push_str("\nFindings:\n");
        if self.findings.is_empty() {
            out.push_str("- No canonical findings.\n");
        } else {
            for finding in &self.findings {
                let draft = finding.draft();
                out.push_str("- [");
                out.push_str(severity_name(&draft.severity));
                out.push_str("] ");
                out.push_str(&draft.title);
                out.push_str(": ");
                out.push_str(&draft.impact_statement);
                out.push('\n');
                if let Some(location) = &draft.primary_location {
                    out.push_str("  Location: ");
                    out.push_str(location);
                    out.push('\n');
                }
            }
        }

        out.push_str("\nProof / evidence:\n");
        if self.findings.is_empty() {
            out.push_str("- None.\n");
        } else {
            for finding in &self.findings {
                let draft = finding.draft();
                out.push_str("- ");
                out.push_str(finding.finding_id());
                out.push_str(" — ");
                out.push_str(epistemic_name(&draft.epistemic_state));
                out.push_str("; evidence=");
                out.push_str(&draft.evidence_ids.len().to_string());
                if !draft.contradiction_ids.is_empty() {
                    out.push_str("; contradictions=");
                    out.push_str(&draft.contradiction_ids.len().to_string());
                }
                out.push('\n');
            }
        }

        out.push_str("\nCoverage gaps:\n");
        let mut wrote_gap = false;
        for record in self.envelope.coverage.iter().filter(|record| record.is_gap()) {
            wrote_gap = true;
            render_observed_gap(&mut out, record);
        }
        for gap in &self.missing_coverage {
            wrote_gap = true;
            render_missing_gap(&mut out, gap);
        }
        if !wrote_gap {
            out.push_str("- None.\n");
        }

        if verbose {
            out.push_str("\nTechnical detail:\n");
            for finding in &self.findings {
                let draft = finding.draft();
                out.push_str("- finding=");
                out.push_str(finding.finding_id());
                out.push_str(" category=");
                out.push_str(&draft.category);
                out.push_str(" evidence_ids=");
                out.push_str(&draft.evidence_ids.join(","));
                out.push('\n');
            }
            out.push_str("- observed_coverage_records=");
            out.push_str(&self.envelope.coverage.len().to_string());
            out.push_str(" missing_expected_coverage=");
            out.push_str(&self.missing_coverage.len().to_string());
            out.push('\n');
        }

        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewOutputError {
    Cli(CliContractError),
    DuplicateFindingId(String),
    InvalidCoverageGap,
    CoveredGap,
    DuplicateMissingCoverage,
}

impl fmt::Display for ReviewOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(error) => write!(formatter, "review CLI contract rejected output: {error}"),
            Self::DuplicateFindingId(id) => {
                write!(formatter, "review output contains duplicate finding id {id:?}")
            }
            Self::InvalidCoverageGap => formatter.write_str(
                "review missing-coverage gap requires bounded non-empty capability, scope, reason, and optional producer",
            ),
            Self::CoveredGap => formatter.write_str(
                "review missing-coverage entry cannot claim COVERED without a producer CoverageRecord",
            ),
            Self::DuplicateMissingCoverage => {
                formatter.write_str("review missing-coverage entries must be unique")
            }
        }
    }
}

impl Error for ReviewOutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Cli(error) => Some(error),
            Self::DuplicateFindingId(_)
            | Self::InvalidCoverageGap
            | Self::CoveredGap
            | Self::DuplicateMissingCoverage => None,
        }
    }
}

impl From<CliContractError> for ReviewOutputError {
    fn from(value: CliContractError) -> Self {
        Self::Cli(value)
    }
}

fn reject_duplicate_findings(findings: &[Finding]) -> Result<(), ReviewOutputError> {
    for pair in findings.windows(2) {
        if pair[0].finding_id() == pair[1].finding_id() {
            return Err(ReviewOutputError::DuplicateFindingId(
                pair[0].finding_id().to_owned(),
            ));
        }
    }
    Ok(())
}

fn reject_duplicate_missing_coverage(gaps: &[ReviewCoverageGap]) -> Result<(), ReviewOutputError> {
    let mut keys = BTreeSet::new();
    for gap in gaps {
        let key = (&gap.capability, &gap.scope, &gap.producer);
        if !keys.insert(key) {
            return Err(ReviewOutputError::DuplicateMissingCoverage);
        }
    }
    Ok(())
}

fn diagnostic_for_observed_gap(record: &CoverageRecord) -> Result<CliDiagnostic, CliContractError> {
    CliDiagnostic::new(
        COVERAGE_GAP_DIAGNOSTIC,
        CliDiagnosticLevel::Warning,
        format!(
            "coverage gap: capability={} scope={} producer={} state={} reason={}",
            record.capability,
            record.scope,
            record.producer.as_deref().unwrap_or("unspecified"),
            coverage_state_name(&record.state),
            record.reason_code.as_deref().unwrap_or("NO_REASON_CODE")
        ),
    )
}

fn diagnostic_for_missing_gap(gap: &ReviewCoverageGap) -> Result<CliDiagnostic, CliContractError> {
    CliDiagnostic::new(
        COVERAGE_GAP_DIAGNOSTIC,
        CliDiagnosticLevel::Warning,
        format!(
            "coverage gap: capability={} scope={} producer={} state={} reason={} source=MISSING_EXPECTED",
            gap.capability,
            gap.scope,
            gap.producer.as_deref().unwrap_or("unspecified"),
            coverage_state_name(&gap.state),
            gap.reason_code
        ),
    )
}

fn render_observed_gap(out: &mut String, record: &CoverageRecord) {
    out.push_str("- ");
    out.push_str(&record.capability);
    out.push_str(" @ ");
    out.push_str(&record.scope);
    out.push_str(" [");
    out.push_str(coverage_state_name(&record.state));
    out.push(']');
    if let Some(producer) = &record.producer {
        out.push_str(" producer=");
        out.push_str(producer);
    }
    if let Some(reason) = &record.reason_code {
        out.push_str(" reason=");
        out.push_str(reason);
    }
    out.push('\n');
}

fn render_missing_gap(out: &mut String, gap: &ReviewCoverageGap) {
    out.push_str("- ");
    out.push_str(&gap.capability);
    out.push_str(" @ ");
    out.push_str(&gap.scope);
    out.push_str(" [");
    out.push_str(coverage_state_name(&gap.state));
    out.push(']');
    if let Some(producer) = &gap.producer {
        out.push_str(" producer=");
        out.push_str(producer);
    }
    out.push_str(" reason=");
    out.push_str(&gap.reason_code);
    out.push_str(" source=MISSING_EXPECTED\n");
}

const fn decision_name(decision: CliDecision) -> &'static str {
    match decision {
        CliDecision::Allow => "ALLOW",
        CliDecision::Ask => "ASK",
        CliDecision::Deny => "DENY",
        CliDecision::Undecidable => "UNDECIDABLE",
        CliDecision::UsageError => "USAGE_ERROR",
        CliDecision::InternalFailure => "INTERNAL_FAILURE",
    }
}

const fn severity_name(severity: &Severity) -> &'static str {
    match severity {
        Severity::Block => "BLOCK",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

const fn epistemic_name(state: &EpistemicState) -> &'static str {
    match state {
        EpistemicState::Detected => "Observed",
        EpistemicState::Corroborated => "Corroborated",
        EpistemicState::Contested => "Contested",
        EpistemicState::Proven => "Proven by test",
        EpistemicState::Unproven => "Unconfirmed",
        EpistemicState::Unverifiable => "Unverifiable",
    }
}

const fn coverage_state_name(state: &CoverageState) -> &'static str {
    match state {
        CoverageState::Covered => "COVERED",
        CoverageState::Partial => "PARTIAL",
        CoverageState::Unsupported => "UNSUPPORTED",
        CoverageState::Unavailable => "UNAVAILABLE",
        CoverageState::Failed => "FAILED",
        CoverageState::TimedOut => "TIMED_OUT",
        CoverageState::SkippedByPolicy => "SKIPPED_BY_POLICY",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::{
        SCHEMA_V1,
        finding::{ReconciledFindingDraft, ReconcilerAuthority, Severity, WorkflowState},
    };

    fn finding(id_seed: &str, severity: Severity, epistemic_state: EpistemicState) -> Finding {
        let authority = ReconcilerAuthority::from_runtime(
            "review-output-tests",
            format!("sha256:{}", "a".repeat(64)),
        )
        .unwrap();
        Finding::new_reconciled(
            ReconciledFindingDraft {
                schema_version: SCHEMA_V1.to_owned(),
                fingerprint: format!("fingerprint:{id_seed}"),
                title: format!("Finding {id_seed}"),
                impact_statement: "An attacker could affect the changed application path.".to_owned(),
                category: "fixture".to_owned(),
                severity,
                epistemic_state,
                evidence_ids: vec![format!("evidence:{id_seed}")],
                contradiction_ids: Vec::new(),
                primary_location: Some("src/app.rs".to_owned()),
                affected_subjects: vec!["file:src/app.rs".to_owned()],
                first_seen_commit: None,
                last_seen_commit: None,
                remediation: None,
                updated_at: "2026-08-28T00:00:00Z".to_owned(),
            },
            &authority,
        )
        .unwrap()
    }

    fn coverage(id: &str, state: CoverageState) -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: id.to_owned(),
            capability: "changed-secrets".to_owned(),
            scope: ".".to_owned(),
            producer: Some("native-secrets".to_owned()),
            provider_dimension: None,
            state,
            reason_code: None,
            details: None,
            input_digests: Vec::new(),
            observed_at: "2026-08-28T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn human_output_uses_binding_order_and_plain_language_first() {
        let record = coverage("coverage:secret", CoverageState::Failed);
        let output = ReviewOutput::new(
            CliRepository::new("sha256:repo", ".").unwrap(),
            CliDecision::Undecidable,
            vec![finding("secret", Severity::Block, EpistemicState::Detected)],
            vec![record],
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap();

        let human = output.render_human(false);
        let decision = human.find("Decision:").unwrap();
        let findings = human.find("Findings:").unwrap();
        let proof = human.find("Proof / evidence:").unwrap();
        let coverage = human.find("Coverage gaps:").unwrap();
        assert!(decision < findings && findings < proof && proof < coverage);
        assert!(human.contains("An attacker could affect the changed application path."));
        assert!(human.contains("[BLOCK]"));
        assert!(human.contains("Observed"));
        assert!(human.contains("FAILED"));
        assert!(!human.contains("Technical detail:"));
    }

    #[test]
    fn json_uses_stable_review_envelope_and_exposes_gap_diagnostics() {
        let record = coverage("coverage:secret", CoverageState::TimedOut);
        let output = ReviewOutput::new(
            CliRepository::new("sha256:repo", ".").unwrap(),
            CliDecision::Undecidable,
            vec![finding("secret", Severity::High, EpistemicState::Contested)],
            vec![record],
            Vec::new(),
            CliTiming::default(),
            Some(vec!["store:evidence".to_owned()]),
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_str(output.render_json().unwrap().trim()).unwrap();
        assert_eq!(json["command"], "review");
        assert_eq!(json["decision"], "UNDECIDABLE");
        assert_eq!(json["coverage"][0]["coverage_id"], "coverage:secret");
        assert_eq!(json["diagnostics"][0]["code"], COVERAGE_GAP_DIAGNOSTIC);
        assert_eq!(output.envelope().exit_code().as_u8(), 3);
    }

    #[test]
    fn missing_expected_coverage_is_visible_without_forging_a_coverage_record() {
        let gap = ReviewCoverageGap::new(
            "github-actions",
            ".github/workflows",
            Some("native-actions".to_owned()),
            CoverageState::Unavailable,
            "PRODUCER_NOT_REPORTED",
        )
        .unwrap();
        let output = ReviewOutput::new(
            CliRepository::new("sha256:repo", ".").unwrap(),
            CliDecision::Undecidable,
            Vec::new(),
            Vec::new(),
            vec![gap],
            CliTiming::default(),
            None,
        )
        .unwrap();

        assert!(output.envelope().coverage.is_empty());
        assert_eq!(output.envelope().diagnostics.len(), 1);
        assert_eq!(output.missing_coverage().len(), 1);
        assert!(output.render_human(false).contains("source=MISSING_EXPECTED"));
    }

    #[test]
    fn missing_coverage_cannot_claim_covered_without_producer_authority() {
        let error = ReviewCoverageGap::new(
            "github-actions",
            ".",
            Some("native-actions".to_owned()),
            CoverageState::Covered,
            "PRODUCER_NOT_REPORTED",
        )
        .unwrap_err();
        assert_eq!(error, ReviewOutputError::CoveredGap);
    }

    #[test]
    fn verbose_output_adds_only_technical_detail_after_coverage() {
        let record = coverage("coverage:secret", CoverageState::Covered);
        let output = ReviewOutput::new(
            CliRepository::new("sha256:repo", ".").unwrap(),
            CliDecision::Allow,
            vec![finding("secret", Severity::Low, EpistemicState::Corroborated)],
            vec![record],
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap();
        let human = output.render_human(true);
        assert!(human.find("Coverage gaps:").unwrap() < human.find("Technical detail:").unwrap());
        assert!(human.contains("category=fixture"));
        assert_eq!(output.findings()[0].workflow_state(), &WorkflowState::New);
    }
}
