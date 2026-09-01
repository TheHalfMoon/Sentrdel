//! Supabase R2 Evidence/Coverage registration for `sentrdel review` and `sentrdel init`.
//!
//! The frozen CLI envelope has no raw-Evidence field. Provider Evidence is
//! therefore retained as canonical `Evidence` for the existing persistence and
//! reconciliation paths, while provider Coverage is added to command output.
//! This module never constructs a Finding or changes a review decision.

use sentrdel_cli::init::InitOutput;
use sentrdel_cli::review::{ReviewOutput, ReviewOutputError};
use sentrdel_cli::{CliContractError, CliEnvelope};
use sentrdel_review::supabase_integration::SupabaseR2ProviderOutput;
use sentrdel_schema::evidence::Evidence;

#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredSupabaseReviewOutput {
    pub output: ReviewOutput,
    provider_evidence: Vec<Evidence>,
}

impl RegisteredSupabaseReviewOutput {
    #[must_use]
    pub fn provider_evidence(&self) -> &[Evidence] {
        &self.provider_evidence
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredSupabaseInitOutput {
    pub output: InitOutput,
    provider_evidence: Vec<Evidence>,
}

impl RegisteredSupabaseInitOutput {
    #[must_use]
    pub fn provider_evidence(&self) -> &[Evidence] {
        &self.provider_evidence
    }
}

pub fn register_supabase_r2_review(
    baseline: &ReviewOutput,
    provider: &SupabaseR2ProviderOutput,
) -> Result<RegisteredSupabaseReviewOutput, ReviewOutputError> {
    let mut coverage = baseline.envelope().coverage.clone();
    coverage.extend(provider.coverage().iter().cloned());

    let output = ReviewOutput::new(
        baseline.envelope().repository.clone(),
        baseline.envelope().decision,
        baseline.findings().to_vec(),
        coverage,
        baseline.missing_coverage().to_vec(),
        baseline.envelope().timing.clone(),
        baseline.envelope().store_refs.clone(),
    )?;

    Ok(RegisteredSupabaseReviewOutput {
        output,
        provider_evidence: provider.evidence().to_vec(),
    })
}

pub fn register_supabase_r2_init(
    baseline: &InitOutput,
    provider: &SupabaseR2ProviderOutput,
) -> Result<RegisteredSupabaseInitOutput, CliContractError> {
    let mut coverage = baseline.envelope.coverage.clone();
    coverage.extend(provider.coverage().iter().cloned());

    let envelope = CliEnvelope::new(
        baseline.envelope.command,
        baseline.envelope.repository.clone(),
        baseline.envelope.decision,
        baseline.envelope.findings.clone(),
        coverage,
        baseline.envelope.diagnostics.clone(),
        baseline.envelope.timing.clone(),
        baseline.envelope.store_refs.clone(),
    )?;

    let mut human = baseline.human.clone();
    if !provider.coverage().is_empty() {
        human.push_str("\nSupabase R2 provider coverage:\n");
        for record in provider.coverage() {
            human.push_str("- ");
            human.push_str(&record.capability);
            human.push_str(" @ ");
            human.push_str(&record.scope);
            human.push_str(" [");
            human.push_str(coverage_state_name(&record.state));
            human.push_str("]\n");
        }
    }

    Ok(RegisteredSupabaseInitOutput {
        output: InitOutput { envelope, human },
        provider_evidence: provider.evidence().to_vec(),
    })
}

const fn coverage_state_name(state: &sentrdel_schema::coverage::CoverageState) -> &'static str {
    use sentrdel_schema::coverage::CoverageState;
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
    use sentrdel_cli::init::InitOutput;
    use sentrdel_cli::review::ReviewOutput;
    use sentrdel_cli::{CliCommand, CliDecision, CliEnvelope, CliRepository, CliTiming};
    use sentrdel_review::supabase::COVERAGE_STATIC_POSTURE_DATABASE;
    use sentrdel_review::supabase_integration::SupabaseR2ProviderOutput;
    use sentrdel_schema::SCHEMA_V1;
    use sentrdel_schema::coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension};
    use sentrdel_schema::evidence::{
        EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind,
    };
    use std::collections::BTreeMap;

    fn provider() -> SupabaseR2ProviderOutput {
        let evidence = EvidenceAuthority::from_runtime(
            "sentrdel.supabase.rls-posture",
            "1",
            ProducerKind::NativeRule,
        )
        .unwrap()
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:r2-t025".to_owned()],
            observation: "RLS state was observed in repository-derived migration state".to_owned(),
            security_interpretation: None,
            category: "supabase_rls_posture".to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: "2026-09-01T01:00:00Z".to_owned(),
        })
        .unwrap();
        let coverage = CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: "coverage:r2-t025:database".to_owned(),
            capability: COVERAGE_STATIC_POSTURE_DATABASE.to_owned(),
            scope: ".".to_owned(),
            producer: Some("sentrdel.supabase.rls-posture".to_owned()),
            provider_dimension: Some(ProviderCoverageDimension::StaticPosture),
            state: CoverageState::Covered,
            reason_code: None,
            details: Some("repository-derived static posture only".to_owned()),
            input_digests: vec!["sha256:r2-t025".to_owned()],
            observed_at: "2026-09-01T01:00:00Z".to_owned(),
        };
        SupabaseR2ProviderOutput::new(vec![evidence], vec![coverage]).unwrap()
    }

    fn envelope(command: CliCommand) -> CliEnvelope {
        CliEnvelope::new(
            command,
            CliRepository::new("repo:r2-t025", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn review_registers_provider_coverage_without_minting_findings_or_changing_decision() {
        let baseline = ReviewOutput::new(
            CliRepository::new("repo:r2-t025", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap();
        let registered = register_supabase_r2_review(&baseline, &provider()).unwrap();

        assert_eq!(registered.output.envelope().decision, CliDecision::Allow);
        assert!(registered.output.findings().is_empty());
        assert_eq!(registered.provider_evidence().len(), 1);
        assert_eq!(registered.output.envelope().coverage.len(), 1);
        assert_eq!(
            registered.output.envelope().coverage[0].capability,
            COVERAGE_STATIC_POSTURE_DATABASE
        );
    }

    #[test]
    fn init_registers_detailed_provider_coverage_and_preserves_frozen_envelope_shape() {
        let baseline = InitOutput {
            envelope: envelope(CliCommand::Init),
            human: "Sentrdel init\n".to_owned(),
        };
        let registered = register_supabase_r2_init(&baseline, &provider()).unwrap();

        assert_eq!(registered.output.envelope.decision, CliDecision::Allow);
        assert!(registered.output.envelope.findings.is_empty());
        assert_eq!(registered.provider_evidence().len(), 1);
        assert_eq!(registered.output.envelope.coverage.len(), 1);
        assert!(registered.output.human.contains("Supabase R2 provider coverage:"));
        assert!(registered.output.human.contains("STATIC_POSTURE_DATABASE"));
    }

    #[test]
    fn registration_cannot_turn_provider_evidence_into_a_finding_by_itself() {
        let baseline = ReviewOutput::new(
            CliRepository::new("repo:r2-t025", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap();
        let registered = register_supabase_r2_review(&baseline, &provider()).unwrap();

        assert!(!registered.provider_evidence().is_empty());
        assert!(registered.output.findings().is_empty());
        assert!(registered.output.envelope().findings.is_empty());
    }
}
