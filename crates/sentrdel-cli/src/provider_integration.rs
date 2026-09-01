//! Authority-preserving Supabase R2 registration for `review` and `init`.
//!
//! Provider Evidence is carried forward for the generic R1 reconciler/store
//! boundary but is never converted into a Finding here. Producer-issued R2
//! CoverageRecords are registered directly in CLI output so real static posture
//! replaces the R1 `PACK_REGISTERED_NOT_RUN` placeholder without hiding the
//! explicit unsupported live/business/runtime dimensions.

use sentrdel_review::supabase_integration::SupabaseR2ProviderOutput;
use sentrdel_schema::coverage::{CoverageRecord, CoverageState};
use sentrdel_schema::evidence::Evidence;
use sentrdel_schema::finding::Finding;

use crate::init::InitOutput;
use crate::review::{ReviewCoverageGap, ReviewOutput, ReviewOutputError};
use crate::{
    CliCommand, CliContractError, CliDecision, CliDiagnostic, CliDiagnosticLevel, CliEnvelope,
    CliRepository, CliTiming,
};

const R1_SUPABASE_STATIC_PLACEHOLDER: &str = "provider.supabase.STATIC_POSTURE";
const R1_PACK_NOT_RUN_REASON: &str = "PACK_REGISTERED_NOT_RUN";
const INIT_PROVIDER_GAP_DIAGNOSTIC: &str = "INIT_R2_PROVIDER_COVERAGE_GAP";
const INIT_R2_STATIC_PLACEHOLDER_LINE: &str =
    "- provider supabase / STATIC_POSTURE: Unavailable (PACK_REGISTERED_NOT_RUN)\n";

pub struct RegisteredInitProviderOutput<'a> {
    pub output: InitOutput,
    evidence: &'a [Evidence],
}

impl RegisteredInitProviderOutput<'_> {
    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        self.evidence
    }
}

pub struct RegisteredReviewProviderOutput<'a> {
    pub output: ReviewOutput,
    evidence: &'a [Evidence],
}

impl RegisteredReviewProviderOutput<'_> {
    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        self.evidence
    }
}

pub fn register_supabase_r2_init_output<'a>(
    base: InitOutput,
    provider: &'a SupabaseR2ProviderOutput,
) -> Result<RegisteredInitProviderOutput<'a>, CliContractError> {
    let InitOutput {
        envelope: base_envelope,
        mut human,
    } = base;
    if base_envelope.command != CliCommand::Init {
        return Err(CliContractError::InvalidIdentifier("init command"));
    }

    let has_static_provider_coverage = provider
        .coverage()
        .iter()
        .any(|record| record.provider_dimension == Some(sentrdel_schema::coverage::ProviderCoverageDimension::StaticPosture));

    let mut coverage = base_envelope.coverage;
    if has_static_provider_coverage {
        coverage.retain(|record| !is_r1_supabase_static_placeholder(record));
        human = human.replace(INIT_R2_STATIC_PLACEHOLDER_LINE, "");
    }
    coverage.extend(provider.coverage().iter().cloned());

    let mut diagnostics = base_envelope.diagnostics;
    if has_static_provider_coverage {
        diagnostics.retain(|diagnostic| {
            !(diagnostic.message.contains("provider supabase coverage")
                && diagnostic.message.contains(R1_PACK_NOT_RUN_REASON))
        });
    }
    for record in provider.coverage().iter().filter(|record| record.is_gap()) {
        diagnostics.push(CliDiagnostic::new(
            INIT_PROVIDER_GAP_DIAGNOSTIC,
            CliDiagnosticLevel::Warning,
            format!(
                "Supabase R2 coverage gap: capability={} scope={} producer={} state={:?} reason={}",
                record.capability,
                record.scope,
                record.producer.as_deref().unwrap_or("unspecified"),
                record.state,
                record.reason_code.as_deref().unwrap_or("NO_REASON_CODE")
            ),
        )?);
    }

    if !provider.coverage().is_empty() {
        human.push_str("R2 provider coverage:\n");
        for record in provider.coverage() {
            human.push_str("- ");
            human.push_str(&record.capability);
            human.push_str(": ");
            human.push_str(coverage_state_name(&record.state));
            if let Some(reason) = &record.reason_code {
                human.push_str(" (");
                human.push_str(reason);
                human.push(')');
            }
            human.push('\n');
        }
    }

    let envelope = CliEnvelope::new(
        CliCommand::Init,
        base_envelope.repository,
        base_envelope.decision,
        base_envelope.findings,
        coverage,
        diagnostics,
        base_envelope.timing,
        base_envelope.store_refs,
    )?;

    Ok(RegisteredInitProviderOutput {
        output: InitOutput { envelope, human },
        evidence: provider.evidence(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_review_with_supabase_r2<'a>(
    repository: CliRepository,
    decision: CliDecision,
    findings: Vec<Finding>,
    mut observed_coverage: Vec<CoverageRecord>,
    missing_coverage: Vec<ReviewCoverageGap>,
    timing: CliTiming,
    store_refs: Option<Vec<String>>,
    provider: &'a SupabaseR2ProviderOutput,
) -> Result<RegisteredReviewProviderOutput<'a>, ReviewOutputError> {
    observed_coverage.extend(provider.coverage().iter().cloned());
    let output = ReviewOutput::new(
        repository,
        decision,
        findings,
        observed_coverage,
        missing_coverage,
        timing,
        store_refs,
    )?;
    Ok(RegisteredReviewProviderOutput {
        output,
        evidence: provider.evidence(),
    })
}

fn is_r1_supabase_static_placeholder(record: &CoverageRecord) -> bool {
    record.capability == R1_SUPABASE_STATIC_PLACEHOLDER
        && record.state == CoverageState::Unavailable
        && record.reason_code.as_deref() == Some(R1_PACK_NOT_RUN_REASON)
        && record.producer.is_none()
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
    use std::collections::BTreeMap;

    use sentrdel_review::config_detection::CiMcpConfigDetection;
    use sentrdel_review::pack_registry::SecurityPackRegistry;
    use sentrdel_review::profile::build_project_profile_snapshot;
    use sentrdel_review::project_detection::{DetectionLimits, LanguageEcosystemDetection};
    use sentrdel_review::reconcile::{ReconciliationRule, reconcile_evidence};
    use sentrdel_review::stack_detection::StackDetectorRegistry;
    use sentrdel_review::supabase::{
        COVERAGE_LIVE_POSTURE, COVERAGE_STATIC_POSTURE_DATABASE, register_r2_pack,
    };
    use sentrdel_review::supabase_detection::detect_supabase;
    use sentrdel_review::supabase_integration::{
        SupabaseR2ProviderOutput, SupabaseR2ProviderOutputLimits,
    };
    use sentrdel_schema::SCHEMA_V1;
    use sentrdel_schema::coverage::{CoverageState, ProviderCoverageDimension};
    use sentrdel_schema::evidence::{
        EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind,
    };
    use sentrdel_schema::finding::{ReconcilerAuthority, Severity};

    use super::*;
    use crate::init::build_init_output;

    fn evidence() -> Evidence {
        EvidenceAuthority::from_runtime(
            "sentrdel.supabase.r2-integration-fixture",
            "1",
            ProducerKind::NativeRule,
        )
        .unwrap()
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:fixture".to_owned()],
            observation: "Repository-derived Supabase fixture posture was observed".to_owned(),
            security_interpretation: None,
            category: "supabase_fixture".to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: "2026-09-01T00:00:00Z".to_owned(),
        })
        .unwrap()
    }

    fn coverage(
        id: &str,
        capability: &str,
        dimension: Option<ProviderCoverageDimension>,
        state: CoverageState,
        reason: Option<&str>,
    ) -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: id.to_owned(),
            capability: capability.to_owned(),
            scope: ".".to_owned(),
            producer: Some("sentrdel.supabase.r2-integration-fixture".to_owned()),
            provider_dimension: dimension,
            state,
            reason_code: reason.map(str::to_owned),
            details: None,
            input_digests: vec!["sha256:fixture".to_owned()],
            observed_at: "2026-09-01T00:00:00Z".to_owned(),
        }
    }

    fn provider_output() -> SupabaseR2ProviderOutput {
        SupabaseR2ProviderOutput::new(
            vec![evidence()],
            vec![
                coverage(
                    "coverage:r2:database",
                    COVERAGE_STATIC_POSTURE_DATABASE,
                    Some(ProviderCoverageDimension::StaticPosture),
                    CoverageState::Covered,
                    None,
                ),
                coverage(
                    "coverage:r2:live",
                    COVERAGE_LIVE_POSTURE,
                    Some(ProviderCoverageDimension::CredentialedLivePosture),
                    CoverageState::Unsupported,
                    Some("SUPABASE_R2_DIMENSION_NOT_IMPLEMENTED"),
                ),
            ],
            SupabaseR2ProviderOutputLimits::default(),
        )
        .unwrap()
    }

    fn init_base() -> InitOutput {
        let stacks = StackDetectorRegistry::new(&[])
            .unwrap()
            .detect(std::iter::empty::<&str>(), DetectionLimits::default())
            .unwrap();
        let supabase = detect_supabase(["supabase/config.toml"], DetectionLimits::default()).unwrap();
        let mut packs = SecurityPackRegistry::new();
        register_r2_pack(&mut packs).unwrap();
        let snapshot = build_project_profile_snapshot(
            "repo:fixture",
            "sha256:fixture",
            &LanguageEcosystemDetection {
                languages: Vec::new(),
                package_ecosystems: Vec::new(),
            },
            &CiMcpConfigDetection {
                ci_systems: Vec::new(),
                mcp_configurations: Vec::new(),
            },
            &stacks,
            &supabase,
            &packs,
            "2026-09-01T00:00:00Z",
            "2026-09-01T00:00:00Z",
        )
        .unwrap();
        build_init_output(&snapshot, ".", 0).unwrap()
    }

    #[test]
    fn init_registers_real_r2_coverage_and_preserves_evidence_for_generic_authority() {
        let provider = provider_output();
        let registered = register_supabase_r2_init_output(init_base(), &provider).unwrap();

        assert_eq!(registered.evidence(), provider.evidence());
        assert!(registered.output.envelope.coverage.iter().any(|record| {
            record.coverage_id == "coverage:r2:database"
                && record.state == CoverageState::Covered
        }));
        assert!(registered.output.envelope.coverage.iter().any(|record| {
            record.coverage_id == "coverage:r2:live"
                && record.state == CoverageState::Unsupported
        }));
        assert!(!registered.output.envelope.coverage.iter().any(|record| {
            record.capability == R1_SUPABASE_STATIC_PLACEHOLDER
                && record.reason_code.as_deref() == Some(R1_PACK_NOT_RUN_REASON)
        }));
        assert!(!registered.output.human.contains(INIT_R2_STATIC_PLACEHOLDER_LINE.trim()));
        assert!(registered.output.human.contains("R2 provider coverage:"));
    }

    #[test]
    fn review_registration_does_not_mint_finding_from_provider_evidence() {
        let provider = provider_output();
        let registered = build_review_with_supabase_r2(
            CliRepository::new("sha256:repo", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
            &provider,
        )
        .unwrap();

        assert_eq!(registered.evidence(), provider.evidence());
        assert!(registered.output.findings().is_empty());
        assert_eq!(
            registered.output.envelope().coverage.len(),
            provider.coverage().len()
        );
    }

    #[test]
    fn provider_evidence_becomes_finding_only_through_generic_reconciler_authority() {
        let provider = provider_output();
        let rule = ReconciliationRule::from_runtime(
            "supabase_fixture",
            "supabase_fixture_finding",
            "Supabase fixture posture",
            "The bounded fixture posture may affect access control.",
            Severity::Medium,
        )
        .unwrap();
        let authority = ReconcilerAuthority::from_runtime(
            "sentrdel.reconciler",
            format!("sha256:{}", "a".repeat(64)),
        )
        .unwrap();
        let findings = reconcile_evidence(
            provider.evidence(),
            &rule,
            &authority,
            "2026-09-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(findings.len(), 1);

        let registered = build_review_with_supabase_r2(
            CliRepository::new("sha256:repo", ".").unwrap(),
            CliDecision::Deny,
            findings,
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
            &provider,
        )
        .unwrap();
        assert_eq!(registered.output.findings().len(), 1);
        assert_eq!(
            registered.output.findings()[0].draft().evidence_ids,
            vec![provider.evidence()[0].evidence_id().to_owned()]
        );
    }
}
