//! T030 explicit external-engine termination-to-coverage mapping.
//!
//! Coverage is derived only from trusted Sentrdel process/adaptation state.
//! External engine bytes cannot select coverage state, reason codes, producer
//! identity, capability, scope, input provenance, or observation time.
//!
//! A raw `Completed` process outcome is deliberately insufficient to claim
//! `COVERED`: T028 adaptation must explicitly accept the output. Rejection of
//! output from an otherwise completed process becomes `MalformedOutput` and
//! therefore `FAILED` coverage. Non-completed process paths remain visible as
//! explicit gaps and can never masquerade as clean analysis.

use std::{error::Error, fmt};

use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    engine::{EngineManifest, TerminationReason},
};

pub const ENGINE_NON_ZERO_REASON: &str = "ENGINE_NON_ZERO";
pub const ENGINE_TIMEOUT_REASON: &str = "ENGINE_TIMEOUT";
pub const ENGINE_OUTPUT_CAP_REASON: &str = "ENGINE_OUTPUT_CAP";
pub const ENGINE_SPAWN_FAILED_REASON: &str = "ENGINE_SPAWN_FAILED";
pub const ENGINE_MALFORMED_OUTPUT_REASON: &str = "ENGINE_MALFORMED_OUTPUT";
pub const ENGINE_POLICY_BLOCKED_REASON: &str = "ENGINE_POLICY_BLOCKED";

/// Trusted metadata required to construct one capability-scoped CoverageRecord.
///
/// T030 does not invent orchestration identifiers or timestamps. The trusted
/// caller supplies those values; the engine manifest supplies producer
/// identity and declares which capability may be represented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineCoverageContext {
    pub coverage_id: String,
    pub capability: String,
    pub scope: String,
    pub input_digests: Vec<String>,
    pub observed_at: String,
}

/// Whether T028 result adaptation was applicable and, when required, whether
/// it accepted the completed process output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineAdaptationOutcome {
    /// No adaptation was attempted because the process did not complete.
    NotAttempted,
    /// T028 accepted the completed process output as canonical Evidence input.
    Accepted,
    /// T028 rejected the completed process output.
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineCoverageError {
    CompletedRequiresAdaptation,
    AdaptationAfterNonCompleted(TerminationReason),
    UndeclaredCapability(String),
    DuplicateCapabilityDeclaration(String),
}

impl fmt::Display for EngineCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompletedRequiresAdaptation => formatter.write_str(
                "completed engine process output must pass T028 adaptation before coverage can be marked covered",
            ),
            Self::AdaptationAfterNonCompleted(reason) => write!(
                formatter,
                "T028 adaptation outcome cannot be attached to non-completed engine termination: {reason:?}"
            ),
            Self::UndeclaredCapability(capability) => write!(
                formatter,
                "engine coverage capability is not declared by the trusted manifest: {capability:?}"
            ),
            Self::DuplicateCapabilityDeclaration(capability) => write!(
                formatter,
                "trusted engine manifest declares coverage capability more than once: {capability:?}"
            ),
        }
    }
}

impl Error for EngineCoverageError {}

/// Resolve the final trusted termination reason after the T027 process boundary
/// and, when applicable, the T028 adapter boundary.
///
/// This function prevents process success from becoming false coverage. A
/// completed process is final only after explicit adapter acceptance; adapter
/// rejection is represented as `MalformedOutput`. Non-completed process paths
/// must not run adaptation and retain their original termination reason.
pub fn final_engine_termination_reason(
    process_reason: &TerminationReason,
    adaptation: EngineAdaptationOutcome,
) -> Result<TerminationReason, EngineCoverageError> {
    match (process_reason, adaptation) {
        (TerminationReason::Completed, EngineAdaptationOutcome::Accepted) => {
            Ok(TerminationReason::Completed)
        }
        (TerminationReason::Completed, EngineAdaptationOutcome::Rejected) => {
            Ok(TerminationReason::MalformedOutput)
        }
        (TerminationReason::Completed, EngineAdaptationOutcome::NotAttempted) => {
            Err(EngineCoverageError::CompletedRequiresAdaptation)
        }
        (reason, EngineAdaptationOutcome::NotAttempted) => Ok(reason.clone()),
        (reason, EngineAdaptationOutcome::Accepted | EngineAdaptationOutcome::Rejected) => Err(
            EngineCoverageError::AdaptationAfterNonCompleted(reason.clone()),
        ),
    }
}

/// Emit the explicit capability-scoped CoverageRecord for one engine result.
///
/// The trusted manifest must declare the capability exactly once. Every final
/// `TerminationReason` has an explicit mapping, and every non-completed or
/// malformed path maps to a gap state. Only `Completed` after T028 acceptance
/// maps to `Covered`.
pub fn coverage_record_for_engine_result(
    manifest: &EngineManifest,
    context: &EngineCoverageContext,
    process_reason: &TerminationReason,
    adaptation: EngineAdaptationOutcome,
) -> Result<CoverageRecord, EngineCoverageError> {
    validate_capability_binding(manifest, &context.capability)?;
    let final_reason = final_engine_termination_reason(process_reason, adaptation)?;
    let (state, reason_code) = coverage_mapping(&final_reason);

    Ok(CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: context.coverage_id.clone(),
        capability: context.capability.clone(),
        scope: context.scope.clone(),
        producer: Some(manifest.engine_id.clone()),
        provider_dimension: None,
        state,
        reason_code: reason_code.map(str::to_owned),
        details: None,
        input_digests: context.input_digests.clone(),
        observed_at: context.observed_at.clone(),
    })
}

fn validate_capability_binding(
    manifest: &EngineManifest,
    capability: &str,
) -> Result<(), EngineCoverageError> {
    match manifest
        .capabilities
        .iter()
        .filter(|declared| declared.as_str() == capability)
        .count()
    {
        0 => Err(EngineCoverageError::UndeclaredCapability(
            capability.to_owned(),
        )),
        1 => Ok(()),
        _ => Err(EngineCoverageError::DuplicateCapabilityDeclaration(
            capability.to_owned(),
        )),
    }
}

fn coverage_mapping(reason: &TerminationReason) -> (CoverageState, Option<&'static str>) {
    match reason {
        TerminationReason::Completed => (CoverageState::Covered, None),
        TerminationReason::NonZero => (CoverageState::Failed, Some(ENGINE_NON_ZERO_REASON)),
        TerminationReason::Timeout => (CoverageState::TimedOut, Some(ENGINE_TIMEOUT_REASON)),
        TerminationReason::OutputCap => (CoverageState::Failed, Some(ENGINE_OUTPUT_CAP_REASON)),
        TerminationReason::SpawnFailed => {
            (CoverageState::Unavailable, Some(ENGINE_SPAWN_FAILED_REASON))
        }
        TerminationReason::MalformedOutput => {
            (CoverageState::Failed, Some(ENGINE_MALFORMED_OUTPUT_REASON))
        }
        TerminationReason::PolicyBlocked => (
            CoverageState::SkippedByPolicy,
            Some(ENGINE_POLICY_BLOCKED_REASON),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::engine::NetworkRequirement;

    fn manifest() -> EngineManifest {
        EngineManifest {
            schema_version: SCHEMA_V1.to_owned(),
            engine_id: "fixture-engine".to_owned(),
            adapter_version: "1".to_owned(),
            executable_source: "trusted-fixture".to_owned(),
            executable_digest: None,
            expected_version_constraint: None,
            input_dialects: vec!["repo".to_owned()],
            output_dialects: vec!["sentrdel-json-v1".to_owned()],
            capabilities: vec!["static-analysis".to_owned()],
            timeout_ms: 1_000,
            max_stdout_bytes: 4_096,
            max_stderr_bytes: 4_096,
            allowed_environment_names: Vec::new(),
            network_requirement: NetworkRequirement::None,
        }
    }

    fn context() -> EngineCoverageContext {
        EngineCoverageContext {
            coverage_id: "coverage:fixture".to_owned(),
            capability: "static-analysis".to_owned(),
            scope: ".".to_owned(),
            input_digests: vec!["sha256:fixture".to_owned()],
            observed_at: "2026-08-26T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn completed_process_cannot_claim_coverage_before_adapter_acceptance() {
        assert_eq!(
            coverage_record_for_engine_result(
                &manifest(),
                &context(),
                &TerminationReason::Completed,
                EngineAdaptationOutcome::NotAttempted,
            ),
            Err(EngineCoverageError::CompletedRequiresAdaptation)
        );
    }

    #[test]
    fn accepted_completed_output_is_the_only_covered_path() {
        let record = coverage_record_for_engine_result(
            &manifest(),
            &context(),
            &TerminationReason::Completed,
            EngineAdaptationOutcome::Accepted,
        )
        .expect("accepted completed output should emit coverage");

        assert_eq!(record.state, CoverageState::Covered);
        assert_eq!(record.reason_code, None);
        assert_eq!(record.producer.as_deref(), Some("fixture-engine"));
        assert_eq!(record.capability, "static-analysis");
        assert!(!record.is_gap());
    }

    #[test]
    fn rejected_completed_output_becomes_failed_malformed_output() {
        let record = coverage_record_for_engine_result(
            &manifest(),
            &context(),
            &TerminationReason::Completed,
            EngineAdaptationOutcome::Rejected,
        )
        .expect("rejected completed output should emit failed coverage");

        assert_eq!(record.state, CoverageState::Failed);
        assert_eq!(
            record.reason_code.as_deref(),
            Some(ENGINE_MALFORMED_OUTPUT_REASON)
        );
        assert!(record.is_gap());
    }

    #[test]
    fn every_non_completed_termination_emits_an_explicit_gap_state() {
        let cases = [
            (
                TerminationReason::NonZero,
                CoverageState::Failed,
                ENGINE_NON_ZERO_REASON,
            ),
            (
                TerminationReason::Timeout,
                CoverageState::TimedOut,
                ENGINE_TIMEOUT_REASON,
            ),
            (
                TerminationReason::OutputCap,
                CoverageState::Failed,
                ENGINE_OUTPUT_CAP_REASON,
            ),
            (
                TerminationReason::SpawnFailed,
                CoverageState::Unavailable,
                ENGINE_SPAWN_FAILED_REASON,
            ),
            (
                TerminationReason::MalformedOutput,
                CoverageState::Failed,
                ENGINE_MALFORMED_OUTPUT_REASON,
            ),
            (
                TerminationReason::PolicyBlocked,
                CoverageState::SkippedByPolicy,
                ENGINE_POLICY_BLOCKED_REASON,
            ),
        ];

        for (termination, expected_state, expected_reason) in cases {
            let record = coverage_record_for_engine_result(
                &manifest(),
                &context(),
                &termination,
                EngineAdaptationOutcome::NotAttempted,
            )
            .expect("non-completed termination should emit coverage");

            assert_eq!(record.state, expected_state, "termination={termination:?}");
            assert_eq!(
                record.reason_code.as_deref(),
                Some(expected_reason),
                "termination={termination:?}"
            );
            assert!(record.is_gap(), "termination={termination:?}");
        }
    }

    #[test]
    fn adaptation_cannot_be_attached_to_non_completed_termination() {
        assert_eq!(
            final_engine_termination_reason(
                &TerminationReason::Timeout,
                EngineAdaptationOutcome::Rejected,
            ),
            Err(EngineCoverageError::AdaptationAfterNonCompleted(
                TerminationReason::Timeout
            ))
        );
    }

    #[test]
    fn manifest_capability_binding_is_fail_closed() {
        let mut undeclared = context();
        undeclared.capability = "not-declared".to_owned();
        assert_eq!(
            coverage_record_for_engine_result(
                &manifest(),
                &undeclared,
                &TerminationReason::Completed,
                EngineAdaptationOutcome::Accepted,
            ),
            Err(EngineCoverageError::UndeclaredCapability(
                "not-declared".to_owned()
            ))
        );

        let mut duplicate_manifest = manifest();
        duplicate_manifest.capabilities.push("static-analysis".to_owned());
        assert_eq!(
            coverage_record_for_engine_result(
                &duplicate_manifest,
                &context(),
                &TerminationReason::Completed,
                EngineAdaptationOutcome::Accepted,
            ),
            Err(EngineCoverageError::DuplicateCapabilityDeclaration(
                "static-analysis".to_owned()
            ))
        );
    }
}
