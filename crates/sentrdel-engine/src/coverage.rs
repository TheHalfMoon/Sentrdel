//! T030 explicit external-engine termination-to-coverage mapping.
//!
//! Coverage is derived only from trusted Sentrdel process/adaptation state.
//! External engine bytes cannot select coverage state, reason codes, producer
//! identity, capability, scope, input provenance, or observation time.
//!
//! A raw `Completed` process outcome is deliberately insufficient to claim
//! `COVERED`. The only public covered path requires an opaque receipt that this
//! module creates only after the canonical T028 adapter accepts bounded output.
//! All non-completed and malformed-output paths remain explicit coverage gaps.

use std::{error::Error, fmt};

use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    engine::{EngineManifest, TerminationReason},
    evidence::{Evidence, EvidenceAuthority},
};

use crate::{
    adapter::{EngineAdapterError, EngineOutputDialect, adapt_engine_output},
    boundary::EngineLimits,
    runner::EngineProcessOutcome,
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

/// Opaque proof that the canonical T028 adapter accepted one completed engine
/// output under a specific trusted manifest/input/time binding.
///
/// Fields are intentionally private and there is no public constructor. Code
/// outside this crate can obtain a receipt only through
/// [`adapt_engine_output_for_coverage`], preventing a caller from fabricating
/// an "accepted" bit and converting raw process completion into `COVERED`.
#[derive(Debug, PartialEq, Eq)]
pub struct EngineAdaptationReceipt {
    engine_id: String,
    adapter_version: String,
    input_digests: Vec<String>,
    captured_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineCoverageError {
    CompletedRequiresAcceptedAdaptation,
    AdaptationReceiptManifestMismatch,
    AdaptationReceiptInputMismatch,
    AdaptationReceiptObservedAtMismatch,
    UndeclaredCapability(String),
    DuplicateCapabilityDeclaration(String),
}

impl fmt::Display for EngineCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompletedRequiresAcceptedAdaptation => formatter.write_str(
                "completed engine process output requires an opaque T028 acceptance receipt before coverage can be marked covered",
            ),
            Self::AdaptationReceiptManifestMismatch => formatter.write_str(
                "T028 adaptation receipt does not match the trusted engine manifest",
            ),
            Self::AdaptationReceiptInputMismatch => formatter.write_str(
                "T028 adaptation receipt input provenance does not match the coverage context",
            ),
            Self::AdaptationReceiptObservedAtMismatch => formatter.write_str(
                "T028 adaptation receipt capture time does not match the coverage observation time",
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

/// Run the canonical T028 adapter and mint an opaque acceptance receipt only on
/// successful adaptation.
///
/// The receipt contains only trusted manifest/provenance binding metadata; raw
/// external output is neither persisted nor copied into the receipt. Adapter
/// rejection returns the original `EngineAdapterError` and cannot mint proof.
pub fn adapt_engine_output_for_coverage(
    manifest: &EngineManifest,
    dialect: EngineOutputDialect,
    outcome: &EngineProcessOutcome,
    authority: &EvidenceAuthority,
    limits: &EngineLimits,
    input_digests: &[String],
    captured_at: &str,
) -> Result<(Vec<Evidence>, EngineAdaptationReceipt), EngineAdapterError> {
    let evidence = adapt_engine_output(
        manifest,
        dialect,
        outcome,
        authority,
        limits,
        input_digests,
        captured_at,
    )?;

    Ok((
        evidence,
        EngineAdaptationReceipt {
            engine_id: manifest.engine_id.clone(),
            adapter_version: manifest.adapter_version.clone(),
            input_digests: input_digests.to_vec(),
            captured_at: captured_at.to_owned(),
        },
    ))
}

/// Emit `COVERED` only from an opaque receipt minted by a successful T028
/// adaptation and bound to the same trusted manifest, inputs, and timestamp.
pub fn coverage_record_for_adapted_output(
    manifest: &EngineManifest,
    context: &EngineCoverageContext,
    receipt: &EngineAdaptationReceipt,
) -> Result<CoverageRecord, EngineCoverageError> {
    validate_capability_binding(manifest, &context.capability)?;
    validate_receipt_binding(manifest, context, receipt)?;

    Ok(build_record(
        manifest,
        context,
        CoverageState::Covered,
        None,
    ))
}

/// Emit an explicit gap CoverageRecord for every non-completed final engine
/// termination path.
///
/// `Completed` is rejected here by construction; callers must use
/// [`coverage_record_for_adapted_output`] with an opaque T028 acceptance
/// receipt. This prevents raw process success from masquerading as coverage.
pub fn coverage_record_for_engine_termination(
    manifest: &EngineManifest,
    context: &EngineCoverageContext,
    termination: &TerminationReason,
) -> Result<CoverageRecord, EngineCoverageError> {
    validate_capability_binding(manifest, &context.capability)?;
    let (state, reason_code) = gap_mapping(termination)?;

    Ok(build_record(
        manifest,
        context,
        state,
        Some(reason_code),
    ))
}

fn validate_receipt_binding(
    manifest: &EngineManifest,
    context: &EngineCoverageContext,
    receipt: &EngineAdaptationReceipt,
) -> Result<(), EngineCoverageError> {
    if receipt.engine_id != manifest.engine_id || receipt.adapter_version != manifest.adapter_version {
        return Err(EngineCoverageError::AdaptationReceiptManifestMismatch);
    }
    if receipt.input_digests != context.input_digests {
        return Err(EngineCoverageError::AdaptationReceiptInputMismatch);
    }
    if receipt.captured_at != context.observed_at {
        return Err(EngineCoverageError::AdaptationReceiptObservedAtMismatch);
    }
    Ok(())
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

fn gap_mapping(
    termination: &TerminationReason,
) -> Result<(CoverageState, &'static str), EngineCoverageError> {
    match termination {
        TerminationReason::Completed => Err(EngineCoverageError::CompletedRequiresAcceptedAdaptation),
        TerminationReason::NonZero => Ok((CoverageState::Failed, ENGINE_NON_ZERO_REASON)),
        TerminationReason::Timeout => Ok((CoverageState::TimedOut, ENGINE_TIMEOUT_REASON)),
        TerminationReason::OutputCap => Ok((CoverageState::Failed, ENGINE_OUTPUT_CAP_REASON)),
        TerminationReason::SpawnFailed => {
            Ok((CoverageState::Unavailable, ENGINE_SPAWN_FAILED_REASON))
        }
        TerminationReason::MalformedOutput => {
            Ok((CoverageState::Failed, ENGINE_MALFORMED_OUTPUT_REASON))
        }
        TerminationReason::PolicyBlocked => {
            Ok((CoverageState::SkippedByPolicy, ENGINE_POLICY_BLOCKED_REASON))
        }
    }
}

fn build_record(
    manifest: &EngineManifest,
    context: &EngineCoverageContext,
    state: CoverageState,
    reason_code: Option<&'static str>,
) -> CoverageRecord {
    CoverageRecord {
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

    fn receipt() -> EngineAdaptationReceipt {
        EngineAdaptationReceipt {
            engine_id: "fixture-engine".to_owned(),
            adapter_version: "1".to_owned(),
            input_digests: vec!["sha256:fixture".to_owned()],
            captured_at: "2026-08-26T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn raw_completed_termination_cannot_claim_coverage() {
        assert_eq!(
            coverage_record_for_engine_termination(
                &manifest(),
                &context(),
                &TerminationReason::Completed,
            ),
            Err(EngineCoverageError::CompletedRequiresAcceptedAdaptation)
        );
    }

    #[test]
    fn opaque_adapter_receipt_is_the_only_covered_path() {
        let record = coverage_record_for_adapted_output(&manifest(), &context(), &receipt())
            .expect("bound adapter receipt should emit coverage");

        assert_eq!(record.state, CoverageState::Covered);
        assert_eq!(record.reason_code, None);
        assert_eq!(record.producer.as_deref(), Some("fixture-engine"));
        assert_eq!(record.capability, "static-analysis");
        assert!(!record.is_gap());
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
            let record = coverage_record_for_engine_termination(&manifest(), &context(), &termination)
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
    fn adapter_receipt_is_bound_to_manifest_inputs_and_time() {
        let mut wrong_manifest = manifest();
        wrong_manifest.adapter_version = "2".to_owned();
        assert_eq!(
            coverage_record_for_adapted_output(&wrong_manifest, &context(), &receipt()),
            Err(EngineCoverageError::AdaptationReceiptManifestMismatch)
        );

        let mut wrong_inputs = context();
        wrong_inputs.input_digests = vec!["sha256:different".to_owned()];
        assert_eq!(
            coverage_record_for_adapted_output(&manifest(), &wrong_inputs, &receipt()),
            Err(EngineCoverageError::AdaptationReceiptInputMismatch)
        );

        let mut wrong_time = context();
        wrong_time.observed_at = "2026-08-26T00:00:01Z".to_owned();
        assert_eq!(
            coverage_record_for_adapted_output(&manifest(), &wrong_time, &receipt()),
            Err(EngineCoverageError::AdaptationReceiptObservedAtMismatch)
        );
    }

    #[test]
    fn manifest_capability_binding_is_fail_closed() {
        let mut undeclared = context();
        undeclared.capability = "not-declared".to_owned();
        assert_eq!(
            coverage_record_for_adapted_output(&manifest(), &undeclared, &receipt()),
            Err(EngineCoverageError::UndeclaredCapability(
                "not-declared".to_owned()
            ))
        );

        let mut duplicate_manifest = manifest();
        duplicate_manifest
            .capabilities
            .push("static-analysis".to_owned());
        assert_eq!(
            coverage_record_for_adapted_output(&duplicate_manifest, &context(), &receipt()),
            Err(EngineCoverageError::DuplicateCapabilityDeclaration(
                "static-analysis".to_owned()
            ))
        );
    }
}
