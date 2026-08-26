//! T030 explicit external-engine termination-to-coverage finalization.
//!
//! Coverage is derived only from trusted Sentrdel T027 process state and T028
//! adaptation. External engine bytes cannot select coverage state, reason
//! codes, producer identity, capability, scope, input provenance, or time.
//!
//! A raw `Completed` process outcome is deliberately insufficient to claim
//! `COVERED`. The sole T030 finalizer invokes the canonical T028 adapter for a
//! completed process; adapter acceptance yields `COVERED`, while adapter
//! rejection yields an explicit `FAILED` / malformed-output coverage gap. Every
//! non-completed T027 termination is mapped directly to an explicit gap.

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

/// Final T030 result for one actual T027 process outcome.
///
/// `Covered` is constructible by this module only after the canonical T028
/// adapter accepts the same completed process output. `RejectedOutput` retains
/// the adapter error for diagnostics while its CoverageRecord remains an
/// explicit gap. `TerminationGap` represents every non-completed T027 outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineCoverageOutcome {
    Covered {
        evidence: Vec<Evidence>,
        coverage: CoverageRecord,
    },
    RejectedOutput {
        coverage: CoverageRecord,
        adapter_error: EngineAdapterError,
    },
    TerminationGap {
        coverage: CoverageRecord,
    },
}

impl EngineCoverageOutcome {
    pub fn coverage(&self) -> &CoverageRecord {
        match self {
            Self::Covered { coverage, .. }
            | Self::RejectedOutput { coverage, .. }
            | Self::TerminationGap { coverage } => coverage,
        }
    }

    pub fn evidence(&self) -> &[Evidence] {
        match self {
            Self::Covered { evidence, .. } => evidence,
            Self::RejectedOutput { .. } | Self::TerminationGap { .. } => &[],
        }
    }

    pub fn adapter_error(&self) -> Option<&EngineAdapterError> {
        match self {
            Self::RejectedOutput { adapter_error, .. } => Some(adapter_error),
            Self::Covered { .. } | Self::TerminationGap { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineCoverageError {
    UndeclaredCapability(String),
    DuplicateCapabilityDeclaration(String),
}

impl fmt::Display for EngineCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

/// Finalize one actual T027 engine process outcome into explicit coverage.
///
/// This is the sole T030 covered path. For `Completed`, it invokes the
/// canonical T028 adapter using the exact trusted manifest, input digests, and
/// observation time carried by the coverage context. Successful adaptation
/// yields `COVERED`. Any adapter rejection yields a `FAILED` malformed-output
/// gap and retains the typed adapter error outside the persisted coverage
/// record. Non-completed termination reasons bypass parsing and map directly to
/// explicit gap states.
pub fn finalize_engine_coverage(
    manifest: &EngineManifest,
    dialect: EngineOutputDialect,
    outcome: &EngineProcessOutcome,
    authority: &EvidenceAuthority,
    limits: &EngineLimits,
    context: &EngineCoverageContext,
) -> Result<EngineCoverageOutcome, EngineCoverageError> {
    validate_capability_binding(manifest, &context.capability)?;

    if outcome.termination_reason() != &TerminationReason::Completed {
        let (state, reason_code) = gap_mapping(outcome.termination_reason())
            .expect("non-completed termination must have an exhaustive T030 gap mapping");
        return Ok(EngineCoverageOutcome::TerminationGap {
            coverage: build_record(manifest, context, state, Some(reason_code)),
        });
    }

    match adapt_engine_output(
        manifest,
        dialect,
        outcome,
        authority,
        limits,
        &context.input_digests,
        &context.observed_at,
    ) {
        Ok(evidence) => Ok(EngineCoverageOutcome::Covered {
            evidence,
            coverage: build_record(manifest, context, CoverageState::Covered, None),
        }),
        Err(adapter_error) => Ok(EngineCoverageOutcome::RejectedOutput {
            coverage: build_record(
                manifest,
                context,
                CoverageState::Failed,
                Some(ENGINE_MALFORMED_OUTPUT_REASON),
            ),
            adapter_error,
        }),
    }
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

fn gap_mapping(termination: &TerminationReason) -> Option<(CoverageState, &'static str)> {
    match termination {
        TerminationReason::Completed => None,
        TerminationReason::NonZero => Some((CoverageState::Failed, ENGINE_NON_ZERO_REASON)),
        TerminationReason::Timeout => Some((CoverageState::TimedOut, ENGINE_TIMEOUT_REASON)),
        TerminationReason::OutputCap => Some((CoverageState::Failed, ENGINE_OUTPUT_CAP_REASON)),
        TerminationReason::SpawnFailed => {
            Some((CoverageState::Unavailable, ENGINE_SPAWN_FAILED_REASON))
        }
        TerminationReason::MalformedOutput => {
            Some((CoverageState::Failed, ENGINE_MALFORMED_OUTPUT_REASON))
        }
        TerminationReason::PolicyBlocked => Some((
            CoverageState::SkippedByPolicy,
            ENGINE_POLICY_BLOCKED_REASON,
        )),
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

    #[test]
    fn completed_is_not_a_gap_mapping() {
        assert_eq!(gap_mapping(&TerminationReason::Completed), None);
    }

    #[test]
    fn every_non_completed_termination_has_explicit_gap_mapping() {
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
            let (state, reason_code) = gap_mapping(&termination)
                .expect("non-completed termination must have an explicit gap mapping");
            assert_eq!(state, expected_state, "termination={termination:?}");
            assert_eq!(reason_code, expected_reason, "termination={termination:?}");
            assert_ne!(state, CoverageState::Covered, "termination={termination:?}");
        }
    }

    #[test]
    fn built_gap_records_never_look_complete() {
        for termination in [
            TerminationReason::NonZero,
            TerminationReason::Timeout,
            TerminationReason::OutputCap,
            TerminationReason::SpawnFailed,
            TerminationReason::MalformedOutput,
            TerminationReason::PolicyBlocked,
        ] {
            let (state, reason_code) = gap_mapping(&termination).expect("gap mapping");
            let record = build_record(&manifest(), &context(), state, Some(reason_code));
            assert!(record.is_gap(), "termination={termination:?}");
            assert!(record.reason_code.is_some(), "termination={termination:?}");
        }
    }

    #[test]
    fn manifest_capability_binding_is_fail_closed() {
        assert_eq!(
            validate_capability_binding(&manifest(), "not-declared"),
            Err(EngineCoverageError::UndeclaredCapability(
                "not-declared".to_owned()
            ))
        );

        let mut duplicate_manifest = manifest();
        duplicate_manifest
            .capabilities
            .push("static-analysis".to_owned());
        assert_eq!(
            validate_capability_binding(&duplicate_manifest, "static-analysis"),
            Err(EngineCoverageError::DuplicateCapabilityDeclaration(
                "static-analysis".to_owned()
            ))
        );
    }
}
