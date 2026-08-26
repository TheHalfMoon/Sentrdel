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

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
};

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

/// Validated trusted metadata for one capability-scoped CoverageRecord.
///
/// Fields are private so callers cannot bypass provenance validation after
/// construction. Input digests use the binding R1 canonical SHA-256 machine
/// form (`sha256:<64 lowercase hex>`), and observation time uses the same
/// canonical UTC RFC3339 profile enforced by T028.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineCoverageContext {
    coverage_id: String,
    capability: String,
    scope: String,
    input_digests: Vec<String>,
    observed_at: String,
}

impl EngineCoverageContext {
    pub fn new(
        coverage_id: impl Into<String>,
        capability: impl Into<String>,
        scope: impl Into<String>,
        input_digests: Vec<String>,
        observed_at: impl Into<String>,
    ) -> Result<Self, EngineCoverageError> {
        let coverage_id = coverage_id.into().trim().to_owned();
        let capability = capability.into().trim().to_owned();
        let scope = scope.into().trim().to_owned();
        let observed_at = observed_at.into();

        if coverage_id.is_empty() {
            return Err(EngineCoverageError::BlankCoverageId);
        }
        if capability.is_empty() {
            return Err(EngineCoverageError::BlankCapability);
        }
        if scope.is_empty() {
            return Err(EngineCoverageError::BlankScope);
        }
        if input_digests.is_empty() {
            return Err(EngineCoverageError::MissingInputDigests);
        }

        let mut seen = BTreeSet::new();
        for digest in &input_digests {
            if !is_canonical_sha256_digest(digest) {
                return Err(EngineCoverageError::InvalidInputDigest(digest.clone()));
            }
            if !seen.insert(digest.as_str()) {
                return Err(EngineCoverageError::DuplicateInputDigest(digest.clone()));
            }
        }
        if !is_canonical_utc_rfc3339(&observed_at) {
            return Err(EngineCoverageError::InvalidObservedAt);
        }

        Ok(Self {
            coverage_id,
            capability,
            scope,
            input_digests,
            observed_at,
        })
    }

    pub fn coverage_id(&self) -> &str {
        &self.coverage_id
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn input_digests(&self) -> &[String] {
        &self.input_digests
    }

    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
}

/// Final T030 result for one actual T027 process outcome.
///
/// `Covered` is returned by this module only after the canonical T028 adapter
/// accepts the same completed process output. `RejectedOutput` retains the
/// adapter error for diagnostics while its CoverageRecord remains an explicit
/// gap. `TerminationGap` represents every non-completed T027 outcome.
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
    BlankCoverageId,
    BlankCapability,
    BlankScope,
    MissingInputDigests,
    InvalidInputDigest(String),
    DuplicateInputDigest(String),
    InvalidObservedAt,
    UndeclaredCapability(String),
    DuplicateCapabilityDeclaration(String),
}

impl fmt::Display for EngineCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankCoverageId => formatter.write_str("engine coverage id must not be blank"),
            Self::BlankCapability => {
                formatter.write_str("engine coverage capability must not be blank")
            }
            Self::BlankScope => formatter.write_str("engine coverage scope must not be blank"),
            Self::MissingInputDigests => {
                formatter.write_str("engine coverage requires trusted input provenance")
            }
            Self::InvalidInputDigest(digest) => write!(
                formatter,
                "engine coverage input digest must use canonical R1 sha256:<64 lowercase hex> form: {digest:?}"
            ),
            Self::DuplicateInputDigest(digest) => write!(
                formatter,
                "engine coverage input digest is duplicated: {digest:?}"
            ),
            Self::InvalidObservedAt => formatter.write_str(
                "engine coverage observation time must use canonical UTC RFC3339 form",
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

/// Finalize one actual T027 engine process outcome into explicit coverage.
///
/// This is the sole T030 covered path. For `Completed`, it invokes the
/// canonical T028 adapter using the exact validated input digests and
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
    validate_capability_binding(manifest, context.capability())?;

    if let Some((state, reason_code)) = gap_mapping(outcome.termination_reason()) {
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
        context.input_digests(),
        context.observed_at(),
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
        coverage_id: context.coverage_id().to_owned(),
        capability: context.capability().to_owned(),
        scope: context.scope().to_owned(),
        producer: Some(manifest.engine_id.clone()),
        provider_dimension: None,
        state,
        reason_code: reason_code.map(str::to_owned),
        details: None,
        input_digests: context.input_digests().to_vec(),
        observed_at: context.observed_at().to_owned(),
    }
}

fn is_canonical_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_utc_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(20..=30).contains(&bytes.len()) {
        return false;
    }
    for index in [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    if bytes.len() == 20 {
        if bytes[19] != b'Z' {
            return false;
        }
    } else {
        if bytes[19] != b'.' || bytes[bytes.len() - 1] != b'Z' {
            return false;
        }
        let fraction = &bytes[20..bytes.len() - 1];
        if fraction.is_empty()
            || fraction.len() > 9
            || fraction.iter().any(|byte| !byte.is_ascii_digit())
            || fraction.last() == Some(&b'0')
        {
            return false;
        }
    }

    let year = parse_ascii_u32(&bytes[0..4]);
    let month = parse_ascii_u32(&bytes[5..7]);
    let day = parse_ascii_u32(&bytes[8..10]);
    let hour = parse_ascii_u32(&bytes[11..13]);
    let minute = parse_ascii_u32(&bytes[14..16]);
    let second = parse_ascii_u32(&bytes[17..19]);
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) =
        (year, month, day, hour, minute, second)
    else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 59 || !(1..=12).contains(&month) {
        return false;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day)
}

fn parse_ascii_u32(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0u32, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::engine::NetworkRequirement;

    fn canonical_digest(fill: char) -> String {
        format!("sha256:{}", fill.to_string().repeat(64))
    }

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
        EngineCoverageContext::new(
            "coverage:fixture",
            "static-analysis",
            ".",
            vec![canonical_digest('0')],
            "2026-08-26T00:00:00Z",
        )
        .expect("valid coverage context")
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
    fn coverage_context_rejects_invalid_or_unbound_provenance() {
        assert_eq!(
            EngineCoverageContext::new(
                "coverage:fixture",
                "static-analysis",
                ".",
                Vec::new(),
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineCoverageError::MissingInputDigests)
        );
        assert_eq!(
            EngineCoverageContext::new(
                "coverage:fixture",
                "static-analysis",
                ".",
                vec!["sha256:not-a-digest".to_owned()],
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineCoverageError::InvalidInputDigest(
                "sha256:not-a-digest".to_owned()
            ))
        );
        assert_eq!(
            EngineCoverageContext::new(
                "coverage:fixture",
                "static-analysis",
                ".",
                vec![canonical_digest('0'), canonical_digest('0')],
                "2026-08-26T00:00:00Z",
            ),
            Err(EngineCoverageError::DuplicateInputDigest(canonical_digest(
                '0'
            )))
        );
        assert_eq!(
            EngineCoverageContext::new(
                "coverage:fixture",
                "static-analysis",
                ".",
                vec![canonical_digest('0')],
                "2026-08-26T00:00:00+03:00",
            ),
            Err(EngineCoverageError::InvalidObservedAt)
        );
    }

    #[test]
    fn canonical_digest_profile_rejects_uppercase_or_wrong_length() {
        assert!(is_canonical_sha256_digest(&canonical_digest('a')));
        assert!(!is_canonical_sha256_digest(&canonical_digest('A')));
        assert!(!is_canonical_sha256_digest("sha256:abc"));
        assert!(!is_canonical_sha256_digest(&format!(
            "sha512:{}",
            "0".repeat(64)
        )));
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
