//! Optional review-reasoning orchestration for the R1 CLI.
//!
//! Native review is authoritative and deterministic before this layer runs.
//! This module can append advisory LLM Evidence and explicit coverage only; it
//! cannot mutate canonical Findings, the native review decision, or policy.

use sentrdel_cli::reasoning::ReviewReasoningFlags;
use sentrdel_review::reasoner::{Reasoner, ReasonerRequest, reason_to_evidence};
use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState},
    evidence::Evidence,
};
use std::{error::Error, fmt};

const REASONER_COVERAGE_ID: &str = "coverage:review:optional-reasoner";
const REASONER_CAPABILITY: &str = "optional_llm_reasoning";
const MAX_REASONER_ID_BYTES: usize = 512;
const MAX_OBSERVED_AT_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReasonerNetworkAccess {
    OfflineOnly,
    NetworkRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewReasoningState {
    Disabled,
    Covered,
    SkippedByPolicy,
    Failed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReviewReasoningOutcome {
    pub state: ReviewReasoningState,
    pub evidence: Vec<Evidence>,
    pub coverage: Option<CoverageRecord>,
}

impl ReviewReasoningOutcome {
    fn disabled() -> Self {
        Self {
            state: ReviewReasoningState::Disabled,
            evidence: Vec::new(),
            coverage: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewReasoningConfigError {
    InvalidReasonerId,
    InvalidObservedAt,
}

impl fmt::Display for ReviewReasoningConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReasonerId => formatter.write_str(
                "optional review reasoner id must be bounded, non-blank text without controls",
            ),
            Self::InvalidObservedAt => formatter.write_str(
                "optional review reasoning observed_at must be bounded, non-blank text without controls",
            ),
        }
    }
}

impl Error for ReviewReasoningConfigError {}

pub fn run_optional_reasoning<R: Reasoner + ?Sized>(
    flags: ReviewReasoningFlags,
    network_access: ReasonerNetworkAccess,
    reasoner: &R,
    request: &ReasonerRequest,
    observed_at: &str,
) -> Result<ReviewReasoningOutcome, ReviewReasoningConfigError> {
    if !flags.reason_enabled() {
        return Ok(ReviewReasoningOutcome::disabled());
    }

    let producer_id = reasoner.id();
    validate_reasoner_id(producer_id)?;
    validate_observed_at(observed_at)?;
    let input_digests = normalized_input_ids(request);

    if flags.no_network() && network_access == ReasonerNetworkAccess::NetworkRequired {
        return Ok(ReviewReasoningOutcome {
            state: ReviewReasoningState::SkippedByPolicy,
            evidence: Vec::new(),
            coverage: Some(coverage_record(
                producer_id,
                CoverageState::SkippedByPolicy,
                Some("REASONER_DISABLED_BY_NO_NETWORK"),
                Some("Optional LLM reasoning was skipped because --no-network is active."),
                input_digests,
                observed_at,
            )),
        });
    }

    match reason_to_evidence(reasoner, request) {
        Ok(evidence) => Ok(ReviewReasoningOutcome {
            state: ReviewReasoningState::Covered,
            evidence,
            coverage: Some(coverage_record(
                producer_id,
                CoverageState::Covered,
                None,
                None,
                input_digests,
                observed_at,
            )),
        }),
        Err(_) => Ok(ReviewReasoningOutcome {
            state: ReviewReasoningState::Failed,
            evidence: Vec::new(),
            coverage: Some(coverage_record(
                producer_id,
                CoverageState::Failed,
                Some("REASONER_FAILED"),
                Some("Optional LLM reasoning failed; native review output remains authoritative."),
                input_digests,
                observed_at,
            )),
        }),
    }
}

fn coverage_record(
    producer_id: &str,
    state: CoverageState,
    reason_code: Option<&str>,
    details: Option<&str>,
    input_digests: Vec<String>,
    observed_at: &str,
) -> CoverageRecord {
    CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: REASONER_COVERAGE_ID.to_owned(),
        capability: REASONER_CAPABILITY.to_owned(),
        scope: ".".to_owned(),
        producer: Some(producer_id.to_owned()),
        provider_dimension: None,
        state,
        reason_code: reason_code.map(str::to_owned),
        details: details.map(str::to_owned),
        input_digests,
        observed_at: observed_at.to_owned(),
    }
}

fn normalized_input_ids(request: &ReasonerRequest) -> Vec<String> {
    let mut ids = request
        .evidence
        .iter()
        .map(|record| record.evidence_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn validate_reasoner_id(value: &str) -> Result<(), ReviewReasoningConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_REASONER_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ReviewReasoningConfigError::InvalidReasonerId);
    }
    Ok(())
}

fn validate_observed_at(value: &str) -> Result<(), ReviewReasoningConfigError> {
    if value.trim().is_empty()
        || value.len() > MAX_OBSERVED_AT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ReviewReasoningConfigError::InvalidObservedAt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_cli::{CliDecision, CliRepository, CliTiming, review::ReviewOutput};
    use sentrdel_review::reasoner::{ReasonerError, ReasonerLimits};
    use sentrdel_schema::evidence::{
        EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind,
    };
    use sentrdel_schema::reasoner::{ReasonerEpistemicClass, ReasonerEvidenceDraft};
    use std::{cell::Cell, collections::BTreeMap};

    struct CountingReasoner {
        id: &'static str,
        fail: bool,
        calls: Cell<usize>,
    }

    impl CountingReasoner {
        fn new(id: &'static str, fail: bool) -> Self {
            Self {
                id,
                fail,
                calls: Cell::new(0),
            }
        }
    }

    impl Reasoner for CountingReasoner {
        fn id(&self) -> &str {
            self.id
        }

        fn reason(
            &self,
            request: &ReasonerRequest,
        ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                return Err(ReasonerError::new("untrusted provider failure detail"));
            }
            Ok(vec![ReasonerEvidenceDraft {
                input_digests: request
                    .evidence
                    .iter()
                    .map(|record| record.evidence_id.clone())
                    .collect(),
                observation: "model advisory".to_owned(),
                security_interpretation: "possible impact".to_owned(),
                category: "reasoner.t076-fixture".to_owned(),
                epistemic_class: ReasonerEpistemicClass::Hypothesis,
                confidence_band: None,
                subjects: Vec::new(),
                locations: Vec::new(),
                attributes: BTreeMap::new(),
                captured_at: "2026-08-29T00:00:00Z".to_owned(),
            }])
        }
    }

    fn evidence_record() -> sentrdel_schema::evidence::EvidenceRecord {
        let authority = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
            .expect("authority");
        authority
            .seal(EvidenceClaim {
                schema_version: SCHEMA_V1.to_owned(),
                input_digests: vec!["sha256:fixture".to_owned()],
                observation: "deterministic observation".to_owned(),
                security_interpretation: None,
                category: "fixture".to_owned(),
                epistemic_class: EpistemicClass::Fact,
                confidence_band: None,
                subjects: Vec::new(),
                locations: Vec::new(),
                attributes: BTreeMap::new(),
                reproduction: None,
                captured_at: "2026-08-29T00:00:00Z".to_owned(),
            })
            .expect("evidence")
            .to_record()
    }

    fn request() -> ReasonerRequest {
        ReasonerRequest::new(
            "Provide advisory context only.",
            vec![evidence_record()],
            ReasonerLimits::default(),
        )
        .expect("bounded request")
    }

    #[test]
    fn disabled_reasoning_never_calls_provider_and_emits_no_coverage() {
        let reasoner = CountingReasoner::new("fixture", false);
        let outcome = run_optional_reasoning(
            ReviewReasoningFlags::new(false, false),
            ReasonerNetworkAccess::NetworkRequired,
            &reasoner,
            &request(),
            "ignored while disabled\n",
        )
        .expect("disabled reasoning");

        assert_eq!(outcome.state, ReviewReasoningState::Disabled);
        assert!(outcome.evidence.is_empty());
        assert!(outcome.coverage.is_none());
        assert_eq!(reasoner.calls.get(), 0);
    }

    #[test]
    fn no_network_skips_network_reasoner_without_invocation() {
        let reasoner = CountingReasoner::new("remote-fixture", false);
        let request = request();
        let expected_input_id = request.evidence[0].evidence_id.clone();
        let outcome = run_optional_reasoning(
            ReviewReasoningFlags::new(true, true),
            ReasonerNetworkAccess::NetworkRequired,
            &reasoner,
            &request,
            "2026-08-29T00:00:00Z",
        )
        .expect("policy skip");

        assert_eq!(outcome.state, ReviewReasoningState::SkippedByPolicy);
        assert!(outcome.evidence.is_empty());
        assert_eq!(reasoner.calls.get(), 0);
        let coverage = outcome.coverage.expect("coverage");
        assert_eq!(coverage.state, CoverageState::SkippedByPolicy);
        assert_eq!(
            coverage.reason_code.as_deref(),
            Some("REASONER_DISABLED_BY_NO_NETWORK")
        );
        assert_eq!(coverage.input_digests, vec![expected_input_id]);
    }

    #[test]
    fn no_network_allows_explicit_offline_reasoner() {
        let reasoner = CountingReasoner::new("offline-fixture", false);
        let outcome = run_optional_reasoning(
            ReviewReasoningFlags::new(true, true),
            ReasonerNetworkAccess::OfflineOnly,
            &reasoner,
            &request(),
            "2026-08-29T00:00:00Z",
        )
        .expect("offline reasoning");

        assert_eq!(reasoner.calls.get(), 1);
        assert_eq!(outcome.state, ReviewReasoningState::Covered);
        assert_eq!(outcome.evidence.len(), 1);
        assert_eq!(
            outcome.evidence[0].producer().kind,
            ProducerKind::LlmReasoner
        );
        assert_eq!(
            outcome.evidence[0].claim().epistemic_class,
            EpistemicClass::Hypothesis
        );
        assert_eq!(
            outcome.coverage.expect("coverage").state,
            CoverageState::Covered
        );
    }

    #[test]
    fn reasoner_failure_is_coverage_gap_not_native_review_failure() {
        let baseline = ReviewOutput::new(
            CliRepository::new("sha256:repo", ".").expect("repository"),
            CliDecision::Deny,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .expect("native review output");
        let before = baseline.render_json().expect("native json");
        let reasoner = CountingReasoner::new("failing-fixture", true);

        let outcome = run_optional_reasoning(
            ReviewReasoningFlags::new(true, false),
            ReasonerNetworkAccess::NetworkRequired,
            &reasoner,
            &request(),
            "2026-08-29T00:00:00Z",
        )
        .expect("optional reasoner failure is represented as coverage");

        assert_eq!(reasoner.calls.get(), 1);
        assert_eq!(outcome.state, ReviewReasoningState::Failed);
        assert!(outcome.evidence.is_empty());
        let coverage = outcome.coverage.expect("coverage");
        assert_eq!(coverage.state, CoverageState::Failed);
        assert_eq!(coverage.reason_code.as_deref(), Some("REASONER_FAILED"));
        assert_eq!(
            coverage.details.as_deref(),
            Some("Optional LLM reasoning failed; native review output remains authoritative.")
        );
        assert!(!
            coverage
                .details
                .as_deref()
                .unwrap_or_default()
                .contains("untrusted")
        );
        assert_eq!(baseline.render_json().expect("native json after"), before);
        assert_eq!(baseline.envelope().decision, CliDecision::Deny);
    }

    #[test]
    fn invalid_enabled_configuration_fails_before_provider_invocation() {
        let invalid_id = CountingReasoner::new("bad\nid", false);
        assert_eq!(
            run_optional_reasoning(
                ReviewReasoningFlags::new(true, false),
                ReasonerNetworkAccess::OfflineOnly,
                &invalid_id,
                &request(),
                "2026-08-29T00:00:00Z",
            ),
            Err(ReviewReasoningConfigError::InvalidReasonerId)
        );
        assert_eq!(invalid_id.calls.get(), 0);

        let reasoner = CountingReasoner::new("fixture", false);
        assert_eq!(
            run_optional_reasoning(
                ReviewReasoningFlags::new(true, false),
                ReasonerNetworkAccess::OfflineOnly,
                &reasoner,
                &request(),
                "bad\ntime",
            ),
            Err(ReviewReasoningConfigError::InvalidObservedAt)
        );
        assert_eq!(reasoner.calls.get(), 0);
    }
}
