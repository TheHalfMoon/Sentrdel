//! Provider-neutral optional reasoner contract.
//!
//! Reasoners consume only explicitly bounded, caller-selected evidence context.
//! They are advisory producers: their output remains untrusted and can only be
//! converted into INFERENCE/HYPOTHESIS Evidence through `sentrdel-schema`.

pub mod local;
pub mod remote;

use sentrdel_schema::evidence::{Evidence, EvidenceAuthority, EvidenceRecord, ProducerKind};
use sentrdel_schema::reasoner::ReasonerEvidenceDraft;
use std::error::Error;
use std::fmt;

pub const DEFAULT_MAX_REASONER_EVIDENCE: usize = 64;
pub const DEFAULT_MAX_REASONER_REQUEST_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_REASONER_INSTRUCTION_BYTES: usize = 8 * 1024;
pub const REASONER_PRODUCER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReasonerLimits {
    pub max_evidence: usize,
    pub max_request_bytes: usize,
    pub max_instruction_bytes: usize,
}

impl Default for ReasonerLimits {
    fn default() -> Self {
        Self {
            max_evidence: DEFAULT_MAX_REASONER_EVIDENCE,
            max_request_bytes: DEFAULT_MAX_REASONER_REQUEST_BYTES,
            max_instruction_bytes: DEFAULT_MAX_REASONER_INSTRUCTION_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReasonerRequest {
    pub instruction: String,
    pub evidence: Vec<EvidenceRecord>,
}

impl ReasonerRequest {
    pub fn new(
        instruction: impl Into<String>,
        evidence: Vec<EvidenceRecord>,
        limits: ReasonerLimits,
    ) -> Result<Self, ReasonerRequestError> {
        let instruction = instruction.into();
        if instruction.trim().is_empty() {
            return Err(ReasonerRequestError::EmptyInstruction);
        }
        if instruction.len() > limits.max_instruction_bytes {
            return Err(ReasonerRequestError::InstructionTooLarge {
                bytes: instruction.len(),
                max: limits.max_instruction_bytes,
            });
        }
        if evidence.len() > limits.max_evidence {
            return Err(ReasonerRequestError::TooManyEvidenceRecords {
                records: evidence.len(),
                max: limits.max_evidence,
            });
        }

        let evidence_bytes = serde_json::to_vec(&evidence)
            .map_err(|error| ReasonerRequestError::Serialization(error.to_string()))?;
        let request_bytes = instruction
            .len()
            .checked_add(evidence_bytes.len())
            .ok_or(ReasonerRequestError::RequestSizeOverflow)?;
        if request_bytes > limits.max_request_bytes {
            return Err(ReasonerRequestError::RequestTooLarge {
                bytes: request_bytes,
                max: limits.max_request_bytes,
            });
        }

        Ok(Self {
            instruction,
            evidence,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReasonerRequestError {
    EmptyInstruction,
    InstructionTooLarge { bytes: usize, max: usize },
    TooManyEvidenceRecords { records: usize, max: usize },
    RequestTooLarge { bytes: usize, max: usize },
    RequestSizeOverflow,
    Serialization(String),
}

impl fmt::Display for ReasonerRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInstruction => formatter.write_str("reasoner instruction must not be empty"),
            Self::InstructionTooLarge { bytes, max } => write!(
                formatter,
                "reasoner instruction size {bytes} exceeds cap {max}"
            ),
            Self::TooManyEvidenceRecords { records, max } => write!(
                formatter,
                "reasoner evidence count {records} exceeds cap {max}"
            ),
            Self::RequestTooLarge { bytes, max } => {
                write!(formatter, "reasoner request size {bytes} exceeds cap {max}")
            }
            Self::RequestSizeOverflow => formatter.write_str("reasoner request size overflow"),
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "reasoner request serialization failed: {message}"
                )
            }
        }
    }
}

impl Error for ReasonerRequestError {}

#[derive(Debug)]
pub struct ReasonerError {
    message: String,
}

impl ReasonerError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ReasonerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ReasonerError {}

pub trait Reasoner {
    fn id(&self) -> &str;

    fn reason(
        &self,
        request: &ReasonerRequest,
    ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError>;
}

/// Run an untrusted reasoner and seal every returned draft through runtime-owned
/// LLM authority. The schema type makes FACT/OBSERVATION/VERIFIED unrepresentable
/// at this boundary, and sealing revalidates every draft before it becomes Evidence.
pub fn reason_to_evidence<R: Reasoner + ?Sized>(
    reasoner: &R,
    request: &ReasonerRequest,
) -> Result<Vec<Evidence>, ReasonerError> {
    let drafts = reasoner.reason(request)?;
    seal_reasoner_drafts(reasoner.id(), REASONER_PRODUCER_VERSION, drafts)
}

/// Seal already-decoded reasoner drafts using runtime-selected producer identity.
/// The caller may choose identity/version, but never the producer kind or a wider
/// epistemic authority.
pub fn seal_reasoner_drafts(
    producer_id: &str,
    producer_version: &str,
    drafts: Vec<ReasonerEvidenceDraft>,
) -> Result<Vec<Evidence>, ReasonerError> {
    let authority = EvidenceAuthority::from_runtime(
        producer_id,
        producer_version,
        ProducerKind::LlmReasoner,
    )
    .map_err(|error| ReasonerError::new(format!("reasoner authority rejected: {error}")))?;

    drafts
        .into_iter()
        .map(|draft| {
            draft
                .seal(&authority)
                .map_err(|error| ReasonerError::new(format!("reasoner evidence rejected: {error}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::evidence::EpistemicClass;
    use sentrdel_schema::reasoner::{ReasonerEpistemicClass, ReasonerEvidenceDraft};
    use std::collections::BTreeMap;

    struct FixtureReasoner {
        drafts: Vec<ReasonerEvidenceDraft>,
    }

    impl Reasoner for FixtureReasoner {
        fn id(&self) -> &str {
            "fixture-reasoner"
        }

        fn reason(
            &self,
            _request: &ReasonerRequest,
        ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
            Ok(self.drafts.clone())
        }
    }

    fn draft(class: ReasonerEpistemicClass) -> ReasonerEvidenceDraft {
        ReasonerEvidenceDraft {
            input_digests: vec!["sha256:fixture-input".to_owned()],
            observation: "model-derived advisory statement".to_owned(),
            security_interpretation: "possible security relevance".to_owned(),
            category: "reasoner.fixture".to_owned(),
            epistemic_class: class,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            captured_at: "2026-08-29T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn reasoner_output_seals_only_as_inference_or_hypothesis() {
        let reasoner = FixtureReasoner {
            drafts: vec![
                draft(ReasonerEpistemicClass::Inference),
                draft(ReasonerEpistemicClass::Hypothesis),
            ],
        };
        let request = ReasonerRequest::new("summarize evidence", Vec::new(), ReasonerLimits::default())
            .expect("bounded request");

        let evidence = reason_to_evidence(&reasoner, &request).expect("sealed evidence");
        assert_eq!(evidence.len(), 2);
        assert!(evidence.iter().all(|item| item.producer().kind == ProducerKind::LlmReasoner));
        assert_eq!(evidence[0].claim().epistemic_class, EpistemicClass::Inference);
        assert_eq!(evidence[1].claim().epistemic_class, EpistemicClass::Hypothesis);
    }

    #[test]
    fn invalid_reasoner_draft_is_rejected_before_evidence_exists() {
        let mut invalid = draft(ReasonerEpistemicClass::Inference);
        invalid.observation.clear();

        let error = seal_reasoner_drafts(
            "fixture-reasoner",
            REASONER_PRODUCER_VERSION,
            vec![invalid],
        )
        .expect_err("empty observation must fail closed");
        assert!(error.to_string().contains("reasoner evidence rejected"));
    }

    #[test]
    fn runtime_reasoner_identity_must_be_non_empty() {
        let error = seal_reasoner_drafts("", REASONER_PRODUCER_VERSION, vec![draft(ReasonerEpistemicClass::Hypothesis)])
            .expect_err("blank runtime producer id must fail closed");
        assert!(error.to_string().contains("reasoner authority rejected"));
    }
}
