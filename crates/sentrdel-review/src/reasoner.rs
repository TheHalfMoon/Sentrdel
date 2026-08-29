//! Provider-neutral optional reasoner contract.
//!
//! Reasoners consume only explicitly bounded, caller-selected evidence context.
//! They are advisory producers: their output remains untrusted and can only be
//! converted into INFERENCE/HYPOTHESIS Evidence through `sentrdel-schema`.

pub mod local;
pub mod remote;

use sentrdel_schema::evidence::EvidenceRecord;
use sentrdel_schema::reasoner::ReasonerEvidenceDraft;
use std::error::Error;
use std::fmt;

pub const DEFAULT_MAX_REASONER_EVIDENCE: usize = 64;
pub const DEFAULT_MAX_REASONER_REQUEST_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_REASONER_INSTRUCTION_BYTES: usize = 8 * 1024;

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
