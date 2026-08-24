//! Canonical immutable Evidence types and producer-authority validation.

use crate::{canonical::{content_id, CanonicalError}, version::SCHEMA_V1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProducerKind {
    NativeRule,
    CompilerIndex,
    ExternalEngine,
    RuntimeTest,
    LlmReasoner,
    Human,
    System,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicClass {
    Fact,
    Inference,
    Hypothesis,
    Observation,
    Verified,
    Contradiction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProducerIdentity {
    pub id: String,
    pub version: String,
    pub kind: ProducerKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSubject {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLocation {
    pub repo_relative_path: String,
    pub start_line: Option<u64>,
    pub start_column: Option<u64>,
    pub end_line: Option<u64>,
    pub end_column: Option<u64>,
    pub symbol: Option<String>,
    pub content_digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReproductionMetadata {
    pub method: String,
    pub input_digest: Option<String>,
    pub notes: Option<String>,
}

/// Unsealed producer submission. The canonical ID is not caller-controlled.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDraft {
    pub schema_version: String,
    pub producer: ProducerIdentity,
    pub input_digests: Vec<String>,
    /// Direct bounded observation or the primary claim text.
    pub observation: String,
    /// Optional explicit interpretation kept separate from raw observation.
    pub security_interpretation: Option<String>,
    pub category: String,
    pub epistemic_class: EpistemicClass,
    pub confidence_band: Option<ConfidenceBand>,
    pub subjects: Vec<EvidenceSubject>,
    pub locations: Vec<EvidenceLocation>,
    pub attributes: BTreeMap<String, Value>,
    pub reproduction: Option<ReproductionMetadata>,
    pub captured_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub evidence_id: String,
    #[serde(flatten)]
    pub draft: EvidenceDraft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceValidationError {
    UnsupportedSchemaVersion(String),
    EmptyProducer,
    EmptyObservation,
    FactContainsInterpretation,
    LlmAuthorityEscalation(EpistemicClass),
    VerifiedNotAuthorizedInR1,
    RuntimeVerifiedNotAuthorizedInR1,
    Canonical(String),
}

impl fmt::Display for EvidenceValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(version) => {
                write!(f, "unsupported evidence schema version: {version}")
            }
            Self::EmptyProducer => write!(f, "evidence producer id/version must not be empty"),
            Self::EmptyObservation => write!(f, "evidence observation must not be empty"),
            Self::FactContainsInterpretation => write!(
                f,
                "FACT evidence must contain only a direct bounded observation; put semantic meaning in separate INFERENCE evidence"
            ),
            Self::LlmAuthorityEscalation(class) => {
                write!(f, "LLM reasoner cannot emit epistemic class {class:?}")
            }
            Self::VerifiedNotAuthorizedInR1 => {
                write!(f, "VERIFIED evidence has no authorized producer in R1")
            }
            Self::RuntimeVerifiedNotAuthorizedInR1 => write!(
                f,
                "runtime-test producer may emit OBSERVATION in R1 but not VERIFIED"
            ),
            Self::Canonical(message) => write!(f, "canonicalization failed: {message}"),
        }
    }
}

impl Error for EvidenceValidationError {}

impl From<CanonicalError> for EvidenceValidationError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value.to_string())
    }
}

impl EvidenceDraft {
    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if self.schema_version != SCHEMA_V1 {
            return Err(EvidenceValidationError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }
        if self.producer.id.trim().is_empty() || self.producer.version.trim().is_empty() {
            return Err(EvidenceValidationError::EmptyProducer);
        }
        if self.observation.trim().is_empty() {
            return Err(EvidenceValidationError::EmptyObservation);
        }
        if self.epistemic_class == EpistemicClass::Fact
            && self.security_interpretation.is_some()
        {
            return Err(EvidenceValidationError::FactContainsInterpretation);
        }
        if self.producer.kind == ProducerKind::LlmReasoner
            && !matches!(
                self.epistemic_class,
                EpistemicClass::Inference | EpistemicClass::Hypothesis
            )
        {
            return Err(EvidenceValidationError::LlmAuthorityEscalation(
                self.epistemic_class.clone(),
            ));
        }
        if self.epistemic_class == EpistemicClass::Verified {
            return Err(EvidenceValidationError::VerifiedNotAuthorizedInR1);
        }
        if self.producer.kind == ProducerKind::RuntimeTest
            && self.epistemic_class == EpistemicClass::Verified
        {
            return Err(EvidenceValidationError::RuntimeVerifiedNotAuthorizedInR1);
        }
        Ok(())
    }

    pub fn seal(self) -> Result<Evidence, EvidenceValidationError> {
        self.validate()?;
        let evidence_id = content_id("evidence", &self)?;
        Ok(Evidence {
            evidence_id,
            draft: self,
        })
    }
}

impl Evidence {
    pub fn verify_identity(&self) -> Result<bool, EvidenceValidationError> {
        self.draft.validate()?;
        Ok(content_id("evidence", &self.draft)? == self.evidence_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(kind: ProducerKind, class: EpistemicClass) -> EvidenceDraft {
        EvidenceDraft {
            schema_version: SCHEMA_V1.to_owned(),
            producer: ProducerIdentity {
                id: "fixture".to_owned(),
                version: "1".to_owned(),
                kind,
            },
            input_digests: vec!["sha256:input".to_owned()],
            observation: "bounded observation".to_owned(),
            security_interpretation: None,
            category: "fixture".to_owned(),
            epistemic_class: class,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: "2026-08-24T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn seal_controls_identity() {
        let evidence = draft(ProducerKind::NativeRule, EpistemicClass::Fact)
            .seal()
            .expect("seal");
        assert!(evidence.verify_identity().expect("verify"));
    }

    #[test]
    fn llm_fact_is_rejected() {
        let error = draft(ProducerKind::LlmReasoner, EpistemicClass::Fact)
            .seal()
            .expect_err("LLM FACT must fail");
        assert!(matches!(
            error,
            EvidenceValidationError::LlmAuthorityEscalation(EpistemicClass::Fact)
        ));
    }

    #[test]
    fn fact_cannot_hide_semantic_interpretation() {
        let mut value = draft(ProducerKind::NativeRule, EpistemicClass::Fact);
        value.security_interpretation = Some("this proves SSRF".to_owned());
        assert!(matches!(
            value.seal().expect_err("semantic FACT must fail"),
            EvidenceValidationError::FactContainsInterpretation
        ));
    }
}
