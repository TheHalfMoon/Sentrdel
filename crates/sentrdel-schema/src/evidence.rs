//! Canonical immutable Evidence types and producer-authority validation.

use crate::{
    canonical::{CanonicalError, content_id},
    version::SCHEMA_V1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error, fmt};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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

/// Runtime-selected producer capability. It is deliberately not serializable or
/// deserializable; untrusted scanner/model/repository bytes cannot choose their
/// own producer kind or identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceAuthority {
    producer: ProducerIdentity,
}

impl EvidenceAuthority {
    pub fn from_runtime(
        id: impl Into<String>,
        version: impl Into<String>,
        kind: ProducerKind,
    ) -> Result<Self, EvidenceValidationError> {
        let producer = ProducerIdentity {
            id: id.into(),
            version: version.into(),
            kind,
        };
        if producer.id.trim().is_empty() || producer.version.trim().is_empty() {
            return Err(EvidenceValidationError::EmptyProducer);
        }
        Ok(Self { producer })
    }

    pub fn producer(&self) -> &ProducerIdentity {
        &self.producer
    }

    pub fn seal(&self, claim: EvidenceClaim) -> Result<Evidence, EvidenceValidationError> {
        validate_claim(&claim, &self.producer.kind)?;
        let unsigned = EvidenceUnsigned {
            producer: &self.producer,
            claim: &claim,
        };
        let evidence_id = content_id("evidence", &unsigned)?;
        Ok(Evidence {
            evidence_id,
            producer: self.producer.clone(),
            claim,
        })
    }
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

/// Untrusted producer claim. Producer identity/kind are intentionally absent;
/// they are injected only from `EvidenceAuthority`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClaim {
    pub schema_version: String,
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

/// Authoritative sealed Evidence. It cannot be deserialized directly and its
/// fields are private.
#[derive(Clone, Debug, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    evidence_id: String,
    producer: ProducerIdentity,
    #[serde(flatten)]
    claim: EvidenceClaim,
}

/// Untrusted wire/persistence representation. Acceptance requires the expected
/// runtime producer authority and canonical ID verification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub producer: ProducerIdentity,
    pub claim: EvidenceClaim,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceValidationError {
    UnsupportedSchemaVersion(String),
    EmptyProducer,
    EmptyObservation,
    ProducerAuthorityMismatch,
    FactContainsInterpretation,
    LlmAuthorityEscalation(EpistemicClass),
    VerifiedNotAuthorizedInR1,
    RuntimeAuthorityMismatch(EpistemicClass),
    ForgedEvidenceId,
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
            Self::ProducerAuthorityMismatch => {
                write!(
                    f,
                    "evidence producer does not match trusted runtime authority"
                )
            }
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
            Self::RuntimeAuthorityMismatch(class) => {
                write!(
                    f,
                    "producer kind is not authorized to emit epistemic class {class:?}"
                )
            }
            Self::ForgedEvidenceId => {
                write!(f, "evidence id does not match validated canonical content")
            }
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

impl Evidence {
    pub fn try_from_record(
        record: EvidenceRecord,
        authority: &EvidenceAuthority,
    ) -> Result<Self, EvidenceValidationError> {
        if record.producer != authority.producer {
            return Err(EvidenceValidationError::ProducerAuthorityMismatch);
        }
        let expected_id = record.evidence_id;
        let evidence = authority.seal(record.claim)?;
        if evidence.evidence_id != expected_id {
            return Err(EvidenceValidationError::ForgedEvidenceId);
        }
        Ok(evidence)
    }

    pub fn to_record(&self) -> EvidenceRecord {
        EvidenceRecord {
            evidence_id: self.evidence_id.clone(),
            producer: self.producer.clone(),
            claim: self.claim.clone(),
        }
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn producer(&self) -> &ProducerIdentity {
        &self.producer
    }

    pub fn claim(&self) -> &EvidenceClaim {
        &self.claim
    }

    pub fn verify_identity(&self) -> Result<bool, EvidenceValidationError> {
        validate_claim(&self.claim, &self.producer.kind)?;
        let unsigned = EvidenceUnsigned {
            producer: &self.producer,
            claim: &self.claim,
        };
        Ok(content_id("evidence", &unsigned)? == self.evidence_id)
    }
}

#[derive(Serialize)]
struct EvidenceUnsigned<'a> {
    producer: &'a ProducerIdentity,
    claim: &'a EvidenceClaim,
}

fn validate_claim(
    claim: &EvidenceClaim,
    producer_kind: &ProducerKind,
) -> Result<(), EvidenceValidationError> {
    if claim.schema_version != SCHEMA_V1 {
        return Err(EvidenceValidationError::UnsupportedSchemaVersion(
            claim.schema_version.clone(),
        ));
    }
    if claim.observation.trim().is_empty() {
        return Err(EvidenceValidationError::EmptyObservation);
    }
    if claim.epistemic_class == EpistemicClass::Fact && claim.security_interpretation.is_some() {
        return Err(EvidenceValidationError::FactContainsInterpretation);
    }
    if producer_kind == &ProducerKind::LlmReasoner
        && !matches!(
            claim.epistemic_class,
            EpistemicClass::Inference | EpistemicClass::Hypothesis
        )
    {
        return Err(EvidenceValidationError::LlmAuthorityEscalation(
            claim.epistemic_class.clone(),
        ));
    }
    if claim.epistemic_class == EpistemicClass::Verified {
        return Err(EvidenceValidationError::VerifiedNotAuthorizedInR1);
    }
    if claim.epistemic_class == EpistemicClass::Observation
        && producer_kind != &ProducerKind::RuntimeTest
    {
        return Err(EvidenceValidationError::RuntimeAuthorityMismatch(
            claim.epistemic_class.clone(),
        ));
    }
    if producer_kind == &ProducerKind::RuntimeTest
        && !matches!(
            claim.epistemic_class,
            EpistemicClass::Observation | EpistemicClass::Contradiction
        )
    {
        return Err(EvidenceValidationError::RuntimeAuthorityMismatch(
            claim.epistemic_class.clone(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(class: EpistemicClass) -> EvidenceClaim {
        EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
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
    fn seal_controls_identity_and_producer() {
        let authority = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
            .expect("authority");
        let evidence = authority.seal(claim(EpistemicClass::Fact)).expect("seal");
        assert_eq!(evidence.producer(), authority.producer());
        assert!(evidence.verify_identity().expect("verify"));
    }

    #[test]
    fn forged_record_or_producer_is_rejected() {
        let native = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
            .expect("authority");
        let external = EvidenceAuthority::from_runtime("engine", "1", ProducerKind::ExternalEngine)
            .expect("authority");
        let evidence = native.seal(claim(EpistemicClass::Fact)).expect("seal");
        let mut record = evidence.to_record();
        record.evidence_id = "sha256:forged".to_owned();
        assert!(matches!(
            Evidence::try_from_record(record, &native),
            Err(EvidenceValidationError::ForgedEvidenceId)
        ));
        let record = evidence.to_record();
        assert!(matches!(
            Evidence::try_from_record(record, &external),
            Err(EvidenceValidationError::ProducerAuthorityMismatch)
        ));
    }

    #[test]
    fn llm_fact_and_verified_are_rejected() {
        let llm = EvidenceAuthority::from_runtime("llm", "1", ProducerKind::LlmReasoner)
            .expect("authority");
        assert!(matches!(
            llm.seal(claim(EpistemicClass::Fact)),
            Err(EvidenceValidationError::LlmAuthorityEscalation(
                EpistemicClass::Fact
            ))
        ));
        assert!(matches!(
            llm.seal(claim(EpistemicClass::Verified)),
            Err(EvidenceValidationError::LlmAuthorityEscalation(
                EpistemicClass::Verified
            )) | Err(EvidenceValidationError::VerifiedNotAuthorizedInR1)
        ));
    }

    #[test]
    fn runtime_observation_authority_is_exclusive() {
        let runtime = EvidenceAuthority::from_runtime("runtime", "1", ProducerKind::RuntimeTest)
            .expect("runtime authority");
        let external =
            EvidenceAuthority::from_runtime("engine", "1", ProducerKind::ExternalEngine)
                .expect("external authority");

        assert!(runtime.seal(claim(EpistemicClass::Observation)).is_ok());
        assert!(matches!(
            external.seal(claim(EpistemicClass::Observation)),
            Err(EvidenceValidationError::RuntimeAuthorityMismatch(
                EpistemicClass::Observation
            ))
        ));
    }

    #[test]
    fn fact_cannot_hide_semantic_interpretation() {
        let native = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
            .expect("authority");
        let mut value = claim(EpistemicClass::Fact);
        value.security_interpretation = Some("this proves SSRF".to_owned());
        assert!(matches!(
            native.seal(value),
            Err(EvidenceValidationError::FactContainsInterpretation)
        ));
    }
}
