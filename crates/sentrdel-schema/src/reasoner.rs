//! Structurally restricted LLM reasoner output.

use crate::{evidence::{ConfidenceBand, EpistemicClass, Evidence, EvidenceDraft, EvidenceLocation, EvidenceSubject, EvidenceValidationError, ProducerIdentity, ProducerKind}, version::SCHEMA_V1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The reasoner public API cannot represent FACT/OBSERVATION/VERIFIED.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonerEpistemicClass {
    Inference,
    Hypothesis,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonerEvidenceDraft {
    pub producer_id: String,
    pub producer_version: String,
    pub input_digests: Vec<String>,
    pub observation: String,
    pub security_interpretation: String,
    pub category: String,
    pub epistemic_class: ReasonerEpistemicClass,
    pub confidence_band: Option<ConfidenceBand>,
    pub subjects: Vec<EvidenceSubject>,
    pub locations: Vec<EvidenceLocation>,
    pub attributes: BTreeMap<String, Value>,
    pub captured_at: String,
}

impl ReasonerEvidenceDraft {
    pub fn seal(self) -> Result<Evidence, EvidenceValidationError> {
        let class = match self.epistemic_class {
            ReasonerEpistemicClass::Inference => EpistemicClass::Inference,
            ReasonerEpistemicClass::Hypothesis => EpistemicClass::Hypothesis,
        };

        EvidenceDraft {
            schema_version: SCHEMA_V1.to_owned(),
            producer: ProducerIdentity {
                id: self.producer_id,
                version: self.producer_version,
                kind: ProducerKind::LlmReasoner,
            },
            input_digests: self.input_digests,
            observation: self.observation,
            security_interpretation: Some(self.security_interpretation),
            category: self.category,
            epistemic_class: class,
            confidence_band: self.confidence_band,
            subjects: self.subjects,
            locations: self.locations,
            attributes: self.attributes,
            reproduction: None,
            captured_at: self.captured_at,
        }
        .seal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasoner_type_exposes_only_two_epistemic_classes() {
        let encoded = serde_json::to_string(&ReasonerEpistemicClass::Inference).expect("encode");
        assert_eq!(encoded, "\"INFERENCE\"");
        assert!(serde_json::from_str::<ReasonerEpistemicClass>("\"VERIFIED\"").is_err());
        assert!(serde_json::from_str::<ReasonerEpistemicClass>("\"FACT\"").is_err());
    }
}
