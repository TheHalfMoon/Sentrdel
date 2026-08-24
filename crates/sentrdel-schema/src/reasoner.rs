//! Structurally restricted LLM reasoner output.

use crate::{
    evidence::{
        ConfidenceBand, EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim,
        EvidenceLocation, EvidenceSubject, EvidenceValidationError, ProducerKind,
    },
    version::SCHEMA_V1,
};
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

/// Untrusted model output. Producer identity is not model-controlled and is
/// supplied separately through a runtime `EvidenceAuthority`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReasonerEvidenceDraft {
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
    pub fn seal(
        self,
        authority: &EvidenceAuthority,
    ) -> Result<Evidence, EvidenceValidationError> {
        if authority.producer().kind != ProducerKind::LlmReasoner {
            return Err(EvidenceValidationError::ProducerAuthorityMismatch);
        }
        let class = match self.epistemic_class {
            ReasonerEpistemicClass::Inference => EpistemicClass::Inference,
            ReasonerEpistemicClass::Hypothesis => EpistemicClass::Hypothesis,
        };

        authority.seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
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
        })
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

    #[test]
    fn reasoner_cannot_use_native_rule_authority() {
        let authority = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
            .expect("authority");
        let draft = ReasonerEvidenceDraft {
            input_digests: Vec::new(),
            observation: "model observed context".to_owned(),
            security_interpretation: "possible issue".to_owned(),
            category: "fixture".to_owned(),
            epistemic_class: ReasonerEpistemicClass::Hypothesis,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            captured_at: "2026-08-24T00:00:00Z".to_owned(),
        };
        assert!(matches!(
            draft.seal(&authority),
            Err(EvidenceValidationError::ProducerAuthorityMismatch)
        ));
    }
}
