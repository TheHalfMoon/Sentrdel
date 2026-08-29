use sentrdel_review::reasoner::{
    Reasoner, ReasonerError, ReasonerLimits, ReasonerRequest, ReasonerRequestError,
};
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::evidence::{EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind};
use sentrdel_schema::reasoner::{ReasonerEpistemicClass, ReasonerEvidenceDraft};
use std::collections::BTreeMap;

fn evidence_record() -> sentrdel_schema::evidence::EvidenceRecord {
    let authority = EvidenceAuthority::from_runtime("native", "1", ProducerKind::NativeRule)
        .expect("authority");
    authority
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:fixture".to_owned()],
            observation: "bounded deterministic observation".to_owned(),
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

#[test]
fn request_rejects_empty_and_oversized_instruction() {
    let limits = ReasonerLimits {
        max_evidence: 1,
        max_request_bytes: 64,
        max_instruction_bytes: 4,
    };

    assert!(matches!(
        ReasonerRequest::new("   ", Vec::new(), limits),
        Err(ReasonerRequestError::EmptyInstruction)
    ));
    assert!(matches!(
        ReasonerRequest::new("12345", Vec::new(), limits),
        Err(ReasonerRequestError::InstructionTooLarge { bytes: 5, max: 4 })
    ));
}

#[test]
fn request_caps_evidence_count_and_total_serialized_size() {
    let record = evidence_record();
    let count_limits = ReasonerLimits {
        max_evidence: 0,
        max_request_bytes: usize::MAX,
        max_instruction_bytes: 16,
    };
    assert!(matches!(
        ReasonerRequest::new("review", vec![record.clone()], count_limits),
        Err(ReasonerRequestError::TooManyEvidenceRecords { records: 1, max: 0 })
    ));

    let size_limits = ReasonerLimits {
        max_evidence: 1,
        max_request_bytes: 8,
        max_instruction_bytes: 16,
    };
    assert!(matches!(
        ReasonerRequest::new("review", vec![record], size_limits),
        Err(ReasonerRequestError::RequestTooLarge { .. })
    ));
}

struct FixtureReasoner;

impl Reasoner for FixtureReasoner {
    fn id(&self) -> &str {
        "fixture"
    }

    fn reason(
        &self,
        request: &ReasonerRequest,
    ) -> Result<Vec<ReasonerEvidenceDraft>, ReasonerError> {
        Ok(vec![ReasonerEvidenceDraft {
            input_digests: request
                .evidence
                .iter()
                .flat_map(|record| record.claim.input_digests.iter().cloned())
                .collect(),
            observation: "model-generated advisory context".to_owned(),
            security_interpretation: "possible security impact".to_owned(),
            category: "reasoner.fixture".to_owned(),
            epistemic_class: ReasonerEpistemicClass::Hypothesis,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            captured_at: "2026-08-29T00:00:00Z".to_owned(),
        }])
    }
}

#[test]
fn provider_neutral_trait_returns_schema_restricted_drafts() {
    let request =
        ReasonerRequest::new("review", vec![evidence_record()], ReasonerLimits::default())
            .expect("bounded request");
    let reasoner = FixtureReasoner;
    assert_eq!(reasoner.id(), "fixture");
    let drafts = reasoner.reason(&request).expect("reason");
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        drafts[0].epistemic_class,
        ReasonerEpistemicClass::Hypothesis
    );
}
