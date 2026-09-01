//! R2 Supabase provider output registration for R1 review/init integration.
//!
//! This module is an authority-preserving seam: it accepts only already-sealed
//! canonical Evidence and producer-issued CoverageRecords from the compiled-in
//! Supabase R2 namespace, normalizes their order, and exposes them to generic R1
//! orchestration. It cannot create Findings, policy decisions, live posture, or
//! target/provider execution authority.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension};
use sentrdel_schema::evidence::{Evidence, EvidenceValidationError, ProducerKind};

use super::{
    COVERAGE_BUSINESS_LOGIC, COVERAGE_DETECTION, COVERAGE_LIVE_POSTURE, COVERAGE_RUNTIME,
    COVERAGE_STATIC_POSTURE_AUTH_CONFIG, COVERAGE_STATIC_POSTURE_DATABASE,
    COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS, COVERAGE_STATIC_POSTURE_KEY_BOUNDARY,
    COVERAGE_STATIC_POSTURE_STORAGE,
};

pub const SUPABASE_R2_PRODUCER_PREFIX: &str = "sentrdel.supabase.";
pub const DEFAULT_MAX_PROVIDER_EVIDENCE: usize = 16_384;
pub const DEFAULT_MAX_PROVIDER_COVERAGE: usize = 256;
pub const SUPABASE_R2_PROVIDER_NETWORK_ALLOWED: bool = false;
pub const SUPABASE_R2_PROVIDER_TARGET_EXECUTION_ALLOWED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SupabaseR2ProviderOutputLimits {
    pub max_evidence: usize,
    pub max_coverage: usize,
}

impl Default for SupabaseR2ProviderOutputLimits {
    fn default() -> Self {
        Self {
            max_evidence: DEFAULT_MAX_PROVIDER_EVIDENCE,
            max_coverage: DEFAULT_MAX_PROVIDER_COVERAGE,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SupabaseR2ProviderOutput {
    evidence: Vec<Evidence>,
    coverage: Vec<CoverageRecord>,
}

impl SupabaseR2ProviderOutput {
    pub fn new(
        mut evidence: Vec<Evidence>,
        mut coverage: Vec<CoverageRecord>,
        limits: SupabaseR2ProviderOutputLimits,
    ) -> Result<Self, SupabaseR2ProviderOutputError> {
        if limits.max_evidence == 0 || limits.max_coverage == 0 {
            return Err(SupabaseR2ProviderOutputError::InvalidLimits);
        }
        if evidence.len() > limits.max_evidence {
            return Err(SupabaseR2ProviderOutputError::TooMuchEvidence {
                count: evidence.len(),
                max: limits.max_evidence,
            });
        }
        if coverage.len() > limits.max_coverage {
            return Err(SupabaseR2ProviderOutputError::TooMuchCoverage {
                count: coverage.len(),
                max: limits.max_coverage,
            });
        }

        let mut evidence_ids = BTreeSet::new();
        for item in &evidence {
            if item.producer().kind != ProducerKind::NativeRule
                || !item.producer().id.starts_with(SUPABASE_R2_PRODUCER_PREFIX)
            {
                return Err(SupabaseR2ProviderOutputError::UnauthorizedEvidenceProducer(
                    item.producer().id.clone(),
                ));
            }
            if !item.verify_identity()? {
                return Err(SupabaseR2ProviderOutputError::InvalidEvidenceIdentity(
                    item.evidence_id().to_owned(),
                ));
            }
            if !evidence_ids.insert(item.evidence_id().to_owned()) {
                return Err(SupabaseR2ProviderOutputError::DuplicateEvidenceId(
                    item.evidence_id().to_owned(),
                ));
            }
        }

        let mut coverage_ids = BTreeSet::new();
        for record in &coverage {
            validate_coverage(record)?;
            if !coverage_ids.insert(record.coverage_id.clone()) {
                return Err(SupabaseR2ProviderOutputError::DuplicateCoverageId(
                    record.coverage_id.clone(),
                ));
            }
        }

        evidence.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));
        coverage.sort_by(|left, right| left.coverage_id.cmp(&right.coverage_id));
        Ok(Self { evidence, coverage })
    }

    #[must_use]
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    #[must_use]
    pub fn coverage(&self) -> &[CoverageRecord] {
        &self.coverage
    }
}

#[derive(Debug)]
pub enum SupabaseR2ProviderOutputError {
    InvalidLimits,
    TooMuchEvidence { count: usize, max: usize },
    TooMuchCoverage { count: usize, max: usize },
    UnauthorizedEvidenceProducer(String),
    InvalidEvidenceIdentity(String),
    DuplicateEvidenceId(String),
    UnauthorizedCoverageProducer(String),
    UnsupportedCoverageCapability(String),
    InvalidCoverageDimension(String),
    LiveAuthorityEscalation(String),
    BlankCoverageField(&'static str),
    DuplicateCoverageId(String),
    Evidence(EvidenceValidationError),
}

impl fmt::Display for SupabaseR2ProviderOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("R2 provider output limits must be non-zero"),
            Self::TooMuchEvidence { count, max } => {
                write!(formatter, "R2 provider evidence count {count} exceeds cap {max}")
            }
            Self::TooMuchCoverage { count, max } => {
                write!(formatter, "R2 provider coverage count {count} exceeds cap {max}")
            }
            Self::UnauthorizedEvidenceProducer(producer) => write!(
                formatter,
                "R2 provider Evidence producer is not an authorized native Supabase producer: {producer:?}"
            ),
            Self::InvalidEvidenceIdentity(id) => {
                write!(formatter, "R2 provider Evidence identity is invalid: {id:?}")
            }
            Self::DuplicateEvidenceId(id) => {
                write!(formatter, "R2 provider Evidence id is duplicated: {id:?}")
            }
            Self::UnauthorizedCoverageProducer(producer) => write!(
                formatter,
                "R2 provider Coverage producer is not an authorized Supabase producer: {producer:?}"
            ),
            Self::UnsupportedCoverageCapability(capability) => write!(
                formatter,
                "R2 provider Coverage capability is outside the frozen contract: {capability:?}"
            ),
            Self::InvalidCoverageDimension(capability) => write!(
                formatter,
                "R2 provider Coverage dimension does not match capability {capability:?}"
            ),
            Self::LiveAuthorityEscalation(capability) => write!(
                formatter,
                "R2 static provider cannot report implemented live/business/runtime capability {capability:?}"
            ),
            Self::BlankCoverageField(field) => {
                write!(formatter, "R2 provider Coverage {field} must not be blank")
            }
            Self::DuplicateCoverageId(id) => {
                write!(formatter, "R2 provider Coverage id is duplicated: {id:?}")
            }
            Self::Evidence(error) => write!(formatter, "R2 provider Evidence validation failed: {error}"),
        }
    }
}

impl Error for SupabaseR2ProviderOutputError {}

impl From<EvidenceValidationError> for SupabaseR2ProviderOutputError {
    fn from(value: EvidenceValidationError) -> Self {
        Self::Evidence(value)
    }
}

fn validate_coverage(record: &CoverageRecord) -> Result<(), SupabaseR2ProviderOutputError> {
    if record.coverage_id.trim().is_empty() {
        return Err(SupabaseR2ProviderOutputError::BlankCoverageField("id"));
    }
    if record.capability.trim().is_empty() {
        return Err(SupabaseR2ProviderOutputError::BlankCoverageField(
            "capability",
        ));
    }
    if record.scope.trim().is_empty() {
        return Err(SupabaseR2ProviderOutputError::BlankCoverageField("scope"));
    }
    if record.observed_at.trim().is_empty() {
        return Err(SupabaseR2ProviderOutputError::BlankCoverageField(
            "observed_at",
        ));
    }
    let producer = record
        .producer
        .as_deref()
        .ok_or(SupabaseR2ProviderOutputError::BlankCoverageField(
            "producer",
        ))?;
    if !producer.starts_with(SUPABASE_R2_PRODUCER_PREFIX) {
        return Err(SupabaseR2ProviderOutputError::UnauthorizedCoverageProducer(
            producer.to_owned(),
        ));
    }

    let expected_dimension = match record.capability.as_str() {
        COVERAGE_DETECTION => ProviderCoverageDimension::Detection,
        COVERAGE_STATIC_POSTURE_DATABASE
        | COVERAGE_STATIC_POSTURE_STORAGE
        | COVERAGE_STATIC_POSTURE_AUTH_CONFIG
        | COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS
        | COVERAGE_STATIC_POSTURE_KEY_BOUNDARY => ProviderCoverageDimension::StaticPosture,
        COVERAGE_LIVE_POSTURE => ProviderCoverageDimension::CredentialedLivePosture,
        COVERAGE_BUSINESS_LOGIC => ProviderCoverageDimension::CrossLayerBusinessLogic,
        COVERAGE_RUNTIME => {
            if record.state == CoverageState::Covered {
                return Err(SupabaseR2ProviderOutputError::LiveAuthorityEscalation(
                    record.capability.clone(),
                ));
            }
            if record.provider_dimension.is_some() {
                return Err(SupabaseR2ProviderOutputError::InvalidCoverageDimension(
                    record.capability.clone(),
                ));
            }
            return Ok(());
        }
        _ => {
            return Err(SupabaseR2ProviderOutputError::UnsupportedCoverageCapability(
                record.capability.clone(),
            ));
        }
    };

    if record.provider_dimension.as_ref() != Some(&expected_dimension) {
        return Err(SupabaseR2ProviderOutputError::InvalidCoverageDimension(
            record.capability.clone(),
        ));
    }
    if matches!(
        record.capability.as_str(),
        COVERAGE_LIVE_POSTURE | COVERAGE_BUSINESS_LOGIC
    ) && record.state == CoverageState::Covered
    {
        return Err(SupabaseR2ProviderOutputError::LiveAuthorityEscalation(
            record.capability.clone(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sentrdel_schema::SCHEMA_V1;
    use sentrdel_schema::evidence::{
        EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind,
    };

    use super::*;

    fn evidence(producer: &str) -> Evidence {
        EvidenceAuthority::from_runtime(producer, "1", ProducerKind::NativeRule)
            .unwrap()
            .seal(EvidenceClaim {
                schema_version: SCHEMA_V1.to_owned(),
                input_digests: vec!["sha256:fixture".to_owned()],
                observation: "Repository-derived Supabase posture was observed".to_owned(),
                security_interpretation: None,
                category: "supabase_fixture".to_owned(),
                epistemic_class: EpistemicClass::Fact,
                confidence_band: None,
                subjects: Vec::new(),
                locations: Vec::new(),
                attributes: BTreeMap::new(),
                reproduction: None,
                captured_at: "2026-09-01T00:00:00Z".to_owned(),
            })
            .unwrap()
    }

    fn coverage(capability: &str, state: CoverageState) -> CoverageRecord {
        let provider_dimension = match capability {
            COVERAGE_DETECTION => Some(ProviderCoverageDimension::Detection),
            COVERAGE_LIVE_POSTURE => Some(ProviderCoverageDimension::CredentialedLivePosture),
            COVERAGE_BUSINESS_LOGIC => {
                Some(ProviderCoverageDimension::CrossLayerBusinessLogic)
            }
            COVERAGE_RUNTIME => None,
            _ => Some(ProviderCoverageDimension::StaticPosture),
        };
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: format!("coverage:sentrdel.supabase.fixture:{capability}"),
            capability: capability.to_owned(),
            scope: ".".to_owned(),
            producer: Some("sentrdel.supabase.fixture".to_owned()),
            provider_dimension,
            state,
            reason_code: None,
            details: None,
            input_digests: vec!["sha256:fixture".to_owned()],
            observed_at: "2026-09-01T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn output_is_deterministic_and_contains_no_finding_authority() {
        let first = evidence("sentrdel.supabase.second");
        let second = evidence("sentrdel.supabase.first");
        let output = SupabaseR2ProviderOutput::new(
            vec![first, second],
            vec![
                coverage(COVERAGE_STATIC_POSTURE_STORAGE, CoverageState::Covered),
                coverage(COVERAGE_STATIC_POSTURE_DATABASE, CoverageState::Partial),
            ],
            SupabaseR2ProviderOutputLimits::default(),
        )
        .unwrap();

        assert!(output.evidence().windows(2).all(|pair| {
            pair[0].evidence_id() <= pair[1].evidence_id()
        }));
        assert!(output.coverage().windows(2).all(|pair| {
            pair[0].coverage_id <= pair[1].coverage_id
        }));
        const { assert!(!SUPABASE_R2_PROVIDER_NETWORK_ALLOWED) };
        const { assert!(!SUPABASE_R2_PROVIDER_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }

    #[test]
    fn non_supabase_or_non_native_evidence_is_rejected() {
        let outside = evidence("sentrdel.changed-secret");
        assert!(matches!(
            SupabaseR2ProviderOutput::new(
                vec![outside],
                Vec::new(),
                SupabaseR2ProviderOutputLimits::default(),
            ),
            Err(SupabaseR2ProviderOutputError::UnauthorizedEvidenceProducer(_))
        ));

        let llm = EvidenceAuthority::from_runtime(
            "sentrdel.supabase.reasoner",
            "1",
            ProducerKind::LlmReasoner,
        )
        .unwrap()
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:fixture".to_owned()],
            observation: "Hypothesis".to_owned(),
            security_interpretation: None,
            category: "supabase_fixture".to_owned(),
            epistemic_class: EpistemicClass::Hypothesis,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: "2026-09-01T00:00:00Z".to_owned(),
        })
        .unwrap();
        assert!(matches!(
            SupabaseR2ProviderOutput::new(
                vec![llm],
                Vec::new(),
                SupabaseR2ProviderOutputLimits::default(),
            ),
            Err(SupabaseR2ProviderOutputError::UnauthorizedEvidenceProducer(_))
        ));
    }

    #[test]
    fn live_business_and_runtime_cannot_claim_covered_in_r2() {
        for capability in [
            COVERAGE_LIVE_POSTURE,
            COVERAGE_BUSINESS_LOGIC,
            COVERAGE_RUNTIME,
        ] {
            assert!(matches!(
                SupabaseR2ProviderOutput::new(
                    Vec::new(),
                    vec![coverage(capability, CoverageState::Covered)],
                    SupabaseR2ProviderOutputLimits::default(),
                ),
                Err(SupabaseR2ProviderOutputError::LiveAuthorityEscalation(_))
            ));
        }
    }

    #[test]
    fn unsupported_or_wrong_dimension_coverage_fails_closed() {
        let unsupported = coverage("STATIC_POSTURE_UNKNOWN", CoverageState::Covered);
        assert!(matches!(
            SupabaseR2ProviderOutput::new(
                Vec::new(),
                vec![unsupported],
                SupabaseR2ProviderOutputLimits::default(),
            ),
            Err(SupabaseR2ProviderOutputError::UnsupportedCoverageCapability(_))
        ));

        let mut wrong = coverage(COVERAGE_STATIC_POSTURE_DATABASE, CoverageState::Covered);
        wrong.provider_dimension = Some(ProviderCoverageDimension::Detection);
        assert!(matches!(
            SupabaseR2ProviderOutput::new(
                Vec::new(),
                vec![wrong],
                SupabaseR2ProviderOutputLimits::default(),
            ),
            Err(SupabaseR2ProviderOutputError::InvalidCoverageDimension(_))
        ));
    }
}
