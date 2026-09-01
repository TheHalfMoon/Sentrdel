//! Validated R2 provider-output registration boundary for CLI integration.
//!
//! This type carries only canonical Evidence and Coverage produced by the
//! Rust-owned Supabase R2 pack. It deliberately has no Finding or policy field:
//! canonical Findings remain owned exclusively by the existing reconciler.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sentrdel_schema::coverage::{CoverageRecord, ProviderCoverageDimension};
use sentrdel_schema::evidence::{Evidence, EvidenceValidationError, ProducerKind};

use super::{
    COVERAGE_BUSINESS_LOGIC, COVERAGE_DETECTION, COVERAGE_LIVE_POSTURE, COVERAGE_RUNTIME,
    COVERAGE_STATIC_POSTURE_AUTH_CONFIG, COVERAGE_STATIC_POSTURE_DATABASE,
    COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS, COVERAGE_STATIC_POSTURE_KEY_BOUNDARY,
    COVERAGE_STATIC_POSTURE_STORAGE,
};

const PRODUCER_PREFIX: &str = "sentrdel.supabase.";

#[derive(Clone, Debug, PartialEq)]
pub struct SupabaseR2ProviderOutput {
    evidence: Vec<Evidence>,
    coverage: Vec<CoverageRecord>,
}

impl SupabaseR2ProviderOutput {
    pub fn new(
        mut evidence: Vec<Evidence>,
        mut coverage: Vec<CoverageRecord>,
    ) -> Result<Self, SupabaseR2ProviderOutputError> {
        let mut evidence_ids = BTreeSet::new();
        for item in &evidence {
            if item.producer().kind != ProducerKind::NativeRule
                || !item.producer().id.starts_with(PRODUCER_PREFIX)
            {
                return Err(SupabaseR2ProviderOutputError::UnexpectedEvidenceProducer(
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

    #[must_use]
    pub fn into_parts(self) -> (Vec<Evidence>, Vec<CoverageRecord>) {
        (self.evidence, self.coverage)
    }
}

#[derive(Debug)]
pub enum SupabaseR2ProviderOutputError {
    UnexpectedEvidenceProducer(String),
    InvalidEvidenceIdentity(String),
    UnexpectedCoverageProducer(String),
    UnexpectedCoverageCapability(String),
    WrongProviderDimension(String),
    DuplicateEvidenceId(String),
    DuplicateCoverageId(String),
    Evidence(EvidenceValidationError),
}

impl fmt::Display for SupabaseR2ProviderOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEvidenceProducer(value) => write!(
                formatter,
                "Supabase R2 CLI registration rejected unexpected Evidence producer {value:?}"
            ),
            Self::InvalidEvidenceIdentity(value) => write!(
                formatter,
                "Supabase R2 CLI registration rejected invalid Evidence identity {value:?}"
            ),
            Self::UnexpectedCoverageProducer(value) => write!(
                formatter,
                "Supabase R2 CLI registration rejected unexpected Coverage producer {value:?}"
            ),
            Self::UnexpectedCoverageCapability(value) => write!(
                formatter,
                "Supabase R2 CLI registration rejected unexpected Coverage capability {value:?}"
            ),
            Self::WrongProviderDimension(value) => write!(
                formatter,
                "Supabase R2 CLI registration rejected provider dimension for {value:?}"
            ),
            Self::DuplicateEvidenceId(value) => {
                write!(formatter, "duplicate Supabase R2 Evidence id {value:?}")
            }
            Self::DuplicateCoverageId(value) => {
                write!(formatter, "duplicate Supabase R2 Coverage id {value:?}")
            }
            Self::Evidence(error) => write!(formatter, "invalid Supabase R2 Evidence: {error}"),
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
    let producer = record.producer.as_deref().unwrap_or_default();
    if !producer.starts_with(PRODUCER_PREFIX) {
        return Err(SupabaseR2ProviderOutputError::UnexpectedCoverageProducer(
            producer.to_owned(),
        ));
    }

    let expected_dimension = match record.capability.as_str() {
        COVERAGE_DETECTION => Some(ProviderCoverageDimension::Detection),
        COVERAGE_STATIC_POSTURE_DATABASE
        | COVERAGE_STATIC_POSTURE_STORAGE
        | COVERAGE_STATIC_POSTURE_AUTH_CONFIG
        | COVERAGE_STATIC_POSTURE_EDGE_FUNCTIONS
        | COVERAGE_STATIC_POSTURE_KEY_BOUNDARY => Some(ProviderCoverageDimension::StaticPosture),
        COVERAGE_LIVE_POSTURE => Some(ProviderCoverageDimension::CredentialedLivePosture),
        COVERAGE_BUSINESS_LOGIC => Some(ProviderCoverageDimension::CrossLayerBusinessLogic),
        COVERAGE_RUNTIME => None,
        other => {
            return Err(SupabaseR2ProviderOutputError::UnexpectedCoverageCapability(
                other.to_owned(),
            ));
        }
    };

    if record.provider_dimension != expected_dimension {
        return Err(SupabaseR2ProviderOutputError::WrongProviderDimension(
            record.capability.clone(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::SCHEMA_V1;
    use sentrdel_schema::coverage::CoverageState;
    use sentrdel_schema::evidence::{
        EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind,
    };
    use std::collections::BTreeMap;

    fn evidence() -> Evidence {
        EvidenceAuthority::from_runtime(
            "sentrdel.supabase.rls-posture",
            "1",
            ProducerKind::NativeRule,
        )
        .unwrap()
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:fixture".to_owned()],
            observation: "repository-derived RLS state was observed".to_owned(),
            security_interpretation: None,
            category: "supabase_rls_posture".to_owned(),
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

    fn coverage() -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: "coverage:r2:rls".to_owned(),
            capability: COVERAGE_STATIC_POSTURE_DATABASE.to_owned(),
            scope: ".".to_owned(),
            producer: Some("sentrdel.supabase.rls-posture".to_owned()),
            provider_dimension: Some(ProviderCoverageDimension::StaticPosture),
            state: CoverageState::Covered,
            reason_code: None,
            details: Some("repository-derived static posture only".to_owned()),
            input_digests: vec!["sha256:fixture".to_owned()],
            observed_at: "2026-09-01T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn provider_output_carries_only_validated_evidence_and_coverage() {
        let output = SupabaseR2ProviderOutput::new(vec![evidence()], vec![coverage()]).unwrap();
        assert_eq!(output.evidence().len(), 1);
        assert_eq!(output.coverage().len(), 1);
    }

    #[test]
    fn provider_output_has_no_finding_or_policy_authority() {
        let output = SupabaseR2ProviderOutput::new(vec![evidence()], vec![coverage()]).unwrap();
        assert_eq!(output.evidence()[0].producer().kind, ProducerKind::NativeRule);
        assert!(output.evidence()[0].verify_identity().unwrap());
    }

    #[test]
    fn non_supabase_producers_and_wrong_dimensions_fail_closed() {
        let mut record = coverage();
        record.producer = Some("attacker.fixture".to_owned());
        assert!(matches!(
            SupabaseR2ProviderOutput::new(Vec::new(), vec![record]),
            Err(SupabaseR2ProviderOutputError::UnexpectedCoverageProducer(_))
        ));

        let mut record = coverage();
        record.provider_dimension = Some(ProviderCoverageDimension::Detection);
        assert!(matches!(
            SupabaseR2ProviderOutput::new(Vec::new(), vec![record]),
            Err(SupabaseR2ProviderOutputError::WrongProviderDimension(_))
        ));
    }
}
