//! Frozen S1 Phase 1 pair, compatibility, and comparison-record contracts.
//!
//! The types in this module are internal deterministic comparison contracts.
//! They intentionally stop short of production Git revision validation,
//! snapshot composition over canonical records, or comparison execution; those
//! capabilities are dependency-ordered S1-T007+ work.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::{CanonicalError, content_id};
use sentrdel_schema::coverage::CoverageState;

use crate::business_logic::model::InvariantEvaluationState;
use crate::regression::{
    S1_FIXTURE_IDENTITY_NAMESPACE, S1_REGRESSION_CONTRACT_VERSION, S1_SNAPSHOT_CONTRACT_VERSION,
};

pub const DEFAULT_MAX_SNAPSHOT_INVARIANTS: usize = 4_096;
pub const DEFAULT_MAX_SNAPSHOT_EVALUATIONS: usize = 4_096;
pub const DEFAULT_MAX_SNAPSHOT_COVERAGE_RECORDS: usize = 4_096;
pub const DEFAULT_MAX_GRAPH_NODES: usize = 4_096;
pub const DEFAULT_MAX_GRAPH_EDGES: usize = 8_192;
pub const DEFAULT_MAX_PAIR_RESULTS: usize = 4_096;
pub const DEFAULT_MAX_EVIDENCE_REFS_PER_RESULT: usize = 128;
pub const DEFAULT_MAX_PROVENANCE_REFS_PER_RESULT: usize = 64;
pub const DEFAULT_MAX_DIAGNOSTICS: usize = 1_024;
pub const DEFAULT_MAX_PRODUCER_CONTRACTS: usize = 128;
pub const DEFAULT_MAX_CONFIGURATION_IDENTITIES: usize = 128;
pub const DEFAULT_MAX_TEXT_BYTES: usize = 4_096;
pub const DEFAULT_MAX_TOTAL_INPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegressionLimits {
    pub max_snapshot_invariants: usize,
    pub max_snapshot_evaluations: usize,
    pub max_snapshot_coverage_records: usize,
    pub max_graph_nodes: usize,
    pub max_graph_edges: usize,
    pub max_pair_results: usize,
    pub max_evidence_refs_per_result: usize,
    pub max_provenance_refs_per_result: usize,
    pub max_diagnostics: usize,
    pub max_producer_contracts: usize,
    pub max_configuration_identities: usize,
    pub max_text_bytes: usize,
    pub max_total_input_bytes: usize,
}

impl Default for RegressionLimits {
    fn default() -> Self {
        Self {
            max_snapshot_invariants: DEFAULT_MAX_SNAPSHOT_INVARIANTS,
            max_snapshot_evaluations: DEFAULT_MAX_SNAPSHOT_EVALUATIONS,
            max_snapshot_coverage_records: DEFAULT_MAX_SNAPSHOT_COVERAGE_RECORDS,
            max_graph_nodes: DEFAULT_MAX_GRAPH_NODES,
            max_graph_edges: DEFAULT_MAX_GRAPH_EDGES,
            max_pair_results: DEFAULT_MAX_PAIR_RESULTS,
            max_evidence_refs_per_result: DEFAULT_MAX_EVIDENCE_REFS_PER_RESULT,
            max_provenance_refs_per_result: DEFAULT_MAX_PROVENANCE_REFS_PER_RESULT,
            max_diagnostics: DEFAULT_MAX_DIAGNOSTICS,
            max_producer_contracts: DEFAULT_MAX_PRODUCER_CONTRACTS,
            max_configuration_identities: DEFAULT_MAX_CONFIGURATION_IDENTITIES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_total_input_bytes: DEFAULT_MAX_TOTAL_INPUT_BYTES,
        }
    }
}

impl RegressionLimits {
    pub fn validate(self) -> Result<Self, RegressionModelError> {
        if self.max_snapshot_invariants == 0
            || self.max_snapshot_evaluations == 0
            || self.max_snapshot_coverage_records == 0
            || self.max_graph_nodes == 0
            || self.max_graph_edges == 0
            || self.max_pair_results == 0
            || self.max_evidence_refs_per_result == 0
            || self.max_provenance_refs_per_result == 0
            || self.max_diagnostics == 0
            || self.max_producer_contracts == 0
            || self.max_configuration_identities == 0
            || self.max_text_bytes == 0
            || self.max_total_input_bytes == 0
        {
            return Err(RegressionModelError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub enum RegressionModelError {
    InvalidLimits,
    EmptyField(&'static str),
    FieldTooLarge {
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    SameRevisionIdentity,
    InvalidRevisionRole,
    EmptyProducerContracts,
    DuplicateProducerContract(String),
    TooManyCollectionItems {
        field: &'static str,
        count: usize,
        max: usize,
    },
    TotalInputBytesExceeded {
        max: usize,
    },
    DuplicateCoverageKey(String),
    MissingComparedIdentity,
    Canonical(CanonicalError),
}

impl fmt::Display for RegressionModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("S1 regression limits must be non-zero"),
            Self::EmptyField(field) => write!(formatter, "S1 field {field} must not be empty"),
            Self::FieldTooLarge { field, bytes, max } => {
                write!(formatter, "S1 field {field} size {bytes} exceeds cap {max}")
            }
            Self::SameRevisionIdentity => formatter.write_str(
                "trusted-base and candidate exact identities must be distinct for a claimed comparison",
            ),
            Self::InvalidRevisionRole => formatter.write_str(
                "S1 revision pair requires TRUSTED_BASE first and CANDIDATE second",
            ),
            Self::EmptyProducerContracts => {
                formatter.write_str("S1 snapshot requires at least one producer contract identity")
            }
            Self::DuplicateProducerContract(value) => {
                write!(formatter, "duplicate S1 producer contract identity {value:?}")
            }
            Self::TooManyCollectionItems { field, count, max } => write!(
                formatter,
                "S1 collection {field} count {count} exceeds cap {max}"
            ),
            Self::TotalInputBytesExceeded { max } => write!(
                formatter,
                "S1 aggregate comparison input exceeds byte cap {max}"
            ),
            Self::DuplicateCoverageKey(value) => {
                write!(formatter, "duplicate S1 coverage comparison key {value:?}")
            }
            Self::MissingComparedIdentity => formatter.write_str(
                "S1 comparison record requires a base or candidate semantic identity",
            ),
            Self::Canonical(error) => write!(formatter, "S1 canonical identity failed: {error}"),
        }
    }
}

impl Error for RegressionModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CanonicalError> for RegressionModelError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RevisionRole {
    TrustedBase,
    Candidate,
}

impl RevisionRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedBase => "TRUSTED_BASE",
            Self::Candidate => "CANDIDATE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionIdentity {
    role: RevisionRole,
    exact_identity: String,
    snapshot_input_digest: String,
    fixture_only: bool,
}

impl RevisionIdentity {
    pub fn fixture(
        role: RevisionRole,
        fixture_identity: impl Into<String>,
        snapshot_input_digest: impl Into<String>,
        limits: RegressionLimits,
    ) -> Result<Self, RegressionModelError> {
        let limits = limits.validate()?;
        let fixture_identity = fixture_identity.into();
        let snapshot_input_digest = snapshot_input_digest.into();
        validate_text(&fixture_identity, "fixture_identity", limits)?;
        validate_text(&snapshot_input_digest, "snapshot_input_digest", limits)?;

        let exact_identity = content_id(
            "s1-fixture-revision-identity",
            &(
                S1_FIXTURE_IDENTITY_NAMESPACE,
                fixture_identity.as_str(),
                snapshot_input_digest.as_str(),
            ),
        )?;

        Ok(Self {
            role,
            exact_identity,
            snapshot_input_digest,
            fixture_only: true,
        })
    }

    #[must_use]
    pub const fn role(&self) -> RevisionRole {
        self.role
    }

    #[must_use]
    pub fn exact_identity(&self) -> &str {
        &self.exact_identity
    }

    #[must_use]
    pub fn snapshot_input_digest(&self) -> &str {
        &self.snapshot_input_digest
    }

    #[must_use]
    pub const fn is_fixture_only(&self) -> bool {
        self.fixture_only
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionPair {
    pair_id: String,
    trusted_base: RevisionIdentity,
    candidate: RevisionIdentity,
}

impl RevisionPair {
    pub fn new(
        trusted_base: RevisionIdentity,
        candidate: RevisionIdentity,
    ) -> Result<Self, RegressionModelError> {
        if trusted_base.role() != RevisionRole::TrustedBase
            || candidate.role() != RevisionRole::Candidate
        {
            return Err(RegressionModelError::InvalidRevisionRole);
        }
        if trusted_base.exact_identity() == candidate.exact_identity() {
            return Err(RegressionModelError::SameRevisionIdentity);
        }

        let pair_id = content_id(
            "s1-revision-pair",
            &(
                S1_REGRESSION_CONTRACT_VERSION,
                trusted_base.exact_identity(),
                candidate.exact_identity(),
            ),
        )?;

        Ok(Self {
            pair_id,
            trusted_base,
            candidate,
        })
    }

    #[must_use]
    pub fn pair_id(&self) -> &str {
        &self.pair_id
    }

    #[must_use]
    pub fn trusted_base(&self) -> &RevisionIdentity {
        &self.trusted_base
    }

    #[must_use]
    pub fn candidate(&self) -> &RevisionIdentity {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProducerContractIdentity {
    producer_id: String,
    producer_version: String,
    configuration_digest: String,
    capability_scope: String,
    schema_or_contract_version: String,
}

impl ProducerContractIdentity {
    pub fn new(
        producer_id: impl Into<String>,
        producer_version: impl Into<String>,
        configuration_digest: impl Into<String>,
        capability_scope: impl Into<String>,
        schema_or_contract_version: impl Into<String>,
        limits: RegressionLimits,
    ) -> Result<Self, RegressionModelError> {
        let limits = limits.validate()?;
        let value = Self {
            producer_id: producer_id.into(),
            producer_version: producer_version.into(),
            configuration_digest: configuration_digest.into(),
            capability_scope: capability_scope.into(),
            schema_or_contract_version: schema_or_contract_version.into(),
        };
        validate_text(&value.producer_id, "producer_id", limits)?;
        validate_text(&value.producer_version, "producer_version", limits)?;
        validate_text(&value.configuration_digest, "configuration_digest", limits)?;
        validate_text(&value.capability_scope, "capability_scope", limits)?;
        validate_text(
            &value.schema_or_contract_version,
            "schema_or_contract_version",
            limits,
        )?;
        Ok(value)
    }

    fn stable_key(&self) -> Result<String, RegressionModelError> {
        Ok(content_id(
            "s1-producer-contract-identity",
            &(
                self.producer_id.as_str(),
                self.producer_version.as_str(),
                self.configuration_digest.as_str(),
                self.capability_scope.as_str(),
                self.schema_or_contract_version.as_str(),
            ),
        )?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotCompatibility {
    Compatible,
    SnapshotContractMismatch,
    CanonicalSchemaMismatch,
    ProducerContractMismatch,
    ConfigurationIdentityMismatch,
}

impl SnapshotCompatibility {
    #[must_use]
    pub const fn is_compatible(self) -> bool {
        matches!(self, Self::Compatible)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticSnapshotContract {
    revision: RevisionIdentity,
    snapshot_contract_version: String,
    canonical_schema_contract: String,
    producer_contracts: Vec<ProducerContractIdentity>,
    configuration_identity: Vec<String>,
}

impl SemanticSnapshotContract {
    pub fn new(
        revision: RevisionIdentity,
        canonical_schema_contract: impl Into<String>,
        producer_contracts: Vec<ProducerContractIdentity>,
        configuration_identity: Vec<String>,
        limits: RegressionLimits,
    ) -> Result<Self, RegressionModelError> {
        let limits = limits.validate()?;
        let canonical_schema_contract = canonical_schema_contract.into();
        validate_text(
            &canonical_schema_contract,
            "canonical_schema_contract",
            limits,
        )?;

        if producer_contracts.is_empty() {
            return Err(RegressionModelError::EmptyProducerContracts);
        }
        if producer_contracts.len() > limits.max_producer_contracts {
            return Err(RegressionModelError::TooManyCollectionItems {
                field: "producer_contracts",
                count: producer_contracts.len(),
                max: limits.max_producer_contracts,
            });
        }

        let mut producer_contracts = producer_contracts;
        producer_contracts.sort();
        for pair in producer_contracts.windows(2) {
            if pair[0] == pair[1] {
                return Err(RegressionModelError::DuplicateProducerContract(
                    pair[0].stable_key()?,
                ));
            }
        }

        let configuration_identity = normalize_text_collection(
            configuration_identity,
            "configuration_identity",
            limits.max_configuration_identities,
            limits,
        )?;

        Ok(Self {
            revision,
            snapshot_contract_version: S1_SNAPSHOT_CONTRACT_VERSION.to_owned(),
            canonical_schema_contract,
            producer_contracts,
            configuration_identity,
        })
    }

    #[must_use]
    pub fn revision(&self) -> &RevisionIdentity {
        &self.revision
    }

    #[must_use]
    pub fn compatibility_with(&self, other: &Self) -> SnapshotCompatibility {
        if self.snapshot_contract_version != other.snapshot_contract_version {
            return SnapshotCompatibility::SnapshotContractMismatch;
        }
        if self.canonical_schema_contract != other.canonical_schema_contract {
            return SnapshotCompatibility::CanonicalSchemaMismatch;
        }
        if self.producer_contracts != other.producer_contracts {
            return SnapshotCompatibility::ProducerContractMismatch;
        }
        if self.configuration_identity != other.configuration_identity {
            return SnapshotCompatibility::ConfigurationIdentityMismatch;
        }
        SnapshotCompatibility::Compatible
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PairPresence {
    Matched,
    BaseOnly,
    CandidateOnly,
}

impl PairPresence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "MATCHED",
            Self::BaseOnly => "BASE_ONLY",
            Self::CandidateOnly => "CANDIDATE_ONLY",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ContinuityBasis {
    ExactStableId,
    ProvenDeterministicContinuity,
    Unmatched,
}

impl ContinuityBasis {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactStableId => "EXACT_STABLE_ID",
            Self::ProvenDeterministicContinuity => "PROVEN_DETERMINISTIC_CONTINUITY",
            Self::Unmatched => "UNMATCHED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecurityDeltaDisposition {
    Regression,
    Improvement,
    Unchanged,
    Unknown,
    CoverageLost,
    CoverageGained,
}

impl SecurityDeltaDisposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regression => "REGRESSION",
            Self::Improvement => "IMPROVEMENT",
            Self::Unchanged => "UNCHANGED",
            Self::Unknown => "UNKNOWN",
            Self::CoverageLost => "COVERAGE_LOST",
            Self::CoverageGained => "COVERAGE_GAINED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SecurityDeltaReason {
    InvariantStateWeakened,
    InvariantStateImproved,
    InvariantStateUnchanged,
    CandidateCoverageDegraded,
    CandidateCoverageGained,
    ProducerDisappeared,
    SnapshotIncompatible,
    InvariantDefinitionConflict,
    InvariantRequirementRemoved,
    SemanticObjectAdded,
    SemanticObjectRemoved,
    SemanticContinuityUnproven,
    MoveOnlyContinuity,
    ResourceCapReached,
}

impl SecurityDeltaReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvariantStateWeakened => "INVARIANT_STATE_WEAKENED",
            Self::InvariantStateImproved => "INVARIANT_STATE_IMPROVED",
            Self::InvariantStateUnchanged => "INVARIANT_STATE_UNCHANGED",
            Self::CandidateCoverageDegraded => "CANDIDATE_COVERAGE_DEGRADED",
            Self::CandidateCoverageGained => "CANDIDATE_COVERAGE_GAINED",
            Self::ProducerDisappeared => "PRODUCER_DISAPPEARED",
            Self::SnapshotIncompatible => "SNAPSHOT_INCOMPATIBLE",
            Self::InvariantDefinitionConflict => "INVARIANT_DEFINITION_CONFLICT",
            Self::InvariantRequirementRemoved => "INVARIANT_REQUIREMENT_REMOVED",
            Self::SemanticObjectAdded => "SEMANTIC_OBJECT_ADDED",
            Self::SemanticObjectRemoved => "SEMANTIC_OBJECT_REMOVED",
            Self::SemanticContinuityUnproven => "SEMANTIC_CONTINUITY_UNPROVEN",
            Self::MoveOnlyContinuity => "MOVE_ONLY_CONTINUITY",
            Self::ResourceCapReached => "RESOURCE_CAP_REACHED",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenInvariantTransition {
    pub base: InvariantEvaluationState,
    pub candidate: InvariantEvaluationState,
    pub allowed_dispositions: &'static [SecurityDeltaDisposition],
}

const REGRESSION_ONLY: &[SecurityDeltaDisposition] = &[SecurityDeltaDisposition::Regression];
const IMPROVEMENT_ONLY: &[SecurityDeltaDisposition] = &[SecurityDeltaDisposition::Improvement];
const UNCHANGED_ONLY: &[SecurityDeltaDisposition] = &[SecurityDeltaDisposition::Unchanged];
const COVERAGE_LOST_OR_UNKNOWN: &[SecurityDeltaDisposition] = &[
    SecurityDeltaDisposition::CoverageLost,
    SecurityDeltaDisposition::Unknown,
];
const COVERAGE_GAINED_OR_UNKNOWN: &[SecurityDeltaDisposition] = &[
    SecurityDeltaDisposition::CoverageGained,
    SecurityDeltaDisposition::Unknown,
];

pub const FROZEN_INVARIANT_TRANSITIONS: &[FrozenInvariantTransition] = &[
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Satisfied,
        candidate: InvariantEvaluationState::Violated,
        allowed_dispositions: REGRESSION_ONLY,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Violated,
        candidate: InvariantEvaluationState::Satisfied,
        allowed_dispositions: IMPROVEMENT_ONLY,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Satisfied,
        candidate: InvariantEvaluationState::Satisfied,
        allowed_dispositions: UNCHANGED_ONLY,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Violated,
        candidate: InvariantEvaluationState::Violated,
        allowed_dispositions: UNCHANGED_ONLY,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Satisfied,
        candidate: InvariantEvaluationState::Unknown,
        allowed_dispositions: COVERAGE_LOST_OR_UNKNOWN,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Violated,
        candidate: InvariantEvaluationState::Unknown,
        allowed_dispositions: COVERAGE_LOST_OR_UNKNOWN,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Unknown,
        candidate: InvariantEvaluationState::Satisfied,
        allowed_dispositions: COVERAGE_GAINED_OR_UNKNOWN,
    },
    FrozenInvariantTransition {
        base: InvariantEvaluationState::Unknown,
        candidate: InvariantEvaluationState::Violated,
        allowed_dispositions: COVERAGE_GAINED_OR_UNKNOWN,
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoveragePair {
    comparison_key: String,
    base_state: Option<CoverageState>,
    candidate_state: Option<CoverageState>,
    base_reason: Option<String>,
    candidate_reason: Option<String>,
}

impl CoveragePair {
    pub fn new(
        comparison_key: impl Into<String>,
        base_state: Option<CoverageState>,
        candidate_state: Option<CoverageState>,
        base_reason: Option<String>,
        candidate_reason: Option<String>,
        limits: RegressionLimits,
    ) -> Result<Self, RegressionModelError> {
        let limits = limits.validate()?;
        let comparison_key = comparison_key.into();
        validate_text(&comparison_key, "coverage_comparison_key", limits)?;
        validate_optional_text(base_reason.as_deref(), "base_coverage_reason", limits)?;
        validate_optional_text(
            candidate_reason.as_deref(),
            "candidate_coverage_reason",
            limits,
        )?;
        Ok(Self {
            comparison_key,
            base_state,
            candidate_state,
            base_reason,
            candidate_reason,
        })
    }

    #[must_use]
    pub fn comparison_key(&self) -> &str {
        &self.comparison_key
    }

    fn semantic_id(&self) -> Result<String, RegressionModelError> {
        Ok(content_id(
            "s1-coverage-pair",
            &(
                self.comparison_key.as_str(),
                coverage_state_name(self.base_state.as_ref()),
                coverage_state_name(self.candidate_state.as_ref()),
                self.base_reason.as_deref().unwrap_or(""),
                self.candidate_reason.as_deref().unwrap_or(""),
            ),
        )?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceState {
    Complete,
    CapReached,
}

impl ResourceState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "COMPLETE",
            Self::CapReached => "CAP_REACHED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityRegressionRecordDraft {
    pub pair_id: String,
    pub pair_presence: PairPresence,
    pub continuity_basis: ContinuityBasis,
    pub base_invariant_id: Option<String>,
    pub candidate_invariant_id: Option<String>,
    pub base_definition_digest: Option<String>,
    pub candidate_definition_digest: Option<String>,
    pub base_evaluation_state: Option<InvariantEvaluationState>,
    pub candidate_evaluation_state: Option<InvariantEvaluationState>,
    pub disposition: SecurityDeltaDisposition,
    pub reason_code: SecurityDeltaReason,
    pub coverage_pairs: Vec<CoveragePair>,
    pub base_supporting_evidence_refs: Vec<String>,
    pub candidate_supporting_evidence_refs: Vec<String>,
    pub base_provenance_refs: Vec<String>,
    pub candidate_provenance_refs: Vec<String>,
    pub graph_context_refs: Vec<String>,
    pub diagnostics: Vec<String>,
    pub resource_state: ResourceState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityRegressionRecord {
    regression_id: String,
    draft: SecurityRegressionRecordDraft,
}

impl SecurityRegressionRecord {
    pub fn seal(
        mut draft: SecurityRegressionRecordDraft,
        limits: RegressionLimits,
    ) -> Result<Self, RegressionModelError> {
        let limits = limits.validate()?;
        validate_text(&draft.pair_id, "pair_id", limits)?;
        enforce_total_input_bytes(&draft, limits)?;
        if draft.base_invariant_id.is_none() && draft.candidate_invariant_id.is_none() {
            return Err(RegressionModelError::MissingComparedIdentity);
        }

        validate_optional_text(
            draft.base_invariant_id.as_deref(),
            "base_invariant_id",
            limits,
        )?;
        validate_optional_text(
            draft.candidate_invariant_id.as_deref(),
            "candidate_invariant_id",
            limits,
        )?;
        validate_optional_text(
            draft.base_definition_digest.as_deref(),
            "base_definition_digest",
            limits,
        )?;
        validate_optional_text(
            draft.candidate_definition_digest.as_deref(),
            "candidate_definition_digest",
            limits,
        )?;

        if draft.coverage_pairs.len() > limits.max_snapshot_coverage_records {
            return Err(RegressionModelError::TooManyCollectionItems {
                field: "coverage_pairs",
                count: draft.coverage_pairs.len(),
                max: limits.max_snapshot_coverage_records,
            });
        }
        draft
            .coverage_pairs
            .sort_by(|left, right| left.comparison_key.cmp(&right.comparison_key));
        for pair in draft.coverage_pairs.windows(2) {
            if pair[0].comparison_key == pair[1].comparison_key {
                return Err(RegressionModelError::DuplicateCoverageKey(
                    pair[0].comparison_key.clone(),
                ));
            }
        }

        draft.base_supporting_evidence_refs = normalize_text_collection(
            draft.base_supporting_evidence_refs,
            "base_supporting_evidence_refs",
            limits.max_evidence_refs_per_result,
            limits,
        )?;
        draft.candidate_supporting_evidence_refs = normalize_text_collection(
            draft.candidate_supporting_evidence_refs,
            "candidate_supporting_evidence_refs",
            limits.max_evidence_refs_per_result,
            limits,
        )?;
        draft.base_provenance_refs = normalize_text_collection(
            draft.base_provenance_refs,
            "base_provenance_refs",
            limits.max_provenance_refs_per_result,
            limits,
        )?;
        draft.candidate_provenance_refs = normalize_text_collection(
            draft.candidate_provenance_refs,
            "candidate_provenance_refs",
            limits.max_provenance_refs_per_result,
            limits,
        )?;
        draft.graph_context_refs = normalize_text_collection(
            draft.graph_context_refs,
            "graph_context_refs",
            limits.max_graph_edges,
            limits,
        )?;
        draft.diagnostics = normalize_text_collection(
            draft.diagnostics,
            "diagnostics",
            limits.max_diagnostics,
            limits,
        )?;

        let coverage_ids = draft
            .coverage_pairs
            .iter()
            .map(CoveragePair::semantic_id)
            .collect::<Result<Vec<_>, _>>()?;
        let coverage_digest = content_id("s1-regression-coverage-set", &coverage_ids)?;
        let base_evidence_digest = content_id(
            "s1-regression-base-evidence-refs",
            &draft.base_supporting_evidence_refs,
        )?;
        let candidate_evidence_digest = content_id(
            "s1-regression-candidate-evidence-refs",
            &draft.candidate_supporting_evidence_refs,
        )?;
        let base_provenance_digest = content_id(
            "s1-regression-base-provenance-refs",
            &draft.base_provenance_refs,
        )?;
        let candidate_provenance_digest = content_id(
            "s1-regression-candidate-provenance-refs",
            &draft.candidate_provenance_refs,
        )?;
        let graph_digest = content_id(
            "s1-regression-graph-context-refs",
            &draft.graph_context_refs,
        )?;
        let diagnostics_digest = content_id("s1-regression-diagnostics", &draft.diagnostics)?;

        let identity_parts = vec![
            S1_REGRESSION_CONTRACT_VERSION.to_owned(),
            draft.pair_id.clone(),
            draft.pair_presence.as_str().to_owned(),
            draft.continuity_basis.as_str().to_owned(),
            draft.base_invariant_id.clone().unwrap_or_default(),
            draft.candidate_invariant_id.clone().unwrap_or_default(),
            draft.base_definition_digest.clone().unwrap_or_default(),
            draft
                .candidate_definition_digest
                .clone()
                .unwrap_or_default(),
            invariant_state_name(draft.base_evaluation_state).to_owned(),
            invariant_state_name(draft.candidate_evaluation_state).to_owned(),
            draft.disposition.as_str().to_owned(),
            draft.reason_code.as_str().to_owned(),
            coverage_digest,
            base_evidence_digest,
            candidate_evidence_digest,
            base_provenance_digest,
            candidate_provenance_digest,
            graph_digest,
            diagnostics_digest,
            draft.resource_state.as_str().to_owned(),
        ];
        let regression_id = content_id("s1-security-regression-record", &identity_parts)?;

        Ok(Self {
            regression_id,
            draft,
        })
    }

    #[must_use]
    pub fn regression_id(&self) -> &str {
        &self.regression_id
    }

    #[must_use]
    pub fn draft(&self) -> &SecurityRegressionRecordDraft {
        &self.draft
    }
}

fn enforce_total_input_bytes(
    draft: &SecurityRegressionRecordDraft,
    limits: RegressionLimits,
) -> Result<(), RegressionModelError> {
    let mut total = 0usize;
    let max = limits.max_total_input_bytes;

    account_total_input_bytes(&mut total, draft.pair_id.len(), max)?;
    for value in [
        draft.base_invariant_id.as_deref(),
        draft.candidate_invariant_id.as_deref(),
        draft.base_definition_digest.as_deref(),
        draft.candidate_definition_digest.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        account_total_input_bytes(&mut total, value.len(), max)?;
    }

    for pair in &draft.coverage_pairs {
        account_total_input_bytes(&mut total, pair.comparison_key.len(), max)?;
        if let Some(reason) = pair.base_reason.as_deref() {
            account_total_input_bytes(&mut total, reason.len(), max)?;
        }
        if let Some(reason) = pair.candidate_reason.as_deref() {
            account_total_input_bytes(&mut total, reason.len(), max)?;
        }
    }

    for values in [
        &draft.base_supporting_evidence_refs,
        &draft.candidate_supporting_evidence_refs,
        &draft.base_provenance_refs,
        &draft.candidate_provenance_refs,
        &draft.graph_context_refs,
        &draft.diagnostics,
    ] {
        for value in values {
            account_total_input_bytes(&mut total, value.len(), max)?;
        }
    }

    Ok(())
}

fn account_total_input_bytes(
    total: &mut usize,
    bytes: usize,
    max: usize,
) -> Result<(), RegressionModelError> {
    *total = total
        .checked_add(bytes)
        .ok_or(RegressionModelError::TotalInputBytesExceeded { max })?;
    if *total > max {
        return Err(RegressionModelError::TotalInputBytesExceeded { max });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    limits: RegressionLimits,
) -> Result<(), RegressionModelError> {
    if value.trim().is_empty() {
        return Err(RegressionModelError::EmptyField(field));
    }
    if value.len() > limits.max_text_bytes {
        return Err(RegressionModelError::FieldTooLarge {
            field,
            bytes: value.len(),
            max: limits.max_text_bytes,
        });
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
    limits: RegressionLimits,
) -> Result<(), RegressionModelError> {
    if let Some(value) = value {
        validate_text(value, field, limits)?;
    }
    Ok(())
}

fn normalize_text_collection(
    values: Vec<String>,
    field: &'static str,
    max: usize,
    limits: RegressionLimits,
) -> Result<Vec<String>, RegressionModelError> {
    if values.len() > max {
        return Err(RegressionModelError::TooManyCollectionItems {
            field,
            count: values.len(),
            max,
        });
    }
    let mut normalized = BTreeSet::new();
    for value in values {
        validate_text(&value, field, limits)?;
        normalized.insert(value);
    }
    Ok(normalized.into_iter().collect())
}

fn invariant_state_name(value: Option<InvariantEvaluationState>) -> &'static str {
    match value {
        Some(InvariantEvaluationState::Satisfied) => "SATISFIED",
        Some(InvariantEvaluationState::Violated) => "VIOLATED",
        Some(InvariantEvaluationState::Unknown) => "UNKNOWN",
        Some(InvariantEvaluationState::NotApplicable) => "NOT_APPLICABLE",
        None => "ABSENT",
    }
}

fn coverage_state_name(value: Option<&CoverageState>) -> &'static str {
    match value {
        Some(CoverageState::Covered) => "COVERED",
        Some(CoverageState::Partial) => "PARTIAL",
        Some(CoverageState::Unsupported) => "UNSUPPORTED",
        Some(CoverageState::Unavailable) => "UNAVAILABLE",
        Some(CoverageState::Failed) => "FAILED",
        Some(CoverageState::TimedOut) => "TIMED_OUT",
        Some(CoverageState::SkippedByPolicy) => "SKIPPED_BY_POLICY",
        None => "ABSENT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_revision(role: RevisionRole, fixture: &str, digest: &str) -> RevisionIdentity {
        RevisionIdentity::fixture(role, fixture, digest, RegressionLimits::default())
            .expect("fixture revision")
    }

    fn producer(version: &str) -> ProducerContractIdentity {
        ProducerContractIdentity::new(
            "sentrdel.r3.business-logic",
            version,
            "config:fixture",
            "BUSINESS_LOGIC",
            "1",
            RegressionLimits::default(),
        )
        .expect("producer contract")
    }

    #[test]
    fn fixture_pair_identity_is_deterministic_and_role_ordered() {
        let first = RevisionPair::new(
            fixture_revision(RevisionRole::TrustedBase, "base", "digest:base"),
            fixture_revision(RevisionRole::Candidate, "candidate", "digest:candidate"),
        )
        .expect("first pair");
        let second = RevisionPair::new(
            fixture_revision(RevisionRole::TrustedBase, "base", "digest:base"),
            fixture_revision(RevisionRole::Candidate, "candidate", "digest:candidate"),
        )
        .expect("second pair");
        assert_eq!(first.pair_id(), second.pair_id());
        assert!(first.trusted_base().is_fixture_only());
        assert!(first.candidate().is_fixture_only());

        let reversed = RevisionPair::new(
            fixture_revision(RevisionRole::TrustedBase, "candidate", "digest:candidate"),
            fixture_revision(RevisionRole::Candidate, "base", "digest:base"),
        )
        .expect("reversed pair");
        assert_ne!(first.pair_id(), reversed.pair_id());
    }

    #[test]
    fn fixture_pair_rejects_same_exact_state_and_wrong_roles() {
        let same = RevisionPair::new(
            fixture_revision(RevisionRole::TrustedBase, "same", "digest:same"),
            fixture_revision(RevisionRole::Candidate, "same", "digest:same"),
        );
        assert!(matches!(
            same,
            Err(RegressionModelError::SameRevisionIdentity)
        ));

        let wrong = RevisionPair::new(
            fixture_revision(RevisionRole::Candidate, "base", "digest:base"),
            fixture_revision(RevisionRole::TrustedBase, "candidate", "digest:candidate"),
        );
        assert!(matches!(
            wrong,
            Err(RegressionModelError::InvalidRevisionRole)
        ));
    }

    #[test]
    fn snapshot_compatibility_is_exact_and_fail_visible() {
        let base = SemanticSnapshotContract::new(
            fixture_revision(RevisionRole::TrustedBase, "base", "digest:base"),
            "schema-v1",
            vec![producer("1")],
            vec!["profile:default".to_owned()],
            RegressionLimits::default(),
        )
        .expect("base snapshot");
        let candidate = SemanticSnapshotContract::new(
            fixture_revision(RevisionRole::Candidate, "candidate", "digest:candidate"),
            "schema-v1",
            vec![producer("1")],
            vec!["profile:default".to_owned()],
            RegressionLimits::default(),
        )
        .expect("candidate snapshot");
        assert_eq!(
            base.compatibility_with(&candidate),
            SnapshotCompatibility::Compatible
        );

        let changed_producer = SemanticSnapshotContract::new(
            fixture_revision(
                RevisionRole::Candidate,
                "candidate-v2",
                "digest:candidate-v2",
            ),
            "schema-v1",
            vec![producer("2")],
            vec!["profile:default".to_owned()],
            RegressionLimits::default(),
        )
        .expect("changed producer");
        assert_eq!(
            base.compatibility_with(&changed_producer),
            SnapshotCompatibility::ProducerContractMismatch
        );

        let changed_config = SemanticSnapshotContract::new(
            fixture_revision(
                RevisionRole::Candidate,
                "candidate-config",
                "digest:candidate-config",
            ),
            "schema-v1",
            vec![producer("1")],
            vec!["profile:strict".to_owned()],
            RegressionLimits::default(),
        )
        .expect("changed config");
        assert_eq!(
            base.compatibility_with(&changed_config),
            SnapshotCompatibility::ConfigurationIdentityMismatch
        );
    }

    #[test]
    fn frozen_transition_matrix_preserves_uncertainty() {
        let weakened = FROZEN_INVARIANT_TRANSITIONS
            .iter()
            .find(|rule| {
                rule.base == InvariantEvaluationState::Satisfied
                    && rule.candidate == InvariantEvaluationState::Violated
            })
            .expect("weakened transition");
        assert_eq!(
            weakened.allowed_dispositions,
            &[SecurityDeltaDisposition::Regression]
        );

        let lost = FROZEN_INVARIANT_TRANSITIONS
            .iter()
            .find(|rule| {
                rule.base == InvariantEvaluationState::Violated
                    && rule.candidate == InvariantEvaluationState::Unknown
            })
            .expect("coverage-loss transition");
        assert!(
            lost.allowed_dispositions
                .contains(&SecurityDeltaDisposition::CoverageLost)
        );
        assert!(
            lost.allowed_dispositions
                .contains(&SecurityDeltaDisposition::Unknown)
        );
        assert!(
            !lost
                .allowed_dispositions
                .contains(&SecurityDeltaDisposition::Improvement)
        );

        assert!(FROZEN_INVARIANT_TRANSITIONS.iter().all(|rule| {
            rule.base != InvariantEvaluationState::NotApplicable
                && rule.candidate != InvariantEvaluationState::NotApplicable
        }));
    }

    #[test]
    fn sealed_record_is_deterministic_and_keeps_bilateral_history() {
        let pair = RevisionPair::new(
            fixture_revision(RevisionRole::TrustedBase, "base", "digest:base"),
            fixture_revision(RevisionRole::Candidate, "candidate", "digest:candidate"),
        )
        .expect("pair");
        let coverage = CoveragePair::new(
            "BUSINESS_LOGIC:.",
            Some(CoverageState::Covered),
            Some(CoverageState::Covered),
            None,
            None,
            RegressionLimits::default(),
        )
        .expect("coverage pair");

        let build = |base_evidence: Vec<String>, candidate_evidence: Vec<String>| {
            SecurityRegressionRecord::seal(
                SecurityRegressionRecordDraft {
                    pair_id: pair.pair_id().to_owned(),
                    pair_presence: PairPresence::Matched,
                    continuity_basis: ContinuityBasis::ExactStableId,
                    base_invariant_id: Some("invariant:tenant".to_owned()),
                    candidate_invariant_id: Some("invariant:tenant".to_owned()),
                    base_definition_digest: Some("definition:tenant".to_owned()),
                    candidate_definition_digest: Some("definition:tenant".to_owned()),
                    base_evaluation_state: Some(InvariantEvaluationState::Satisfied),
                    candidate_evaluation_state: Some(InvariantEvaluationState::Violated),
                    disposition: SecurityDeltaDisposition::Regression,
                    reason_code: SecurityDeltaReason::InvariantStateWeakened,
                    coverage_pairs: vec![coverage.clone()],
                    base_supporting_evidence_refs: base_evidence,
                    candidate_supporting_evidence_refs: candidate_evidence,
                    base_provenance_refs: vec!["base:path:1".to_owned()],
                    candidate_provenance_refs: vec!["candidate:path:2".to_owned()],
                    graph_context_refs: Vec::new(),
                    diagnostics: Vec::new(),
                    resource_state: ResourceState::Complete,
                },
                RegressionLimits::default(),
            )
            .expect("record")
        };

        let first = build(
            vec!["evidence:b".to_owned(), "evidence:a".to_owned()],
            vec!["evidence:d".to_owned(), "evidence:c".to_owned()],
        );
        let second = build(
            vec!["evidence:a".to_owned(), "evidence:b".to_owned()],
            vec!["evidence:c".to_owned(), "evidence:d".to_owned()],
        );
        assert_eq!(first.regression_id(), second.regression_id());
        assert_eq!(
            first.draft().base_supporting_evidence_refs,
            vec!["evidence:a", "evidence:b"]
        );
        assert_eq!(
            first.draft().candidate_supporting_evidence_refs,
            vec!["evidence:c", "evidence:d"]
        );
        assert_ne!(
            first.draft().base_provenance_refs,
            first.draft().candidate_provenance_refs
        );
    }

    #[test]
    fn seal_rejects_aggregate_input_bytes_before_complete_record_creation() {
        let limits = RegressionLimits {
            max_total_input_bytes: 64,
            ..RegressionLimits::default()
        };
        let result = SecurityRegressionRecord::seal(
            SecurityRegressionRecordDraft {
                pair_id: "pair:aggregate-limit".to_owned(),
                pair_presence: PairPresence::Matched,
                continuity_basis: ContinuityBasis::ExactStableId,
                base_invariant_id: Some("invariant:base-limit".to_owned()),
                candidate_invariant_id: Some("invariant:candidate-limit".to_owned()),
                base_definition_digest: None,
                candidate_definition_digest: None,
                base_evaluation_state: Some(InvariantEvaluationState::Satisfied),
                candidate_evaluation_state: Some(InvariantEvaluationState::Satisfied),
                disposition: SecurityDeltaDisposition::Unchanged,
                reason_code: SecurityDeltaReason::InvariantStateUnchanged,
                coverage_pairs: Vec::new(),
                base_supporting_evidence_refs: vec!["evidence:base-limit".to_owned()],
                candidate_supporting_evidence_refs: Vec::new(),
                base_provenance_refs: Vec::new(),
                candidate_provenance_refs: Vec::new(),
                graph_context_refs: Vec::new(),
                diagnostics: Vec::new(),
                resource_state: ResourceState::Complete,
            },
            limits,
        );
        assert!(matches!(
            result,
            Err(RegressionModelError::TotalInputBytesExceeded { max: 64 })
        ));
    }

    #[test]
    fn limits_and_resource_cap_state_are_explicit() {
        assert!(RegressionLimits::default().validate().is_ok());
        assert!(matches!(
            RegressionLimits {
                max_pair_results: 0,
                ..RegressionLimits::default()
            }
            .validate(),
            Err(RegressionModelError::InvalidLimits)
        ));
        assert_eq!(ResourceState::CapReached.as_str(), "CAP_REACHED");
        assert_eq!(
            SecurityDeltaReason::ResourceCapReached.as_str(),
            "RESOURCE_CAP_REACHED"
        );
    }
}
