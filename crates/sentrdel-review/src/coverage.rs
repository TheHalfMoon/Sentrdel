//! Deterministic review coverage matrix aggregation.
//!
//! Coverage records remain the authority for producers that actually reported.
//! Missing expected producers are represented only as review-local matrix gaps;
//! this module does not forge producer CoverageRecords or infer secure posture.

use sentrdel_schema::coverage::{CoverageRecord, CoverageState};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const PRODUCER_NOT_REPORTED_REASON: &str = "PRODUCER_NOT_REPORTED";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReviewCoverageKey {
    pub capability: String,
    pub scope: String,
    pub producer: Option<String>,
}

impl ReviewCoverageKey {
    pub fn new(
        capability: impl Into<String>,
        scope: impl Into<String>,
        producer: Option<String>,
    ) -> Result<Self, ReviewCoverageError> {
        let capability = capability.into().trim().to_owned();
        let scope = scope.into().trim().to_owned();
        let producer = producer.map(|value| value.trim().to_owned());
        if capability.is_empty() {
            return Err(ReviewCoverageError::BlankCapability);
        }
        if scope.is_empty() {
            return Err(ReviewCoverageError::BlankScope);
        }
        if producer.as_deref().is_some_and(str::is_empty) {
            return Err(ReviewCoverageError::BlankProducer);
        }
        Ok(Self {
            capability,
            scope,
            producer,
        })
    }

    fn from_record(record: &CoverageRecord) -> Result<Self, ReviewCoverageError> {
        Self::new(
            record.capability.clone(),
            record.scope.clone(),
            record.producer.clone(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewCoverageSource {
    ObservedExpected,
    ObservedUnexpected,
    MissingExpected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewCoverageEntry {
    pub key: ReviewCoverageKey,
    pub state: CoverageState,
    pub coverage_id: Option<String>,
    pub reason_code: Option<String>,
    pub source: ReviewCoverageSource,
}

impl ReviewCoverageEntry {
    #[must_use]
    pub fn is_gap(&self) -> bool {
        self.state != CoverageState::Covered
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewCoverageMatrix {
    pub entries: Vec<ReviewCoverageEntry>,
    pub gap_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewCoverageError {
    BlankCapability,
    BlankScope,
    BlankProducer,
    BlankCoverageId,
    DuplicateExpectation(ReviewCoverageKey),
    DuplicateObservedCoverage(ReviewCoverageKey),
}

impl fmt::Display for ReviewCoverageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankCapability => {
                formatter.write_str("review coverage capability must not be blank")
            }
            Self::BlankScope => formatter.write_str("review coverage scope must not be blank"),
            Self::BlankProducer => {
                formatter.write_str("review coverage producer must not be blank")
            }
            Self::BlankCoverageId => formatter.write_str("observed coverage id must not be blank"),
            Self::DuplicateExpectation(key) => write!(
                formatter,
                "review coverage expectation is duplicated: {} / {} / {:?}",
                key.capability, key.scope, key.producer
            ),
            Self::DuplicateObservedCoverage(key) => write!(
                formatter,
                "observed review coverage is ambiguous for one producer capability: {} / {} / {:?}",
                key.capability, key.scope, key.producer
            ),
        }
    }
}

impl std::error::Error for ReviewCoverageError {}

/// Aggregate explicit producer coverage into a deterministic review matrix.
///
/// Every expected key appears exactly once. If a producer did not report, its
/// matrix row is `UNAVAILABLE` with `PRODUCER_NOT_REPORTED`; this is a local
/// coverage gap and not a fabricated CoverageRecord. Unexpected producer
/// records remain visible rather than being silently discarded. Multiple
/// records for the same producer/capability/scope are rejected as ambiguous.
pub fn aggregate_review_coverage(
    expected: &[ReviewCoverageKey],
    observed: &[CoverageRecord],
) -> Result<ReviewCoverageMatrix, ReviewCoverageError> {
    let mut expected_keys = BTreeSet::new();
    for key in expected {
        let validated = ReviewCoverageKey::new(
            key.capability.clone(),
            key.scope.clone(),
            key.producer.clone(),
        )?;
        if !expected_keys.insert(validated.clone()) {
            return Err(ReviewCoverageError::DuplicateExpectation(validated));
        }
    }

    let mut observed_by_key = BTreeMap::new();
    for record in observed {
        if record.coverage_id.trim().is_empty() {
            return Err(ReviewCoverageError::BlankCoverageId);
        }
        let key = ReviewCoverageKey::from_record(record)?;
        if observed_by_key.insert(key.clone(), record).is_some() {
            return Err(ReviewCoverageError::DuplicateObservedCoverage(key));
        }
    }

    let mut entries = Vec::with_capacity(expected_keys.len() + observed_by_key.len());
    for key in &expected_keys {
        match observed_by_key.remove(key) {
            Some(record) => entries.push(observed_entry(
                key.clone(),
                record,
                ReviewCoverageSource::ObservedExpected,
            )),
            None => entries.push(ReviewCoverageEntry {
                key: key.clone(),
                state: CoverageState::Unavailable,
                coverage_id: None,
                reason_code: Some(PRODUCER_NOT_REPORTED_REASON.to_owned()),
                source: ReviewCoverageSource::MissingExpected,
            }),
        }
    }

    for (key, record) in observed_by_key {
        entries.push(observed_entry(
            key,
            record,
            ReviewCoverageSource::ObservedUnexpected,
        ));
    }

    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let gap_count = entries.iter().filter(|entry| entry.is_gap()).count();
    Ok(ReviewCoverageMatrix { entries, gap_count })
}

fn observed_entry(
    key: ReviewCoverageKey,
    record: &CoverageRecord,
    source: ReviewCoverageSource,
) -> ReviewCoverageEntry {
    ReviewCoverageEntry {
        key,
        state: record.state.clone(),
        coverage_id: Some(record.coverage_id.clone()),
        reason_code: record.reason_code.clone(),
        source,
    }
}
