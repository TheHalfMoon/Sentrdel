//! Monotonic R3 business-logic coverage aggregation.
//!
//! Coverage is independent from Findings. Every frozen R3 coverage area must be
//! present exactly once, and any non-covered required area keeps the aggregate
//! non-covered. This module does not create CoverageRecords or Findings, execute
//! target code, access providers, or widen runtime/network authority.

use std::{collections::BTreeMap, error::Error, fmt};

use sentrdel_schema::coverage::CoverageState;

use super::model::{BusinessLogicCoverage, BusinessLogicCoverageArea};

pub const R3_COVERAGE_DEPENDS_ON_FINDINGS: bool = false;
pub const R3_COVERAGE_CREATES_FINDINGS: bool = false;
pub const R3_COVERAGE_EXECUTES_TARGET_CODE: bool = false;
pub const R3_COVERAGE_PERFORMS_NETWORK_ACCESS: bool = false;

pub const REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS: [BusinessLogicCoverageArea; 10] = [
    BusinessLogicCoverageArea::Routes,
    BusinessLogicCoverageArea::ActorIdentity,
    BusinessLogicCoverageArea::Guards,
    BusinessLogicCoverageArea::ValueOrigins,
    BusinessLogicCoverageArea::DataOperations,
    BusinessLogicCoverageArea::LocalLinking,
    BusinessLogicCoverageArea::SemanticLinking,
    BusinessLogicCoverageArea::R2ProviderCorrelation,
    BusinessLogicCoverageArea::ProjectInvariants,
    BusinessLogicCoverageArea::InvariantEvaluation,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessLogicCoverageAggregate {
    areas: Vec<BusinessLogicCoverage>,
    state: CoverageState,
}

impl BusinessLogicCoverageAggregate {
    #[must_use]
    pub fn areas(&self) -> &[BusinessLogicCoverage] {
        &self.areas
    }

    #[must_use]
    pub fn state(&self) -> &CoverageState {
        &self.state
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == CoverageState::Covered
    }

    #[must_use]
    pub fn gap_areas(&self) -> Vec<BusinessLogicCoverageArea> {
        self.areas
            .iter()
            .filter(|coverage| coverage.state() != &CoverageState::Covered)
            .map(BusinessLogicCoverage::area)
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BusinessLogicCoverageAggregationError {
    DuplicateArea(BusinessLogicCoverageArea),
    MissingArea(BusinessLogicCoverageArea),
}

impl fmt::Display for BusinessLogicCoverageAggregationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateArea(area) => {
                write!(
                    formatter,
                    "R3 business-logic coverage area is duplicated: {area:?}"
                )
            }
            Self::MissingArea(area) => {
                write!(
                    formatter,
                    "R3 business-logic coverage area is missing: {area:?}"
                )
            }
        }
    }
}

impl Error for BusinessLogicCoverageAggregationError {}

/// Aggregate the complete frozen R3 coverage matrix without consulting Findings.
///
/// Input order cannot affect output order or aggregate state. Missing or duplicate
/// required areas fail closed. The aggregate is `Covered` only when every required
/// area is `Covered`; otherwise a deterministic gap precedence preserves a concrete
/// non-covered state while the ordered area matrix retains every original state.
pub fn aggregate_business_logic_coverage(
    coverage: &[BusinessLogicCoverage],
) -> Result<BusinessLogicCoverageAggregate, BusinessLogicCoverageAggregationError> {
    let mut by_area = BTreeMap::new();
    for entry in coverage {
        let area = entry.area();
        if by_area.insert(area, entry).is_some() {
            return Err(BusinessLogicCoverageAggregationError::DuplicateArea(area));
        }
    }

    let mut ordered = Vec::with_capacity(REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS.len());
    for area in REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS {
        let entry = by_area
            .remove(&area)
            .ok_or(BusinessLogicCoverageAggregationError::MissingArea(area))?;
        ordered.push(entry.clone());
    }

    let state = aggregate_state(&ordered);
    Ok(BusinessLogicCoverageAggregate {
        areas: ordered,
        state,
    })
}

fn aggregate_state(coverage: &[BusinessLogicCoverage]) -> CoverageState {
    // Precedence is deterministic and conservative, not a claim that one gap is
    // semantically safer than another. Detailed area states are always retained.
    for state in [
        CoverageState::Failed,
        CoverageState::TimedOut,
        CoverageState::Unsupported,
        CoverageState::Unavailable,
        CoverageState::SkippedByPolicy,
        CoverageState::Partial,
    ] {
        if coverage.iter().any(|entry| entry.state() == &state) {
            return state;
        }
    }
    CoverageState::Covered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business_logic::{R3_BUSINESS_LOGIC_COVERAGE_AREAS, model::BusinessLogicLimits};

    fn coverage(area: BusinessLogicCoverageArea, state: CoverageState) -> BusinessLogicCoverage {
        BusinessLogicCoverage::new(
            area,
            state,
            "R3_COVERAGE_FIXTURE",
            ".",
            Vec::new(),
            "sentrdel.r3.fixture",
            BusinessLogicLimits::default(),
        )
        .expect("valid fixture coverage")
    }

    fn complete_matrix() -> Vec<BusinessLogicCoverage> {
        REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
            .into_iter()
            .map(|area| coverage(area, CoverageState::Covered))
            .collect()
    }

    #[test]
    fn frozen_area_order_matches_pack_contract() {
        assert_eq!(
            R3_BUSINESS_LOGIC_COVERAGE_AREAS,
            [
                "ROUTES",
                "ACTOR_IDENTITY",
                "GUARDS",
                "VALUE_ORIGINS",
                "DATA_OPERATIONS",
                "LOCAL_LINKING",
                "SEMANTIC_LINKING",
                "R2_PROVIDER_CORRELATION",
                "PROJECT_INVARIANTS",
                "INVARIANT_EVALUATION",
            ]
        );
        assert_eq!(REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS.len(), 10);
    }

    #[test]
    fn all_required_areas_must_be_covered_for_clean_aggregate() {
        let aggregate = aggregate_business_logic_coverage(&complete_matrix()).unwrap();
        assert_eq!(aggregate.state(), &CoverageState::Covered);
        assert!(aggregate.is_complete());
        assert!(aggregate.gap_areas().is_empty());
    }

    #[test]
    fn every_canonical_gap_state_keeps_the_aggregate_non_clean() {
        for gap_state in [
            CoverageState::Partial,
            CoverageState::Unsupported,
            CoverageState::Unavailable,
            CoverageState::Failed,
            CoverageState::TimedOut,
            CoverageState::SkippedByPolicy,
        ] {
            let mut matrix = complete_matrix();
            matrix[4] = coverage(BusinessLogicCoverageArea::DataOperations, gap_state.clone());
            let aggregate = aggregate_business_logic_coverage(&matrix).unwrap();
            assert_eq!(aggregate.state(), &gap_state);
            assert!(!aggregate.is_complete());
            assert_eq!(
                aggregate.gap_areas(),
                vec![BusinessLogicCoverageArea::DataOperations]
            );
        }
    }

    #[test]
    fn hard_gap_precedence_is_deterministic_and_preserves_all_area_states() {
        let mut matrix = complete_matrix();
        matrix[0] = coverage(BusinessLogicCoverageArea::Routes, CoverageState::Partial);
        matrix[5] = coverage(
            BusinessLogicCoverageArea::LocalLinking,
            CoverageState::Unsupported,
        );
        matrix[7] = coverage(
            BusinessLogicCoverageArea::R2ProviderCorrelation,
            CoverageState::Failed,
        );

        let aggregate = aggregate_business_logic_coverage(&matrix).unwrap();
        assert_eq!(aggregate.state(), &CoverageState::Failed);
        assert_eq!(
            aggregate.gap_areas(),
            vec![
                BusinessLogicCoverageArea::Routes,
                BusinessLogicCoverageArea::LocalLinking,
                BusinessLogicCoverageArea::R2ProviderCorrelation,
            ]
        );
    }

    #[test]
    fn input_permutation_cannot_change_the_aggregate_or_area_order() {
        let mut matrix = complete_matrix();
        matrix[6] = coverage(
            BusinessLogicCoverageArea::SemanticLinking,
            CoverageState::Unavailable,
        );
        let expected = aggregate_business_logic_coverage(&matrix).unwrap();

        matrix.reverse();
        let replay = aggregate_business_logic_coverage(&matrix).unwrap();
        assert_eq!(replay, expected);
    }

    #[test]
    fn missing_or_duplicate_areas_fail_closed() {
        let mut missing = complete_matrix();
        missing.retain(|entry| entry.area() != BusinessLogicCoverageArea::InvariantEvaluation);
        assert_eq!(
            aggregate_business_logic_coverage(&missing),
            Err(BusinessLogicCoverageAggregationError::MissingArea(
                BusinessLogicCoverageArea::InvariantEvaluation
            ))
        );

        let mut duplicate = complete_matrix();
        duplicate.push(coverage(
            BusinessLogicCoverageArea::Routes,
            CoverageState::Covered,
        ));
        assert_eq!(
            aggregate_business_logic_coverage(&duplicate),
            Err(BusinessLogicCoverageAggregationError::DuplicateArea(
                BusinessLogicCoverageArea::Routes
            ))
        );
    }

    #[test]
    fn coverage_authority_is_independent_from_findings_and_execution() {
        const { assert!(!R3_COVERAGE_DEPENDS_ON_FINDINGS) };
        const { assert!(!R3_COVERAGE_CREATES_FINDINGS) };
        const { assert!(!R3_COVERAGE_EXECUTES_TARGET_CODE) };
        const { assert!(!R3_COVERAGE_PERFORMS_NETWORK_ACCESS) };
    }
}
