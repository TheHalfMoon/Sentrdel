use sentrdel_review::coverage::{
    PRODUCER_NOT_REPORTED_REASON, ReviewCoverageError, ReviewCoverageKey, ReviewCoverageSource,
    aggregate_review_coverage,
};
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::{CoverageRecord, CoverageState};

fn key(producer: &str, capability: &str) -> ReviewCoverageKey {
    ReviewCoverageKey::new(capability, ".", Some(producer.to_owned())).unwrap()
}

fn record(
    coverage_id: &str,
    producer: &str,
    capability: &str,
    state: CoverageState,
    reason_code: Option<&str>,
) -> CoverageRecord {
    CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: coverage_id.to_owned(),
        capability: capability.to_owned(),
        scope: ".".to_owned(),
        producer: Some(producer.to_owned()),
        provider_dimension: None,
        state,
        reason_code: reason_code.map(str::to_owned),
        details: None,
        input_digests: vec!["sha256:fixture".to_owned()],
        observed_at: "2026-08-28T19:00:00Z".to_owned(),
    }
}

#[test]
fn missing_expected_producer_is_visible_as_unavailable_gap() {
    let matrix = aggregate_review_coverage(
        &[
            key("secret", "changed-secret"),
            key("gha", "github-actions"),
        ],
        &[record(
            "coverage:secret",
            "secret",
            "changed-secret",
            CoverageState::Covered,
            None,
        )],
    )
    .unwrap();

    assert_eq!(matrix.entries.len(), 2);
    assert_eq!(matrix.gap_count, 1);
    let missing = matrix
        .entries
        .iter()
        .find(|entry| entry.key.producer.as_deref() == Some("gha"))
        .unwrap();
    assert_eq!(missing.state, CoverageState::Unavailable);
    assert_eq!(missing.source, ReviewCoverageSource::MissingExpected);
    assert_eq!(missing.coverage_id, None);
    assert_eq!(
        missing.reason_code.as_deref(),
        Some(PRODUCER_NOT_REPORTED_REASON)
    );
}

#[test]
fn failed_and_timed_out_producers_remain_explicit_gaps() {
    let expected = [
        key("semgrep", "static-analysis"),
        key("osv", "dependency-advisories"),
    ];
    let matrix = aggregate_review_coverage(
        &expected,
        &[
            record(
                "coverage:semgrep",
                "semgrep",
                "static-analysis",
                CoverageState::Failed,
                Some("ENGINE_MALFORMED_OUTPUT"),
            ),
            record(
                "coverage:osv",
                "osv",
                "dependency-advisories",
                CoverageState::TimedOut,
                Some("ENGINE_TIMEOUT"),
            ),
        ],
    )
    .unwrap();

    assert_eq!(matrix.gap_count, 2);
    assert!(matrix.entries.iter().all(|entry| entry.is_gap()));
    assert!(
        matrix
            .entries
            .iter()
            .all(|entry| entry.source == ReviewCoverageSource::ObservedExpected)
    );
}

#[test]
fn unexpected_observed_producer_is_retained_in_deterministic_order() {
    let matrix = aggregate_review_coverage(
        &[key("gha", "github-actions")],
        &[
            record(
                "coverage:structural",
                "structural",
                "native-structural",
                CoverageState::Partial,
                Some("LIMITED_RULESET"),
            ),
            record(
                "coverage:gha",
                "gha",
                "github-actions",
                CoverageState::Covered,
                None,
            ),
        ],
    )
    .unwrap();

    assert_eq!(matrix.entries.len(), 2);
    assert_eq!(matrix.gap_count, 1);
    assert_eq!(matrix.entries[0].key.capability.as_str(), "github-actions");
    assert_eq!(
        matrix.entries[0].source,
        ReviewCoverageSource::ObservedExpected
    );
    assert_eq!(
        matrix.entries[1].source,
        ReviewCoverageSource::ObservedUnexpected
    );
}

#[test]
fn duplicate_expectation_or_observed_key_fails_closed() {
    let duplicate_key = key("gha", "github-actions");
    assert!(matches!(
        aggregate_review_coverage(&[duplicate_key.clone(), duplicate_key], &[]),
        Err(ReviewCoverageError::DuplicateExpectation(_))
    ));

    assert!(matches!(
        aggregate_review_coverage(
            &[key("gha", "github-actions")],
            &[
                record(
                    "coverage:gha-1",
                    "gha",
                    "github-actions",
                    CoverageState::Covered,
                    None,
                ),
                record(
                    "coverage:gha-2",
                    "gha",
                    "github-actions",
                    CoverageState::Failed,
                    Some("DUPLICATE_FIXTURE"),
                ),
            ],
        ),
        Err(ReviewCoverageError::DuplicateObservedCoverage(_))
    ));
}
