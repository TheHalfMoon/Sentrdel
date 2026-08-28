#![forbid(unsafe_code)]

use sentrdel_schema::{
    SCHEMA_V1,
    canonical::{CanonicalError, canonical_json_bytes, content_id},
    finding::Severity,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

const EVALUATOR_VERSION: &str = "sentrdelbench-core/t089-v1";
const METRIC_CONTRACT_VERSION: &str = "sentrdelbench-contract/t088-r1-v1";
const EVALUATOR_SOURCE: &str = include_str!("t089_benchmark_core.rs");
const METRIC_CONTRACT_SOURCE: &str = include_str!("../../../docs/security/evaluation-contract.md");
const CORE_CORPUS_BYTES: &[u8] = include_bytes!("../../../tests/benchmark/t089-core-corpus.json");
const _: () = assert!(!sentrdel_review::TARGET_BUILD_EXECUTION_ALLOWED);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CorpusClass {
    PublicRegression,
    DevelopmentEvaluation,
    ProtectedHoldout,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CoverageState {
    Completed,
    Partial,
    Unavailable,
    Failed,
    Skipped,
    TimedOut,
    Unsupported,
}

impl CoverageState {
    fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FindingExpectation {
    finding_id: String,
    severity: Severity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EmittedFinding {
    finding_id: String,
    severity: Severity,
    evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ProvenanceExpectation {
    finding_id: String,
    required_evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ObservedCoverage {
    dimension: String,
    state: CoverageState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct BenchmarkCase {
    case_id: String,
    known_evidence_ids: Vec<String>,
    expected_findings: Vec<FindingExpectation>,
    emitted_findings: Vec<EmittedFinding>,
    expected_provenance: Vec<ProvenanceExpectation>,
    expected_coverage: Vec<String>,
    observed_coverage: Vec<ObservedCoverage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AuthorityAssertion {
    assertion_id: String,
    passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MachineMetadata {
    os: String,
    architecture: String,
    runner: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PerformanceMeasurement {
    measurement_policy: String,
    mode: String,
    workload_size: u64,
    elapsed_ms: u64,
    machine: Option<MachineMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CorpusFixture {
    corpus_revision: String,
    expected_outputs_revision: String,
    corpus_class: CorpusClass,
    baseline_identity: String,
    candidate_identity: String,
    cases: Vec<BenchmarkCase>,
    authority_assertions: Vec<AuthorityAssertion>,
    performance: Option<PerformanceMeasurement>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum MetricState {
    Measured,
    NotApplicable,
    NotMeasured,
    UnqualifiedMeasurement,
    EvaluationError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RatioMetric {
    state: MetricState,
    numerator: Option<u64>,
    denominator: Option<u64>,
}

impl RatioMetric {
    fn from_parts(numerator: u64, denominator: u64) -> Self {
        if denominator == 0 {
            Self {
                state: MetricState::NotApplicable,
                numerator: None,
                denominator: None,
            }
        } else {
            Self {
                state: MetricState::Measured,
                numerator: Some(numerator),
                denominator: Some(denominator),
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ContentIdentity {
    version: String,
    digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct CorpusIdentity {
    class: CorpusClass,
    revision: String,
    digest: String,
    expected_outputs_revision: String,
    expected_outputs_digest: String,
    case_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct FindingMetrics {
    true_positive: u64,
    false_negative: u64,
    false_positive: u64,
    known_ground_truth_recall: RatioMetric,
    known_ground_truth_miss_rate: RatioMetric,
    high_severity_expected: u64,
    high_severity_true_positive: u64,
    high_severity_false_negative: u64,
    high_severity_false_positive: u64,
    high_severity_precision: RatioMetric,
    severity_mismatch_count: u64,
    clean_cases_evaluated: u64,
    clean_cases_with_false_positive: u64,
    clean_case_false_positive_rate: RatioMetric,
    false_positive_findings_on_clean_cases: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct CoverageMetrics {
    expected_dimensions: u64,
    completed_dimensions: u64,
    gap_dimensions: u64,
    missing_coverage_records: u64,
    unexpected_coverage_records: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ProvenanceMetrics {
    required_objects: u64,
    complete_objects: u64,
    incomplete_objects: u64,
    dangling_references: u64,
    completeness: RatioMetric,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum ReplayStatus {
    #[serde(rename = "REPLAY_EQUAL")]
    Equal,
    #[serde(rename = "REPLAY_DIFFERENT")]
    Different,
    #[serde(rename = "REPLAY_NOT_MEASURED")]
    NotMeasured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ReplayRecord {
    status: ReplayStatus,
    differing_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct AuthorityMetrics {
    assertions: Vec<AuthorityAssertion>,
    failed_assertions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct PerformanceRecord {
    state: MetricState,
    measurement_policy: Option<String>,
    mode: Option<String>,
    workload_size: Option<u64>,
    elapsed_ms: Option<u64>,
    machine: Option<MachineMetadata>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct BenchmarkRunRecord {
    schema_version: String,
    evaluator: ContentIdentity,
    metric_contract: ContentIdentity,
    corpus: CorpusIdentity,
    baseline_identity: String,
    candidate_identity: String,
    findings: FindingMetrics,
    coverage: CoverageMetrics,
    provenance: ProvenanceMetrics,
    replay: ReplayRecord,
    authority: AuthorityMetrics,
    performance: PerformanceRecord,
    diagnostics: Vec<String>,
}

impl BenchmarkRunRecord {
    fn to_json_line(&self) -> Result<String, EvaluationError> {
        let mut bytes = canonical_json_bytes(self)?;
        bytes.push(b'\n');
        String::from_utf8(bytes).map_err(EvaluationError::Utf8)
    }
}

#[derive(Debug)]
enum EvaluationError {
    Json(serde_json::Error),
    Canonical(CanonicalError),
    Utf8(std::string::FromUtf8Error),
    EmptyIdentity(&'static str),
    DuplicateCaseId(String),
    DuplicateExpectedFinding { case_id: String, finding_id: String },
    DuplicateEmittedFinding { case_id: String, finding_id: String },
    DuplicateCoverageDimension { case_id: String, dimension: String },
    DuplicateProvenanceExpectation { case_id: String, finding_id: String },
    DuplicateAuthorityAssertion(String),
    NonDeterministicEvaluator,
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "benchmark fixture JSON is invalid: {error}"),
            Self::Canonical(error) => {
                write!(formatter, "benchmark canonicalization failed: {error}")
            }
            Self::Utf8(error) => write!(formatter, "benchmark JSON was not UTF-8: {error}"),
            Self::EmptyIdentity(field) => write!(formatter, "benchmark identity is empty: {field}"),
            Self::DuplicateCaseId(case_id) => {
                write!(formatter, "duplicate benchmark case id: {case_id}")
            }
            Self::DuplicateExpectedFinding {
                case_id,
                finding_id,
            } => write!(
                formatter,
                "duplicate expected finding {finding_id} in benchmark case {case_id}"
            ),
            Self::DuplicateEmittedFinding {
                case_id,
                finding_id,
            } => write!(
                formatter,
                "duplicate emitted finding {finding_id} in benchmark case {case_id}"
            ),
            Self::DuplicateCoverageDimension { case_id, dimension } => write!(
                formatter,
                "duplicate observed coverage dimension {dimension} in benchmark case {case_id}"
            ),
            Self::DuplicateProvenanceExpectation {
                case_id,
                finding_id,
            } => write!(
                formatter,
                "duplicate provenance expectation for {finding_id} in benchmark case {case_id}"
            ),
            Self::DuplicateAuthorityAssertion(assertion_id) => {
                write!(formatter, "duplicate authority assertion: {assertion_id}")
            }
            Self::NonDeterministicEvaluator => formatter.write_str(
                "identical immutable benchmark inputs produced different canonical run records",
            ),
        }
    }
}

impl Error for EvaluationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::Utf8(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for EvaluationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<CanonicalError> for EvaluationError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

fn load_core_fixture() -> Result<CorpusFixture, EvaluationError> {
    Ok(serde_json::from_slice(CORE_CORPUS_BYTES)?)
}

fn is_high_severity(severity: &Severity) -> bool {
    matches!(severity, Severity::Block | Severity::High)
}

fn evaluate_replayed(
    fixture: &CorpusFixture,
    corpus_bytes: &[u8],
) -> Result<BenchmarkRunRecord, EvaluationError> {
    let first = evaluate_once(fixture, corpus_bytes)?;
    let second = evaluate_once(fixture, corpus_bytes)?;
    if first.to_json_line()? != second.to_json_line()? {
        return Err(EvaluationError::NonDeterministicEvaluator);
    }

    let mut qualified = first;
    qualified.replay = ReplayRecord {
        status: ReplayStatus::Equal,
        differing_fields: Vec::new(),
    };
    Ok(qualified)
}

fn evaluate_once(
    fixture: &CorpusFixture,
    corpus_bytes: &[u8],
) -> Result<BenchmarkRunRecord, EvaluationError> {
    validate_fixture(fixture)?;

    let evaluator = ContentIdentity {
        version: EVALUATOR_VERSION.to_owned(),
        digest: content_id("benchmark-evaluator-source", &EVALUATOR_SOURCE)?,
    };
    let metric_contract = ContentIdentity {
        version: METRIC_CONTRACT_VERSION.to_owned(),
        digest: content_id("benchmark-metric-contract", &METRIC_CONTRACT_SOURCE)?,
    };

    let mut case_ids = fixture
        .cases
        .iter()
        .map(|case| case.case_id.clone())
        .collect::<Vec<_>>();
    case_ids.sort();

    let expected_projection = fixture
        .cases
        .iter()
        .map(|case| {
            (
                case.case_id.as_str(),
                &case.expected_findings,
                &case.expected_provenance,
                &case.expected_coverage,
            )
        })
        .collect::<Vec<_>>();

    let corpus = CorpusIdentity {
        class: fixture.corpus_class.clone(),
        revision: fixture.corpus_revision.clone(),
        digest: content_id("benchmark-corpus", &corpus_bytes)?,
        expected_outputs_revision: fixture.expected_outputs_revision.clone(),
        expected_outputs_digest: content_id(
            "benchmark-expected-output",
            &(
                fixture.expected_outputs_revision.as_str(),
                expected_projection,
                &fixture.authority_assertions,
            ),
        )?,
        case_ids,
    };

    let findings = evaluate_findings(&fixture.cases);
    let coverage = evaluate_coverage(&fixture.cases)?;
    let provenance = evaluate_provenance(&fixture.cases)?;
    let authority = evaluate_authority(&fixture.authority_assertions)?;
    let performance = evaluate_performance(fixture.performance.as_ref());
    let mut diagnostics = Vec::new();
    if performance.state == MetricState::UnqualifiedMeasurement {
        diagnostics.push(
            "performance measurement is present without required machine metadata".to_owned(),
        );
    }

    Ok(BenchmarkRunRecord {
        schema_version: SCHEMA_V1.to_owned(),
        evaluator,
        metric_contract,
        corpus,
        baseline_identity: fixture.baseline_identity.clone(),
        candidate_identity: fixture.candidate_identity.clone(),
        findings,
        coverage,
        provenance,
        replay: ReplayRecord {
            status: ReplayStatus::NotMeasured,
            differing_fields: Vec::new(),
        },
        authority,
        performance,
        diagnostics,
    })
}

fn validate_fixture(fixture: &CorpusFixture) -> Result<(), EvaluationError> {
    for (name, value) in [
        ("corpus_revision", fixture.corpus_revision.as_str()),
        (
            "expected_outputs_revision",
            fixture.expected_outputs_revision.as_str(),
        ),
        ("baseline_identity", fixture.baseline_identity.as_str()),
        ("candidate_identity", fixture.candidate_identity.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(EvaluationError::EmptyIdentity(name));
        }
    }

    let mut case_ids = BTreeSet::new();
    for case in &fixture.cases {
        if case.case_id.trim().is_empty() {
            return Err(EvaluationError::EmptyIdentity("case_id"));
        }
        if !case_ids.insert(case.case_id.as_str()) {
            return Err(EvaluationError::DuplicateCaseId(case.case_id.clone()));
        }

        let mut expected_ids = BTreeSet::new();
        for expected in &case.expected_findings {
            if !expected_ids.insert(expected.finding_id.as_str()) {
                return Err(EvaluationError::DuplicateExpectedFinding {
                    case_id: case.case_id.clone(),
                    finding_id: expected.finding_id.clone(),
                });
            }
        }

        let mut emitted_ids = BTreeSet::new();
        for emitted in &case.emitted_findings {
            if !emitted_ids.insert(emitted.finding_id.as_str()) {
                return Err(EvaluationError::DuplicateEmittedFinding {
                    case_id: case.case_id.clone(),
                    finding_id: emitted.finding_id.clone(),
                });
            }
        }

        let mut coverage_dimensions = BTreeSet::new();
        for observed in &case.observed_coverage {
            if !coverage_dimensions.insert(observed.dimension.as_str()) {
                return Err(EvaluationError::DuplicateCoverageDimension {
                    case_id: case.case_id.clone(),
                    dimension: observed.dimension.clone(),
                });
            }
        }

        let mut provenance_ids = BTreeSet::new();
        for expected in &case.expected_provenance {
            if !provenance_ids.insert(expected.finding_id.as_str()) {
                return Err(EvaluationError::DuplicateProvenanceExpectation {
                    case_id: case.case_id.clone(),
                    finding_id: expected.finding_id.clone(),
                });
            }
        }
    }

    let mut authority_ids = BTreeSet::new();
    for assertion in &fixture.authority_assertions {
        if assertion.assertion_id.trim().is_empty() {
            return Err(EvaluationError::EmptyIdentity("authority_assertion_id"));
        }
        if !authority_ids.insert(assertion.assertion_id.as_str()) {
            return Err(EvaluationError::DuplicateAuthorityAssertion(
                assertion.assertion_id.clone(),
            ));
        }
    }

    Ok(())
}

fn evaluate_findings(cases: &[BenchmarkCase]) -> FindingMetrics {
    let mut true_positive = 0_u64;
    let mut false_negative = 0_u64;
    let mut false_positive = 0_u64;
    let mut high_severity_expected = 0_u64;
    let mut high_severity_true_positive = 0_u64;
    let mut high_severity_false_negative = 0_u64;
    let mut high_severity_false_positive = 0_u64;
    let mut severity_mismatch_count = 0_u64;
    let mut clean_cases_evaluated = 0_u64;
    let mut clean_cases_with_false_positive = 0_u64;
    let mut false_positive_findings_on_clean_cases = 0_u64;

    for case in cases {
        let expected = case
            .expected_findings
            .iter()
            .map(|finding| (finding.finding_id.as_str(), finding))
            .collect::<BTreeMap<_, _>>();
        let emitted = case
            .emitted_findings
            .iter()
            .map(|finding| (finding.finding_id.as_str(), finding))
            .collect::<BTreeMap<_, _>>();

        if expected.is_empty() {
            clean_cases_evaluated += 1;
            if !emitted.is_empty() {
                clean_cases_with_false_positive += 1;
                false_positive_findings_on_clean_cases += emitted.len() as u64;
            }
        }

        for expected_finding in expected.values() {
            match emitted.get(expected_finding.finding_id.as_str()) {
                Some(emitted_finding) => {
                    true_positive += 1;
                    if emitted_finding.severity != expected_finding.severity {
                        severity_mismatch_count += 1;
                    }
                }
                None => false_negative += 1,
            }

            if is_high_severity(&expected_finding.severity) {
                high_severity_expected += 1;
                match emitted.get(expected_finding.finding_id.as_str()) {
                    Some(emitted_finding) if is_high_severity(&emitted_finding.severity) => {
                        high_severity_true_positive += 1;
                    }
                    _ => high_severity_false_negative += 1,
                }
            }
        }

        for emitted_finding in emitted.values() {
            if !expected.contains_key(emitted_finding.finding_id.as_str()) {
                false_positive += 1;
            }
            if is_high_severity(&emitted_finding.severity)
                && expected
                    .get(emitted_finding.finding_id.as_str())
                    .is_none_or(|expected_finding| !is_high_severity(&expected_finding.severity))
            {
                high_severity_false_positive += 1;
            }
        }
    }

    let expected_total = true_positive + false_negative;
    FindingMetrics {
        true_positive,
        false_negative,
        false_positive,
        known_ground_truth_recall: RatioMetric::from_parts(true_positive, expected_total),
        known_ground_truth_miss_rate: RatioMetric::from_parts(false_negative, expected_total),
        high_severity_expected,
        high_severity_true_positive,
        high_severity_false_negative,
        high_severity_false_positive,
        high_severity_precision: RatioMetric::from_parts(
            high_severity_true_positive,
            high_severity_true_positive + high_severity_false_positive,
        ),
        severity_mismatch_count,
        clean_cases_evaluated,
        clean_cases_with_false_positive,
        clean_case_false_positive_rate: RatioMetric::from_parts(
            clean_cases_with_false_positive,
            clean_cases_evaluated,
        ),
        false_positive_findings_on_clean_cases,
    }
}

fn evaluate_coverage(cases: &[BenchmarkCase]) -> Result<CoverageMetrics, EvaluationError> {
    let mut expected_dimensions = 0_u64;
    let mut completed_dimensions = 0_u64;
    let mut gap_dimensions = 0_u64;
    let mut missing_coverage_records = 0_u64;
    let mut unexpected_coverage_records = 0_u64;

    for case in cases {
        let expected = case
            .expected_coverage
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let observed = case
            .observed_coverage
            .iter()
            .map(|coverage| (coverage.dimension.as_str(), &coverage.state))
            .collect::<BTreeMap<_, _>>();

        expected_dimensions += expected.len() as u64;
        for dimension in &expected {
            match observed.get(dimension) {
                Some(state) if state.is_completed() => completed_dimensions += 1,
                Some(_) => gap_dimensions += 1,
                None => {
                    gap_dimensions += 1;
                    missing_coverage_records += 1;
                }
            }
        }
        unexpected_coverage_records += observed
            .keys()
            .filter(|dimension| !expected.contains(**dimension))
            .count() as u64;
    }

    Ok(CoverageMetrics {
        expected_dimensions,
        completed_dimensions,
        gap_dimensions,
        missing_coverage_records,
        unexpected_coverage_records,
    })
}

fn evaluate_provenance(cases: &[BenchmarkCase]) -> Result<ProvenanceMetrics, EvaluationError> {
    let mut required_objects = 0_u64;
    let mut complete_objects = 0_u64;
    let mut incomplete_objects = 0_u64;
    let mut dangling_references = 0_u64;

    for case in cases {
        let known_evidence = case
            .known_evidence_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let emitted = case
            .emitted_findings
            .iter()
            .map(|finding| (finding.finding_id.as_str(), finding))
            .collect::<BTreeMap<_, _>>();

        for emitted_finding in emitted.values() {
            dangling_references += emitted_finding
                .evidence_ids
                .iter()
                .filter(|evidence_id| !known_evidence.contains(evidence_id.as_str()))
                .count() as u64;
        }

        for expectation in &case.expected_provenance {
            required_objects += 1;
            let complete =
                emitted
                    .get(expectation.finding_id.as_str())
                    .is_some_and(|emitted_finding| {
                        let actual = emitted_finding
                            .evidence_ids
                            .iter()
                            .map(String::as_str)
                            .collect::<BTreeSet<_>>();
                        expectation
                            .required_evidence_ids
                            .iter()
                            .all(|required| actual.contains(required.as_str()))
                    });
            if complete {
                complete_objects += 1;
            } else {
                incomplete_objects += 1;
            }
        }
    }

    Ok(ProvenanceMetrics {
        required_objects,
        complete_objects,
        incomplete_objects,
        dangling_references,
        completeness: RatioMetric::from_parts(complete_objects, required_objects),
    })
}

fn evaluate_authority(
    assertions: &[AuthorityAssertion],
) -> Result<AuthorityMetrics, EvaluationError> {
    let mut sorted = assertions.to_vec();
    sorted.sort_by(|left, right| left.assertion_id.cmp(&right.assertion_id));
    let failed_assertions = sorted.iter().filter(|assertion| !assertion.passed).count() as u64;
    Ok(AuthorityMetrics {
        assertions: sorted,
        failed_assertions,
    })
}

fn evaluate_performance(measurement: Option<&PerformanceMeasurement>) -> PerformanceRecord {
    let Some(measurement) = measurement else {
        return PerformanceRecord {
            state: MetricState::NotMeasured,
            measurement_policy: None,
            mode: None,
            workload_size: None,
            elapsed_ms: None,
            machine: None,
        };
    };

    PerformanceRecord {
        state: if measurement.machine.is_some() {
            MetricState::Measured
        } else {
            MetricState::UnqualifiedMeasurement
        },
        measurement_policy: Some(measurement.measurement_policy.clone()),
        mode: Some(measurement.mode.clone()),
        workload_size: Some(measurement.workload_size),
        elapsed_ms: Some(measurement.elapsed_ms),
        machine: measurement.machine.clone(),
    }
}

#[test]
fn core_fixture_emits_contract_complete_machine_record() -> Result<(), Box<dyn Error>> {
    let fixture = load_core_fixture()?;
    let record = evaluate_replayed(&fixture, CORE_CORPUS_BYTES)?;

    assert_eq!(record.schema_version, SCHEMA_V1);
    assert_eq!(record.evaluator.version, EVALUATOR_VERSION);
    assert!(record.evaluator.digest.starts_with("sha256:"));
    assert_eq!(record.metric_contract.version, METRIC_CONTRACT_VERSION);
    assert!(record.metric_contract.digest.starts_with("sha256:"));
    assert_eq!(record.corpus.class, CorpusClass::PublicRegression);
    assert_eq!(record.corpus.revision, "t089-core-corpus-v1");
    assert_eq!(record.corpus.case_ids.len(), 4);
    assert!(record.corpus.digest.starts_with("sha256:"));
    assert!(record.corpus.expected_outputs_digest.starts_with("sha256:"));
    assert_eq!(record.baseline_identity, fixture.baseline_identity);
    assert_eq!(record.candidate_identity, fixture.candidate_identity);
    assert_eq!(record.coverage.expected_dimensions, 5);
    assert_eq!(record.coverage.completed_dimensions, 4);
    assert_eq!(record.coverage.gap_dimensions, 1);
    assert_eq!(record.provenance.required_objects, 2);
    assert_eq!(record.provenance.complete_objects, 2);
    assert_eq!(record.authority.failed_assertions, 0);
    assert_eq!(record.performance.state, MetricState::NotMeasured);
    assert_eq!(record.replay.status, ReplayStatus::Equal);

    let json_line = record.to_json_line()?;
    assert!(json_line.ends_with('\n'));
    let json: serde_json::Value = serde_json::from_str(json_line.trim_end())?;
    for required in [
        "schema_version",
        "evaluator",
        "metric_contract",
        "corpus",
        "baseline_identity",
        "candidate_identity",
        "findings",
        "coverage",
        "provenance",
        "replay",
        "authority",
        "performance",
        "diagnostics",
    ] {
        assert!(
            json.get(required).is_some(),
            "missing run-record field {required}"
        );
    }
    println!("{json_line}");
    Ok(())
}

#[test]
fn identical_immutable_inputs_replay_byte_identically() -> Result<(), Box<dyn Error>> {
    let fixture = load_core_fixture()?;
    let first = evaluate_replayed(&fixture, CORE_CORPUS_BYTES)?.to_json_line()?;
    let second = evaluate_replayed(&fixture, CORE_CORPUS_BYTES)?.to_json_line()?;
    assert_eq!(first, second);
    Ok(())
}

#[test]
fn severity_downgrade_cannot_game_high_severity_precision() -> Result<(), Box<dyn Error>> {
    let fixture = load_core_fixture()?;
    let record = evaluate_replayed(&fixture, CORE_CORPUS_BYTES)?;

    assert_eq!(record.findings.high_severity_expected, 2);
    assert_eq!(record.findings.high_severity_true_positive, 1);
    assert_eq!(record.findings.high_severity_false_negative, 1);
    assert_eq!(record.findings.high_severity_false_positive, 1);
    assert_eq!(record.findings.severity_mismatch_count, 1);
    assert_eq!(
        record.findings.high_severity_precision,
        RatioMetric {
            state: MetricState::Measured,
            numerator: Some(1),
            denominator: Some(2),
        }
    );
    Ok(())
}

#[test]
fn absent_denominators_are_not_applicable_not_perfect() -> Result<(), Box<dyn Error>> {
    let mut fixture = load_core_fixture()?;
    fixture
        .cases
        .retain(|case| case.case_id == "clean-no-findings");
    let bytes = serde_json::to_vec(&fixture)?;
    let record = evaluate_replayed(&fixture, &bytes)?;

    assert_eq!(
        record.findings.known_ground_truth_recall.state,
        MetricState::NotApplicable
    );
    assert_eq!(
        record.findings.known_ground_truth_miss_rate.state,
        MetricState::NotApplicable
    );
    assert_eq!(
        record.findings.high_severity_precision.state,
        MetricState::NotApplicable
    );
    assert_eq!(
        record.provenance.completeness.state,
        MetricState::NotApplicable
    );
    assert_eq!(
        record.findings.clean_case_false_positive_rate,
        RatioMetric {
            state: MetricState::Measured,
            numerator: Some(0),
            denominator: Some(1),
        }
    );
    Ok(())
}

#[test]
fn performance_requires_machine_metadata_to_be_qualified() -> Result<(), Box<dyn Error>> {
    let mut fixture = load_core_fixture()?;
    fixture.performance = Some(PerformanceMeasurement {
        measurement_policy: "synthetic-latency-policy-v1".to_owned(),
        mode: "WARM".to_owned(),
        workload_size: 128,
        elapsed_ms: 7,
        machine: None,
    });
    let unqualified_bytes = serde_json::to_vec(&fixture)?;
    let unqualified = evaluate_replayed(&fixture, &unqualified_bytes)?;
    assert_eq!(
        unqualified.performance.state,
        MetricState::UnqualifiedMeasurement
    );
    assert_eq!(unqualified.performance.machine, None);
    assert_eq!(unqualified.diagnostics.len(), 1);

    fixture.performance.as_mut().expect("measurement").machine = Some(MachineMetadata {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        runner: "rust-test-harness".to_owned(),
    });
    let measured_bytes = serde_json::to_vec(&fixture)?;
    let measured = evaluate_replayed(&fixture, &measured_bytes)?;
    assert_eq!(measured.performance.state, MetricState::Measured);
    assert!(measured.performance.machine.is_some());
    assert!(measured.diagnostics.is_empty());
    Ok(())
}

#[test]
fn duplicate_case_identity_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut fixture = load_core_fixture()?;
    fixture.cases.push(fixture.cases[0].clone());
    let bytes = serde_json::to_vec(&fixture)?;
    let error = evaluate_replayed(&fixture, &bytes).expect_err("duplicate case must fail");
    assert!(matches!(error, EvaluationError::DuplicateCaseId(_)));
    Ok(())
}

#[test]
fn explicit_metric_and_replay_states_remain_machine_serializable() -> Result<(), Box<dyn Error>> {
    let metric_states = [
        MetricState::Measured,
        MetricState::NotApplicable,
        MetricState::NotMeasured,
        MetricState::UnqualifiedMeasurement,
        MetricState::EvaluationError,
    ];
    let replay_states = [
        ReplayStatus::Equal,
        ReplayStatus::Different,
        ReplayStatus::NotMeasured,
    ];

    assert_eq!(
        serde_json::to_string(&metric_states)?,
        r#"["MEASURED","NOT_APPLICABLE","NOT_MEASURED","UNQUALIFIED_MEASUREMENT","EVALUATION_ERROR"]"#
    );
    assert_eq!(
        serde_json::to_string(&replay_states)?,
        r#"["REPLAY_EQUAL","REPLAY_DIFFERENT","REPLAY_NOT_MEASURED"]"#
    );
    Ok(())
}
