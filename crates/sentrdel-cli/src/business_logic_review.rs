//! R3 business-logic Evidence/Coverage registration for `sentrdel review`.
//!
//! The frozen CLI envelope has no raw-Evidence or R3 path-context field. R3
//! Evidence is therefore retained as canonical `Evidence` for persistence and
//! reconciliation, R3 Coverage is added to the existing review envelope, and a
//! bounded deterministic context view is retained beside the envelope for review
//! presentation. This module never creates a Finding, changes review/policy
//! decisions, executes target code, accesses providers, or performs network I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_cli::review::{ReviewOutput, ReviewOutputError};
use sentrdel_review::business_logic::model::{
    CrossLayerPath, InvariantEvaluation, InvariantEvaluationState, PathState, RouteObservation,
};
use sentrdel_review::business_logic::producer::BusinessLogicProducerOutput;
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::evidence::Evidence;

pub const DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS: usize = 4_096;
pub const DEFAULT_MAX_R3_REVIEW_CONTEXTS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessLogicInvariantContext {
    pub evaluation_id: String,
    pub invariant_id: String,
    pub state: InvariantEvaluationState,
    pub coverage_reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessLogicReviewContext {
    pub changed: bool,
    pub source_paths: Vec<String>,
    pub route_id: String,
    pub route_pattern: Option<String>,
    pub path_id: String,
    pub actor_ids: Vec<String>,
    pub guard_ids: Vec<String>,
    pub data_operation_id: String,
    pub provider_client_id: Option<String>,
    pub r2_evidence_ids: Vec<String>,
    pub path_state: PathState,
    pub invariants: Vec<BusinessLogicInvariantContext>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredBusinessLogicReviewOutput {
    pub output: ReviewOutput,
    business_logic_evidence: Vec<Evidence>,
    context: Vec<BusinessLogicReviewContext>,
}

impl RegisteredBusinessLogicReviewOutput {
    #[must_use]
    pub fn business_logic_evidence(&self) -> &[Evidence] {
        &self.business_logic_evidence
    }

    #[must_use]
    pub fn context(&self) -> &[BusinessLogicReviewContext] {
        &self.context
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BusinessLogicReviewRegistrationError {
    Review(ReviewOutputError),
    TooManyChangedPaths { observed: usize, max: usize },
    TooManyContexts { observed: usize, max: usize },
    DuplicateRouteId(String),
    DuplicatePathId(String),
    DuplicateEvaluationId(String),
}

impl fmt::Display for BusinessLogicReviewRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Review(error) => write!(formatter, "R3 review registration failed: {error}"),
            Self::TooManyChangedPaths { observed, max } => write!(
                formatter,
                "R3 review changed-path count {observed} exceeds cap {max}"
            ),
            Self::TooManyContexts { observed, max } => write!(
                formatter,
                "R3 review context count {observed} exceeds cap {max}"
            ),
            Self::DuplicateRouteId(value) => {
                write!(
                    formatter,
                    "R3 review context contains duplicate route id {value:?}"
                )
            }
            Self::DuplicatePathId(value) => {
                write!(
                    formatter,
                    "R3 review context contains duplicate path id {value:?}"
                )
            }
            Self::DuplicateEvaluationId(value) => write!(
                formatter,
                "R3 review context contains duplicate invariant evaluation id {value:?}"
            ),
        }
    }
}

impl Error for BusinessLogicReviewRegistrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Review(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ReviewOutputError> for BusinessLogicReviewRegistrationError {
    fn from(value: ReviewOutputError) -> Self {
        Self::Review(value)
    }
}

pub fn register_r3_business_logic_review(
    baseline: &ReviewOutput,
    producer: &BusinessLogicProducerOutput,
    changed_paths: &[NormalizedRepoPath],
    routes: &[RouteObservation],
    paths: &[CrossLayerPath],
    evaluations: &[InvariantEvaluation],
) -> Result<RegisteredBusinessLogicReviewOutput, BusinessLogicReviewRegistrationError> {
    if changed_paths.len() > DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS {
        return Err(BusinessLogicReviewRegistrationError::TooManyChangedPaths {
            observed: changed_paths.len(),
            max: DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS,
        });
    }
    if paths.len() > DEFAULT_MAX_R3_REVIEW_CONTEXTS {
        return Err(BusinessLogicReviewRegistrationError::TooManyContexts {
            observed: paths.len(),
            max: DEFAULT_MAX_R3_REVIEW_CONTEXTS,
        });
    }

    let mut coverage = baseline.envelope().coverage.clone();
    coverage.extend(producer.coverage().iter().cloned());
    let output = ReviewOutput::new(
        baseline.envelope().repository.clone(),
        baseline.envelope().decision,
        baseline.findings().to_vec(),
        coverage,
        baseline.missing_coverage().to_vec(),
        baseline.envelope().timing.clone(),
        baseline.envelope().store_refs.clone(),
    )?;

    let context = build_context(changed_paths, routes, paths, evaluations)?;
    Ok(RegisteredBusinessLogicReviewOutput {
        output,
        business_logic_evidence: producer.evidence().to_vec(),
        context,
    })
}

fn build_context(
    changed_paths: &[NormalizedRepoPath],
    routes: &[RouteObservation],
    paths: &[CrossLayerPath],
    evaluations: &[InvariantEvaluation],
) -> Result<Vec<BusinessLogicReviewContext>, BusinessLogicReviewRegistrationError> {
    let changed = changed_paths
        .iter()
        .map(NormalizedRepoPath::as_str)
        .collect::<BTreeSet<_>>();

    let mut route_by_id = BTreeMap::new();
    for route in routes {
        let route_id = route.route_id().as_str();
        if route_by_id.insert(route_id, route).is_some() {
            return Err(BusinessLogicReviewRegistrationError::DuplicateRouteId(
                route_id.to_owned(),
            ));
        }
    }

    let mut evaluations_by_path = BTreeMap::<&str, Vec<&InvariantEvaluation>>::new();
    let mut seen_evaluations = BTreeSet::new();
    for evaluation in evaluations {
        let evaluation_id = evaluation.evaluation_id().as_str();
        if !seen_evaluations.insert(evaluation_id) {
            return Err(BusinessLogicReviewRegistrationError::DuplicateEvaluationId(
                evaluation_id.to_owned(),
            ));
        }
        if let Some(path_id) = evaluation.path_id() {
            evaluations_by_path
                .entry(path_id.as_str())
                .or_default()
                .push(evaluation);
        }
    }
    for path_evaluations in evaluations_by_path.values_mut() {
        path_evaluations.sort_by(|left, right| {
            left.evaluation_id()
                .as_str()
                .cmp(right.evaluation_id().as_str())
        });
    }

    let mut seen_paths = BTreeSet::new();
    let mut context = Vec::with_capacity(paths.len());
    for path in paths {
        let path_id = path.path_id().as_str();
        if !seen_paths.insert(path_id) {
            return Err(BusinessLogicReviewRegistrationError::DuplicatePathId(
                path_id.to_owned(),
            ));
        }

        let source_paths = path
            .provenance()
            .iter()
            .map(|location| location.path().as_str().to_owned())
            .collect::<Vec<_>>();
        let is_changed = source_paths
            .iter()
            .any(|source_path| changed.contains(source_path.as_str()));
        let route = route_by_id.get(path.route_id().as_str()).copied();
        let invariants = evaluations_by_path
            .get(path_id)
            .into_iter()
            .flatten()
            .map(|evaluation| BusinessLogicInvariantContext {
                evaluation_id: evaluation.evaluation_id().as_str().to_owned(),
                invariant_id: evaluation.invariant_id().as_str().to_owned(),
                state: evaluation.state(),
                coverage_reasons: evaluation.coverage_reasons().to_vec(),
            })
            .collect();

        context.push(BusinessLogicReviewContext {
            changed: is_changed,
            source_paths,
            route_id: path.route_id().as_str().to_owned(),
            route_pattern: route.map(|value| value.route_pattern().to_owned()),
            path_id: path_id.to_owned(),
            actor_ids: path
                .actor_ids()
                .iter()
                .map(|value| value.as_str().to_owned())
                .collect(),
            guard_ids: path
                .guard_ids()
                .iter()
                .map(|value| value.as_str().to_owned())
                .collect(),
            data_operation_id: path.data_operation_id().as_str().to_owned(),
            provider_client_id: path
                .provider_client_id()
                .map(|value| value.as_str().to_owned()),
            r2_evidence_ids: path.r2_evidence_ids().to_vec(),
            path_state: path.path_state(),
            invariants,
        });
    }

    context.sort_by(|left, right| {
        (!left.changed)
            .cmp(&(!right.changed))
            .then_with(|| left.source_paths.cmp(&right.source_paths))
            .then_with(|| left.route_id.cmp(&right.route_id))
            .then_with(|| left.path_id.cmp(&right.path_id))
            .then_with(|| left.data_operation_id.cmp(&right.data_operation_id))
    });
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_cli::review::ReviewOutput;
    use sentrdel_cli::{CliDecision, CliRepository, CliTiming};
    use sentrdel_review::business_logic::coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS;
    use sentrdel_review::business_logic::model::{
        BusinessLogicCoverage, BusinessLogicLimits, FrameworkFamily, HttpMethod, SourceLocation,
        StableSemanticId,
    };
    use sentrdel_review::business_logic::producer::{
        R3_BUSINESS_LOGIC_PRODUCER_ID, produce_business_logic_outputs,
    };
    use sentrdel_review::view::DEFAULT_MAX_REPO_PATH_BYTES;
    use sentrdel_schema::coverage::CoverageState;

    fn id(namespace: &str, value: &str) -> StableSemanticId {
        StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default()).unwrap()
    }

    fn location(path: &str, digest_seed: char) -> SourceLocation {
        SourceLocation::new(
            NormalizedRepoPath::parse(path, DEFAULT_MAX_REPO_PATH_BYTES).unwrap(),
            0,
            32,
            format!("sha256:{}", digest_seed.to_string().repeat(64)),
        )
        .unwrap()
    }

    fn route(value: &str, path: &str) -> RouteObservation {
        RouteObservation::new(
            id("route", value),
            FrameworkFamily::Express,
            HttpMethod::Post,
            format!("/{value}"),
            None,
            Vec::new(),
            vec![location(path, 'a')],
            CoverageState::Covered,
            BusinessLogicLimits::default(),
        )
        .unwrap()
    }

    fn cross_layer_path(value: &str, source_path: &str) -> CrossLayerPath {
        CrossLayerPath::new(
            id("path", value),
            id("route", value),
            vec![id("actor", value)],
            vec![id("guard", value)],
            id("operation", value),
            None,
            Vec::new(),
            vec![format!("evidence:r2:{value}")],
            PathState::Supported,
            vec![location(source_path, 'b')],
            BusinessLogicLimits::default(),
        )
        .unwrap()
    }

    fn evaluation(value: &str, state: InvariantEvaluationState) -> InvariantEvaluation {
        InvariantEvaluation::new(
            id("evaluation", value),
            id("invariant", value),
            Some(id("path", value)),
            state,
            vec![id("guard", value)],
            Vec::new(),
            vec!["STATIC_SCOPE_ONLY".to_owned()],
            vec![location(&format!("src/{value}.ts"), 'c')],
            BusinessLogicLimits::default(),
        )
        .unwrap()
    }

    fn producer(evaluations: &[InvariantEvaluation]) -> BusinessLogicProducerOutput {
        let coverage = REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
            .into_iter()
            .map(|area| {
                BusinessLogicCoverage::new(
                    area,
                    CoverageState::Covered,
                    "R3_REVIEW_FIXTURE",
                    ".",
                    Vec::new(),
                    R3_BUSINESS_LOGIC_PRODUCER_ID,
                    BusinessLogicLimits::default(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        produce_business_logic_outputs(evaluations, &coverage, "2026-09-06T20:00:00Z").unwrap()
    }

    fn baseline() -> ReviewOutput {
        ReviewOutput::new(
            CliRepository::new("repo:r3-t027", ".").unwrap(),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn registration_adds_r3_coverage_and_retains_evidence_without_minting_findings_or_decision() {
        let evaluations = vec![evaluation("changed", InvariantEvaluationState::Violated)];
        let producer = producer(&evaluations);
        let registered = register_r3_business_logic_review(
            &baseline(),
            &producer,
            &[NormalizedRepoPath::parse("src/changed.ts", DEFAULT_MAX_REPO_PATH_BYTES).unwrap()],
            &[route("changed", "src/changed.ts")],
            &[cross_layer_path("changed", "src/changed.ts")],
            &evaluations,
        )
        .unwrap();

        assert_eq!(registered.output.envelope().decision, CliDecision::Allow);
        assert!(registered.output.findings().is_empty());
        assert_eq!(registered.output.envelope().coverage.len(), 12);
        assert_eq!(registered.business_logic_evidence().len(), 2);
        assert_eq!(registered.context().len(), 1);
        assert!(registered.context()[0].changed);
        assert_eq!(registered.context()[0].guard_ids.len(), 1);
        assert_eq!(registered.context()[0].invariants.len(), 1);
        assert_eq!(
            registered.context()[0].invariants[0].state,
            InvariantEvaluationState::Violated
        );
    }

    #[test]
    fn exact_changed_path_is_prioritized_deterministically_and_prefix_attack_is_rejected() {
        let changed = cross_layer_path("changed", "src/admin.ts");
        let unchanged = cross_layer_path("unchanged", "src/admin-helper.ts");
        let routes = vec![
            route("unchanged", "src/admin-helper.ts"),
            route("changed", "src/admin.ts"),
        ];
        let evaluations = vec![
            evaluation("unchanged", InvariantEvaluationState::Satisfied),
            evaluation("changed", InvariantEvaluationState::Unknown),
        ];
        let changed_paths =
            vec![NormalizedRepoPath::parse("src/admin.ts", DEFAULT_MAX_REPO_PATH_BYTES).unwrap()];

        let forward = build_context(
            &changed_paths,
            &routes,
            &[unchanged.clone(), changed.clone()],
            &evaluations,
        )
        .unwrap();
        let mut reversed_routes = routes.clone();
        reversed_routes.reverse();
        let mut reversed_evaluations = evaluations.clone();
        reversed_evaluations.reverse();
        let replay = build_context(
            &changed_paths,
            &reversed_routes,
            &[changed, unchanged],
            &reversed_evaluations,
        )
        .unwrap();

        assert_eq!(forward, replay);
        assert!(forward[0].changed);
        assert_eq!(forward[0].source_paths, vec!["src/admin.ts"]);
        assert!(!forward[1].changed);
        assert_eq!(forward[1].source_paths, vec!["src/admin-helper.ts"]);
        assert_eq!(
            forward[0].invariants[0].state,
            InvariantEvaluationState::Unknown
        );
        assert_eq!(
            forward[0].invariants[0].coverage_reasons,
            vec!["STATIC_SCOPE_ONLY"]
        );
    }

    #[test]
    fn context_cap_fails_visible_instead_of_silently_truncating() {
        let too_many = (0..=DEFAULT_MAX_R3_REVIEW_CONTEXTS)
            .map(|index| cross_layer_path(&format!("p{index}"), &format!("src/p{index}.ts")))
            .collect::<Vec<_>>();
        let result = register_r3_business_logic_review(
            &baseline(),
            &producer(&[]),
            &[],
            &[],
            &too_many,
            &[],
        );
        assert_eq!(
            result,
            Err(BusinessLogicReviewRegistrationError::TooManyContexts {
                observed: DEFAULT_MAX_R3_REVIEW_CONTEXTS + 1,
                max: DEFAULT_MAX_R3_REVIEW_CONTEXTS,
            })
        );
    }
}
