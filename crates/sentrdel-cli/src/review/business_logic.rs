//! Public R3 business-logic Evidence/Coverage integration for `sentrdel review`.
//!
//! The frozen R1 JSON envelope has no raw-Evidence or R3 path-context field. R3
//! Evidence is therefore retained beside the canonical `ReviewOutput`, R3
//! Coverage is appended through the existing envelope constructor, and bounded
//! deterministic route/guard/data/invariant context is exposed for developer
//! presentation. This module never creates a Finding, changes review/policy
//! decisions, executes target code, accesses providers, or performs network I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_review::business_logic::model::{
    CrossLayerPath, InvariantEvaluation, InvariantEvaluationState, PathState, RouteObservation,
};
use sentrdel_review::business_logic::producer::BusinessLogicProducerOutput;
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::evidence::Evidence;

use super::{ReviewOutput, ReviewOutputError};

/// Maximum changed-path inputs accepted by one R3 review integration call.
pub const DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS: usize = 4_096;
/// Maximum route observations accepted by one R3 review integration call.
pub const DEFAULT_MAX_R3_REVIEW_ROUTES: usize = 4_096;
/// Maximum cross-layer path contexts accepted by one R3 review integration call.
pub const DEFAULT_MAX_R3_REVIEW_CONTEXTS: usize = 4_096;
/// Maximum invariant evaluations accepted by one R3 review integration call.
pub const DEFAULT_MAX_R3_REVIEW_EVALUATIONS: usize = 4_096;

/// Developer-facing invariant context attached to one bounded cross-layer path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessLogicInvariantContext {
    pub evaluation_id: String,
    pub invariant_id: String,
    pub state: InvariantEvaluationState,
    pub coverage_reasons: Vec<String>,
}

/// Developer-facing route/actor/guard/data/invariant context for one R3 path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessLogicReviewContext {
    pub changed: bool,
    pub source_paths: Vec<String>,
    pub route_id: String,
    pub route_pattern: String,
    pub path_id: String,
    pub actor_ids: Vec<String>,
    pub guard_ids: Vec<String>,
    pub data_operation_id: String,
    pub provider_client_id: Option<String>,
    pub r2_evidence_ids: Vec<String>,
    pub path_state: PathState,
    pub invariants: Vec<BusinessLogicInvariantContext>,
}

/// R3-integrated review result with canonical output, retained Evidence and context.
#[derive(Clone, Debug, PartialEq)]
pub struct RegisteredBusinessLogicReviewOutput {
    output: ReviewOutput,
    business_logic_evidence: Vec<Evidence>,
    context: Vec<BusinessLogicReviewContext>,
}

impl RegisteredBusinessLogicReviewOutput {
    /// Return the canonical review output carrying the appended R3 Coverage.
    #[must_use]
    pub fn output(&self) -> &ReviewOutput {
        &self.output
    }

    /// Return canonical R3 Evidence retained for persistence/reconciliation consumers.
    #[must_use]
    pub fn business_logic_evidence(&self) -> &[Evidence] {
        &self.business_logic_evidence
    }

    /// Return deterministic changed-path-prioritized R3 review context.
    #[must_use]
    pub fn context(&self) -> &[BusinessLogicReviewContext] {
        &self.context
    }

    /// Render the frozen R1 machine-readable envelope without adding ad-hoc fields.
    pub fn render_json(&self) -> Result<String, serde_json::Error> {
        self.output.render_json()
    }

    /// Render canonical review output followed by bounded R3 developer context.
    #[must_use]
    pub fn render_human(&self, verbose: bool) -> String {
        let mut rendered = self.output.render_human(verbose);
        rendered.push_str("\nBusiness-logic context:\n");
        if self.context.is_empty() {
            rendered.push_str("- None.\n");
            return rendered;
        }

        for entry in &self.context {
            rendered.push_str("- path=");
            rendered.push_str(&entry.path_id);
            rendered.push_str(" changed=");
            rendered.push_str(if entry.changed { "true" } else { "false" });
            rendered.push_str(" state=");
            rendered.push_str(path_state_name(entry.path_state));
            rendered.push_str(" route=");
            rendered.push_str(&entry.route_id);
            rendered.push_str(" pattern=");
            rendered.push_str(&entry.route_pattern);
            rendered.push('\n');

            render_list(&mut rendered, "  sources", &entry.source_paths);
            render_list(&mut rendered, "  actors", &entry.actor_ids);
            render_list(&mut rendered, "  guards", &entry.guard_ids);
            rendered.push_str("  data_operation=");
            rendered.push_str(&entry.data_operation_id);
            rendered.push('\n');
            rendered.push_str("  provider_client=");
            rendered.push_str(entry.provider_client_id.as_deref().unwrap_or("none"));
            rendered.push('\n');
            render_list(&mut rendered, "  r2_evidence", &entry.r2_evidence_ids);

            if entry.invariants.is_empty() {
                rendered.push_str("  invariants=none\n");
            } else {
                for invariant in &entry.invariants {
                    rendered.push_str("  invariant=");
                    rendered.push_str(&invariant.invariant_id);
                    rendered.push_str(" evaluation=");
                    rendered.push_str(&invariant.evaluation_id);
                    rendered.push_str(" state=");
                    rendered.push_str(invariant_state_name(invariant.state));
                    if !invariant.coverage_reasons.is_empty() {
                        rendered.push_str(" reasons=");
                        rendered.push_str(&invariant.coverage_reasons.join(","));
                    }
                    rendered.push('\n');
                }
            }
        }
        rendered
    }
}

/// Fail-visible validation errors for the public R3 review integration boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BusinessLogicReviewRegistrationError {
    Review(ReviewOutputError),
    TooManyChangedPaths { observed: usize, max: usize },
    TooManyRoutes { observed: usize, max: usize },
    TooManyContexts { observed: usize, max: usize },
    TooManyEvaluations { observed: usize, max: usize },
    DuplicateRouteId(String),
    DuplicatePathId(String),
    DuplicateEvaluationId(String),
    MissingRouteId(String),
    DanglingEvaluationPathId(String),
}

impl fmt::Display for BusinessLogicReviewRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Review(error) => write!(formatter, "R3 review integration failed: {error}"),
            Self::TooManyChangedPaths { observed, max } => write!(
                formatter,
                "R3 review changed-path count {observed} exceeds cap {max}"
            ),
            Self::TooManyRoutes { observed, max } => {
                write!(formatter, "R3 review route count {observed} exceeds cap {max}")
            }
            Self::TooManyContexts { observed, max } => write!(
                formatter,
                "R3 review context count {observed} exceeds cap {max}"
            ),
            Self::TooManyEvaluations { observed, max } => write!(
                formatter,
                "R3 review invariant-evaluation count {observed} exceeds cap {max}"
            ),
            Self::DuplicateRouteId(value) => {
                write!(formatter, "R3 review context contains duplicate route id {value:?}")
            }
            Self::DuplicatePathId(value) => {
                write!(formatter, "R3 review context contains duplicate path id {value:?}")
            }
            Self::DuplicateEvaluationId(value) => write!(
                formatter,
                "R3 review context contains duplicate invariant evaluation id {value:?}"
            ),
            Self::MissingRouteId(value) => write!(
                formatter,
                "R3 review path references route id {value:?} that is absent from the supplied route set"
            ),
            Self::DanglingEvaluationPathId(value) => write!(
                formatter,
                "R3 review invariant evaluation references path id {value:?} that is absent from the supplied path set"
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

/// Integrate already-authoritative R3 producer output into an existing review result.
///
/// The function preserves the baseline decision and Findings verbatim, appends
/// canonical producer Coverage, retains canonical producer Evidence separately,
/// and constructs deterministic changed-path-first developer context.
#[allow(clippy::too_many_arguments)]
pub fn register_r3_business_logic_review(
    baseline: &ReviewOutput,
    producer: &BusinessLogicProducerOutput,
    changed_paths: &[NormalizedRepoPath],
    routes: &[RouteObservation],
    paths: &[CrossLayerPath],
    evaluations: &[InvariantEvaluation],
) -> Result<RegisteredBusinessLogicReviewOutput, BusinessLogicReviewRegistrationError> {
    validate_input_caps(changed_paths, routes, paths, evaluations)?;

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

/// Reject unbounded integration inputs before any context-sized allocation occurs.
fn validate_input_caps(
    changed_paths: &[NormalizedRepoPath],
    routes: &[RouteObservation],
    paths: &[CrossLayerPath],
    evaluations: &[InvariantEvaluation],
) -> Result<(), BusinessLogicReviewRegistrationError> {
    if changed_paths.len() > DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS {
        return Err(BusinessLogicReviewRegistrationError::TooManyChangedPaths {
            observed: changed_paths.len(),
            max: DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS,
        });
    }
    if routes.len() > DEFAULT_MAX_R3_REVIEW_ROUTES {
        return Err(BusinessLogicReviewRegistrationError::TooManyRoutes {
            observed: routes.len(),
            max: DEFAULT_MAX_R3_REVIEW_ROUTES,
        });
    }
    if paths.len() > DEFAULT_MAX_R3_REVIEW_CONTEXTS {
        return Err(BusinessLogicReviewRegistrationError::TooManyContexts {
            observed: paths.len(),
            max: DEFAULT_MAX_R3_REVIEW_CONTEXTS,
        });
    }
    if evaluations.len() > DEFAULT_MAX_R3_REVIEW_EVALUATIONS {
        return Err(BusinessLogicReviewRegistrationError::TooManyEvaluations {
            observed: evaluations.len(),
            max: DEFAULT_MAX_R3_REVIEW_EVALUATIONS,
        });
    }
    Ok(())
}

/// Build deterministic changed-path-first context without guessing missing identity links.
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

    let mut seen_paths = BTreeSet::new();
    for path in paths {
        let path_id = path.path_id().as_str();
        if !seen_paths.insert(path_id.to_owned()) {
            return Err(BusinessLogicReviewRegistrationError::DuplicatePathId(
                path_id.to_owned(),
            ));
        }
        if !route_by_id.contains_key(path.route_id().as_str()) {
            return Err(BusinessLogicReviewRegistrationError::MissingRouteId(
                path.route_id().as_str().to_owned(),
            ));
        }
    }

    let mut evaluations_by_path = BTreeMap::<String, Vec<&InvariantEvaluation>>::new();
    let mut seen_evaluations = BTreeSet::new();
    for evaluation in evaluations {
        let evaluation_id = evaluation.evaluation_id().as_str();
        if !seen_evaluations.insert(evaluation_id.to_owned()) {
            return Err(BusinessLogicReviewRegistrationError::DuplicateEvaluationId(
                evaluation_id.to_owned(),
            ));
        }
        if let Some(path_id) = evaluation.path_id() {
            let path_id = path_id.as_str();
            if !seen_paths.contains(path_id) {
                return Err(
                    BusinessLogicReviewRegistrationError::DanglingEvaluationPathId(
                        path_id.to_owned(),
                    ),
                );
            }
            evaluations_by_path
                .entry(path_id.to_owned())
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

    let mut context = Vec::with_capacity(paths.len());
    for path in paths {
        let path_id = path.path_id().as_str();
        let route = route_by_id
            .get(path.route_id().as_str())
            .copied()
            .expect("validated route identity must remain present");

        let mut source_paths = path
            .provenance()
            .iter()
            .map(|location| location.path().as_str().to_owned())
            .collect::<Vec<_>>();
        normalize_strings(&mut source_paths);
        let is_changed = source_paths
            .iter()
            .any(|source_path| changed.contains(source_path.as_str()));

        let mut actor_ids = path
            .actor_ids()
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        normalize_strings(&mut actor_ids);
        let mut guard_ids = path
            .guard_ids()
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        normalize_strings(&mut guard_ids);
        let mut r2_evidence_ids = path.r2_evidence_ids().to_vec();
        normalize_strings(&mut r2_evidence_ids);

        let invariants = evaluations_by_path
            .get(path_id)
            .into_iter()
            .flatten()
            .map(|evaluation| {
                let mut coverage_reasons = evaluation.coverage_reasons().to_vec();
                normalize_strings(&mut coverage_reasons);
                BusinessLogicInvariantContext {
                    evaluation_id: evaluation.evaluation_id().as_str().to_owned(),
                    invariant_id: evaluation.invariant_id().as_str().to_owned(),
                    state: evaluation.state(),
                    coverage_reasons,
                }
            })
            .collect();

        context.push(BusinessLogicReviewContext {
            changed: is_changed,
            source_paths,
            route_id: path.route_id().as_str().to_owned(),
            route_pattern: route.route_pattern().to_owned(),
            path_id: path_id.to_owned(),
            actor_ids,
            guard_ids,
            data_operation_id: path.data_operation_id().as_str().to_owned(),
            provider_client_id: path
                .provider_client_id()
                .map(|value| value.as_str().to_owned()),
            r2_evidence_ids,
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

/// Sort and deduplicate already-validated bounded identifier/text collections.
fn normalize_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

/// Render one deterministic list-valued context field.
fn render_list(out: &mut String, label: &str, values: &[String]) {
    out.push_str(label);
    out.push('=');
    if values.is_empty() {
        out.push_str("none");
    } else {
        out.push_str(&values.join(","));
    }
    out.push('\n');
}

/// Stable human rendering for bounded R3 path states.
const fn path_state_name(state: PathState) -> &'static str {
    match state {
        PathState::Supported => "SUPPORTED",
        PathState::Partial => "PARTIAL",
        PathState::Ambiguous => "AMBIGUOUS",
        PathState::BoundedRejection => "BOUNDED_REJECTION",
    }
}

/// Stable human rendering for bounded invariant-evaluation states.
const fn invariant_state_name(state: InvariantEvaluationState) -> &'static str {
    match state {
        InvariantEvaluationState::Satisfied => "SATISFIED",
        InvariantEvaluationState::Violated => "VIOLATED",
        InvariantEvaluationState::Unknown => "UNKNOWN",
        InvariantEvaluationState::NotApplicable => "NOT_APPLICABLE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CliDecision, CliRepository, CliTiming};
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

    /// Build one bounded stable semantic id fixture.
    fn id(namespace: &str, value: &str) -> StableSemanticId {
        StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default()).unwrap()
    }

    /// Build one source-location fixture with deterministic content provenance.
    fn location(path: &str, digest_seed: char) -> SourceLocation {
        SourceLocation::new(
            NormalizedRepoPath::parse(path, DEFAULT_MAX_REPO_PATH_BYTES).unwrap(),
            0,
            32,
            format!("sha256:{}", digest_seed.to_string().repeat(64)),
        )
        .unwrap()
    }

    /// Build one supported Express route fixture.
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

    /// Build one supported cross-layer path fixture.
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

    /// Build one invariant-evaluation fixture linked to the corresponding path.
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

    /// Produce canonical R3 Evidence/Coverage for fixture evaluations.
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
        produce_business_logic_outputs(evaluations, &coverage, "2026-09-07T00:00:00Z").unwrap()
    }

    /// Build an empty authoritative baseline review output.
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

    /// Public ReviewOutput integration retains Evidence and appends Coverage only.
    #[test]
    fn public_review_surface_integrates_r3_without_minting_findings_or_decision() {
        let evaluations = vec![evaluation("changed", InvariantEvaluationState::Violated)];
        let producer = producer(&evaluations);
        let registered = baseline()
            .integrate_r3_business_logic(
                &producer,
                &[NormalizedRepoPath::parse(
                    "src/changed.ts",
                    DEFAULT_MAX_REPO_PATH_BYTES,
                )
                .unwrap()],
                &[route("changed", "src/changed.ts")],
                &[cross_layer_path("changed", "src/changed.ts")],
                &evaluations,
            )
            .unwrap();

        assert_eq!(registered.output().envelope().decision, CliDecision::Allow);
        assert!(registered.output().findings().is_empty());
        assert_eq!(registered.output().envelope().coverage.len(), 12);
        assert_eq!(registered.business_logic_evidence().len(), 2);
        assert_eq!(registered.context().len(), 1);
        assert!(registered.context()[0].changed);
    }

    /// Human rendering includes bounded route/guard/data/invariant context.
    #[test]
    fn human_rendering_exposes_developer_context_and_unknown_limitations() {
        let evaluations = vec![evaluation("admin", InvariantEvaluationState::Unknown)];
        let producer = producer(&evaluations);
        let registered = baseline()
            .integrate_r3_business_logic(
                &producer,
                &[NormalizedRepoPath::parse(
                    "src/admin.ts",
                    DEFAULT_MAX_REPO_PATH_BYTES,
                )
                .unwrap()],
                &[route("admin", "src/admin.ts")],
                &[cross_layer_path("admin", "src/admin.ts")],
                &evaluations,
            )
            .unwrap();
        let human = registered.render_human(false);

        for expected in [
            "Business-logic context:",
            "changed=true",
            "route=route:",
            "pattern=/admin",
            "guards=guard:",
            "data_operation=operation:",
            "state=UNKNOWN",
            "reasons=STATIC_SCOPE_ONLY",
        ] {
            assert!(human.contains(expected), "missing {expected:?}");
        }
    }

    /// Machine rendering keeps the frozen R1 envelope and never adds context keys.
    #[test]
    fn json_rendering_preserves_frozen_review_envelope() {
        let evaluations = vec![evaluation("json", InvariantEvaluationState::Satisfied)];
        let producer = producer(&evaluations);
        let registered = baseline()
            .integrate_r3_business_logic(
                &producer,
                &[],
                &[route("json", "src/json.ts")],
                &[cross_layer_path("json", "src/json.ts")],
                &evaluations,
            )
            .unwrap();
        let value: serde_json::Value =
            serde_json::from_str(registered.render_json().unwrap().trim()).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.keys().cloned().collect::<Vec<_>>(),
            vec![
                "command",
                "coverage",
                "decision",
                "diagnostics",
                "findings",
                "repository",
                "schema_version",
                "timing",
            ]
        );
        assert!(object.get("business_logic_context").is_none());
    }

    /// Exact path matching prioritizes changed code without accepting prefix attacks.
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
    }

    /// A path referencing an omitted route fails visible instead of losing context.
    #[test]
    fn missing_route_identity_fails_visible() {
        let result = build_context(
            &[],
            &[],
            &[cross_layer_path("missing", "src/missing.ts")],
            &[],
        );
        assert_eq!(
            result,
            Err(BusinessLogicReviewRegistrationError::MissingRouteId(
                id("route", "missing").as_str().to_owned()
            ))
        );
    }

    /// A path-scoped evaluation referencing an omitted path fails visible.
    #[test]
    fn dangling_evaluation_path_identity_fails_visible() {
        let result = build_context(
            &[],
            &[route("dangling", "src/dangling.ts")],
            &[],
            &[evaluation("dangling", InvariantEvaluationState::Unknown)],
        );
        assert_eq!(
            result,
            Err(
                BusinessLogicReviewRegistrationError::DanglingEvaluationPathId(
                    id("path", "dangling").as_str().to_owned()
                )
            )
        );
    }

    /// Context count caps fail visible instead of silently truncating developer evidence.
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

    /// Route count caps fail before building route identity maps.
    #[test]
    fn route_cap_fails_visible_before_context_allocation() {
        let fixture = route("route-cap", "src/route-cap.ts");
        let too_many = vec![fixture; DEFAULT_MAX_R3_REVIEW_ROUTES + 1];
        let result = register_r3_business_logic_review(
            &baseline(),
            &producer(&[]),
            &[],
            &too_many,
            &[],
            &[],
        );
        assert_eq!(
            result,
            Err(BusinessLogicReviewRegistrationError::TooManyRoutes {
                observed: DEFAULT_MAX_R3_REVIEW_ROUTES + 1,
                max: DEFAULT_MAX_R3_REVIEW_ROUTES,
            })
        );
    }

    /// Evaluation count caps fail before grouping invariant context.
    #[test]
    fn evaluation_cap_fails_visible_before_context_allocation() {
        let fixture = evaluation("evaluation-cap", InvariantEvaluationState::Unknown);
        let too_many = vec![fixture; DEFAULT_MAX_R3_REVIEW_EVALUATIONS + 1];
        let result = register_r3_business_logic_review(
            &baseline(),
            &producer(&[]),
            &[],
            &[],
            &[],
            &too_many,
        );
        assert_eq!(
            result,
            Err(BusinessLogicReviewRegistrationError::TooManyEvaluations {
                observed: DEFAULT_MAX_R3_REVIEW_EVALUATIONS + 1,
                max: DEFAULT_MAX_R3_REVIEW_EVALUATIONS,
            })
        );
    }

    /// Changed-path count caps fail before allocating integration context.
    #[test]
    fn changed_path_cap_fails_visible_before_context_allocation() {
        let path = NormalizedRepoPath::parse("src/cap.ts", DEFAULT_MAX_REPO_PATH_BYTES).unwrap();
        let too_many = vec![path; DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS + 1];
        let result = register_r3_business_logic_review(
            &baseline(),
            &producer(&[]),
            &too_many,
            &[],
            &[],
            &[],
        );
        assert_eq!(
            result,
            Err(BusinessLogicReviewRegistrationError::TooManyChangedPaths {
                observed: DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS + 1,
                max: DEFAULT_MAX_R3_REVIEW_CHANGED_PATHS,
            })
        );
    }
}
