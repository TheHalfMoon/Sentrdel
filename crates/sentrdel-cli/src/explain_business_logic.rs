//! Output-only R3 business-logic context for `sentrdel explain`.
//!
//! This module matches already-canonical Finding subjects to bounded R3 review
//! context. It never creates or mutates Findings, changes policy/reconciler
//! authority, executes target code, accesses provider credentials, performs
//! network I/O, or treats graph metadata as verdict authority.

use std::collections::BTreeSet;
use std::{error::Error, fmt};

use sentrdel_cli::review::business_logic::{
    BusinessLogicInvariantContext, BusinessLogicReviewContext,
};
use sentrdel_review::business_logic::model::{InvariantEvaluationState, PathState};

use crate::explain::ExplainOutput;

pub const DEFAULT_MAX_R3_EXPLAIN_CONTEXTS: usize = 256;

const STATIC_LIMITATION: &str = "R3 explanation is bounded repository-derived static context only; it does not prove runtime exploitability, hosted state, actual cross-tenant access, or absence of vulnerabilities.";
const AUTHORITY_LIMITATION: &str = "Route/path/graph metadata and invariant state are explanation context only; the canonical Finding and reconciler remain the verdict authority.";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessLogicExplainInvariant {
    pub evaluation_id: String,
    pub invariant_id: String,
    pub state: InvariantEvaluationState,
    pub coverage_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessLogicExplainChain {
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
    pub invariants: Vec<BusinessLogicExplainInvariant>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessLogicExplainContext {
    chains: Vec<BusinessLogicExplainChain>,
}

impl BusinessLogicExplainContext {
    pub fn from_output(
        output: &ExplainOutput,
        contexts: &[BusinessLogicReviewContext],
    ) -> Result<Option<Self>, BusinessLogicExplainError> {
        if contexts.len() > DEFAULT_MAX_R3_EXPLAIN_CONTEXTS {
            return Err(BusinessLogicExplainError::TooManyContexts {
                count: contexts.len(),
                max: DEFAULT_MAX_R3_EXPLAIN_CONTEXTS,
            });
        }

        let affected: BTreeSet<&str> = output
            .finding()
            .draft()
            .affected_subjects
            .iter()
            .map(String::as_str)
            .collect();

        let mut seen_paths = BTreeSet::new();
        let mut chains = Vec::new();
        for context in contexts {
            if !seen_paths.insert(context.path_id.as_str()) {
                return Err(BusinessLogicExplainError::DuplicatePathId(
                    context.path_id.clone(),
                ));
            }

            let path_subject = format!("cross_layer_path:{}", context.path_id);
            let path_matches = affected.contains(path_subject.as_str());
            let has_matching_invariant_subject = context.invariants.iter().any(|invariant| {
                let invariant_subject = format!("invariant:{}", invariant.invariant_id);
                let evaluation_subject =
                    format!("invariant_evaluation:{}", invariant.evaluation_id);
                affected.contains(invariant_subject.as_str())
                    || affected.contains(evaluation_subject.as_str())
            });

            let mut invariants = Vec::new();
            for invariant in &context.invariants {
                let invariant_subject = format!("invariant:{}", invariant.invariant_id);
                let evaluation_subject =
                    format!("invariant_evaluation:{}", invariant.evaluation_id);
                let invariant_matches = affected.contains(invariant_subject.as_str())
                    || affected.contains(evaluation_subject.as_str());
                if invariant_matches || (path_matches && !has_matching_invariant_subject) {
                    invariants.push(explain_invariant(invariant));
                }
            }

            if !path_matches && invariants.is_empty() {
                continue;
            }
            if path_matches && has_matching_invariant_subject && invariants.is_empty() {
                continue;
            }

            invariants.sort_by(|left, right| {
                left.evaluation_id
                    .cmp(&right.evaluation_id)
                    .then_with(|| left.invariant_id.cmp(&right.invariant_id))
            });

            let mut source_paths = context.source_paths.clone();
            source_paths.sort();
            source_paths.dedup();
            let mut actor_ids = context.actor_ids.clone();
            actor_ids.sort();
            actor_ids.dedup();
            let mut guard_ids = context.guard_ids.clone();
            guard_ids.sort();
            guard_ids.dedup();
            let mut r2_evidence_ids = context.r2_evidence_ids.clone();
            r2_evidence_ids.sort();
            r2_evidence_ids.dedup();

            chains.push(BusinessLogicExplainChain {
                source_paths,
                route_id: context.route_id.clone(),
                route_pattern: context.route_pattern.clone(),
                path_id: context.path_id.clone(),
                actor_ids,
                guard_ids,
                data_operation_id: context.data_operation_id.clone(),
                provider_client_id: context.provider_client_id.clone(),
                r2_evidence_ids,
                path_state: context.path_state,
                invariants,
            });
        }

        if chains.is_empty() {
            return Ok(None);
        }
        if chains.len() > DEFAULT_MAX_R3_EXPLAIN_CONTEXTS {
            return Err(BusinessLogicExplainError::TooManyMatchedChains {
                count: chains.len(),
                max: DEFAULT_MAX_R3_EXPLAIN_CONTEXTS,
            });
        }

        chains.sort_by(|left, right| {
            left.path_id
                .cmp(&right.path_id)
                .then_with(|| left.route_id.cmp(&right.route_id))
        });
        Ok(Some(Self { chains }))
    }

    #[must_use]
    pub fn chains(&self) -> &[BusinessLogicExplainChain] {
        &self.chains
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        let mut rendered = String::from("R3 business-logic context:\n");
        for chain in &self.chains {
            rendered.push_str("- route: ");
            rendered.push_str(&chain.route_id);
            if !chain.route_pattern.is_empty() {
                rendered.push_str(" (");
                rendered.push_str(&chain.route_pattern);
                rendered.push(')');
            }
            rendered.push('\n');
            rendered.push_str("  path: ");
            rendered.push_str(&chain.path_id);
            rendered.push_str(" [");
            rendered.push_str(path_state_name(chain.path_state));
            rendered.push_str("]\n");
            rendered.push_str("  source paths: ");
            rendered.push_str(&render_list(&chain.source_paths));
            rendered.push('\n');
            rendered.push_str("  actors: ");
            rendered.push_str(&render_list(&chain.actor_ids));
            rendered.push('\n');
            rendered.push_str("  guards: ");
            rendered.push_str(&render_list(&chain.guard_ids));
            rendered.push('\n');
            rendered.push_str("  data operation: ");
            rendered.push_str(&chain.data_operation_id);
            rendered.push('\n');
            rendered.push_str("  provider client: ");
            rendered.push_str(chain.provider_client_id.as_deref().unwrap_or("none"));
            rendered.push('\n');
            rendered.push_str("  R2 supporting Evidence: ");
            rendered.push_str(&render_list(&chain.r2_evidence_ids));
            rendered.push('\n');
            for invariant in &chain.invariants {
                rendered.push_str("  invariant: ");
                rendered.push_str(&invariant.invariant_id);
                rendered.push_str(" / evaluation: ");
                rendered.push_str(&invariant.evaluation_id);
                rendered.push_str(" [");
                rendered.push_str(invariant_state_name(invariant.state));
                rendered.push_str("]\n");
                rendered.push_str("    coverage limitations: ");
                if invariant.coverage_reasons.is_empty() {
                    rendered.push_str("none recorded beyond the bounded static scope");
                } else {
                    rendered.push_str(&render_list(&invariant.coverage_reasons));
                }
                rendered.push('\n');
            }
        }
        rendered.push_str("- limitation: ");
        rendered.push_str(STATIC_LIMITATION);
        rendered.push('\n');
        rendered.push_str("- authority: ");
        rendered.push_str(AUTHORITY_LIMITATION);
        rendered.push('\n');
        rendered
    }
}

#[must_use]
pub fn render_explain_human_with_business_logic_context(
    output: &ExplainOutput,
    context: Option<&BusinessLogicExplainContext>,
) -> String {
    let mut rendered = output.render_human();
    if let Some(context) = context {
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        rendered.push('\n');
        rendered.push_str(&context.render_human());
    }
    rendered
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BusinessLogicExplainError {
    TooManyContexts { count: usize, max: usize },
    TooManyMatchedChains { count: usize, max: usize },
    DuplicatePathId(String),
}

impl fmt::Display for BusinessLogicExplainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyContexts { count, max } => write!(
                formatter,
                "R3 explain received {count} business-logic contexts; maximum is {max}"
            ),
            Self::TooManyMatchedChains { count, max } => write!(
                formatter,
                "R3 explain matched {count} business-logic chains; maximum is {max}"
            ),
            Self::DuplicatePathId(path_id) => write!(
                formatter,
                "R3 explain rejected duplicate business-logic path id {path_id:?}"
            ),
        }
    }
}

impl Error for BusinessLogicExplainError {}

fn explain_invariant(value: &BusinessLogicInvariantContext) -> BusinessLogicExplainInvariant {
    let mut coverage_reasons = value.coverage_reasons.clone();
    coverage_reasons.sort();
    coverage_reasons.dedup();
    BusinessLogicExplainInvariant {
        evaluation_id: value.evaluation_id.clone(),
        invariant_id: value.invariant_id.clone(),
        state: value.state,
        coverage_reasons,
    }
}

fn render_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values.join(", ")
    }
}

const fn invariant_state_name(value: InvariantEvaluationState) -> &'static str {
    match value {
        InvariantEvaluationState::Satisfied => "SATISFIED",
        InvariantEvaluationState::Violated => "VIOLATED",
        InvariantEvaluationState::Unknown => "UNKNOWN",
        InvariantEvaluationState::NotApplicable => "NOT_APPLICABLE",
    }
}

const fn path_state_name(value: PathState) -> &'static str {
    match value {
        PathState::Supported => "SUPPORTED",
        PathState::Partial => "PARTIAL",
        PathState::Ambiguous => "AMBIGUOUS",
        PathState::BoundedRejection => "BOUNDED_REJECTION",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explain::{ExplainOutput, ImpactComponents};
    use sentrdel_cli::{CliRepository, CliTiming};
    use sentrdel_schema::{
        SCHEMA_V1,
        finding::{EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity},
    };

    fn finding(affected_subjects: Vec<String>) -> Finding {
        let reconciler =
            ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:r3-t029-config")
                .unwrap();
        Finding::new_reconciled(
            ReconciledFindingDraft {
                schema_version: SCHEMA_V1.to_owned(),
                fingerprint: "r3-t029:fingerprint".to_owned(),
                title: "Cross-layer authorization invariant".to_owned(),
                impact_statement: "A bounded static path violates an authorization invariant."
                    .to_owned(),
                category: "business_logic_invariant_interpretation".to_owned(),
                severity: Severity::High,
                epistemic_state: EpistemicState::Detected,
                evidence_ids: vec!["evidence:r3".to_owned()],
                contradiction_ids: Vec::new(),
                primary_location: Some("src/routes/update.ts".to_owned()),
                affected_subjects,
                first_seen_commit: None,
                last_seen_commit: None,
                remediation: None,
                updated_at: "2026-09-07T00:00:00Z".to_owned(),
            },
            &reconciler,
        )
        .unwrap()
    }

    fn output(affected_subjects: Vec<String>) -> ExplainOutput {
        ExplainOutput::new(
            1,
            finding(affected_subjects),
            CliRepository::new("repo:r3-t029", ".").unwrap(),
            ImpactComponents::new("authenticated user", "update", "tenant-owned object").unwrap(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap()
    }

    fn context(path_id: &str, state: InvariantEvaluationState) -> BusinessLogicReviewContext {
        BusinessLogicReviewContext {
            changed: true,
            source_paths: vec![
                "src/routes/update.ts".to_owned(),
                "src/data/update.ts".to_owned(),
            ],
            route_id: "route:update".to_owned(),
            route_pattern: "PATCH /items/:id".to_owned(),
            path_id: path_id.to_owned(),
            actor_ids: vec!["actor:session-user".to_owned()],
            guard_ids: vec!["guard:tenant".to_owned(), "guard:auth".to_owned()],
            data_operation_id: "data:update-item".to_owned(),
            provider_client_id: Some("client:supabase".to_owned()),
            r2_evidence_ids: vec!["evidence:r2:policy".to_owned()],
            path_state: PathState::Partial,
            invariants: vec![BusinessLogicInvariantContext {
                evaluation_id: "eval:tenant-binding".to_owned(),
                invariant_id: "invariant:tenant-binding".to_owned(),
                state,
                coverage_reasons: vec!["STATIC_SCOPE_ONLY".to_owned()],
            }],
        }
    }

    #[test]
    fn exact_r3_subjects_render_bounded_chain_r2_evidence_and_limitations() {
        let output = output(vec![
            "cross_layer_path:path:update".to_owned(),
            "invariant:invariant:tenant-binding".to_owned(),
            "invariant_evaluation:eval:tenant-binding".to_owned(),
        ]);
        let contexts = vec![context("path:update", InvariantEvaluationState::Violated)];
        let explanation = BusinessLogicExplainContext::from_output(&output, &contexts)
            .unwrap()
            .expect("matching R3 context");
        let rendered =
            render_explain_human_with_business_logic_context(&output, Some(&explanation));

        for expected in [
            "route:update (PATCH /items/:id)",
            "actors: actor:session-user",
            "guards: guard:auth, guard:tenant",
            "data operation: data:update-item",
            "provider client: client:supabase",
            "R2 supporting Evidence: evidence:r2:policy",
            "invariant: invariant:tenant-binding / evaluation: eval:tenant-binding [VIOLATED]",
            "coverage limitations: STATIC_SCOPE_ONLY",
            "does not prove runtime exploitability",
            "graph metadata and invariant state are explanation context only",
        ] {
            assert!(rendered.contains(expected), "missing {expected:?}");
        }
    }

    #[test]
    fn unknown_state_remains_unknown_and_json_envelope_is_unchanged() {
        let output = output(vec!["cross_layer_path:path:update".to_owned()]);
        let before = output.render_json().unwrap();
        let contexts = vec![context("path:update", InvariantEvaluationState::Unknown)];
        let explanation = BusinessLogicExplainContext::from_output(&output, &contexts)
            .unwrap()
            .expect("matching R3 context");
        let rendered =
            render_explain_human_with_business_logic_context(&output, Some(&explanation));
        let after = output.render_json().unwrap();

        assert!(rendered.contains("[UNKNOWN]"));
        assert!(rendered.contains("bounded repository-derived static context only"));
        assert_eq!(before, after);
        assert_eq!(
            output.finding().draft().epistemic_state,
            EpistemicState::Detected
        );
    }

    #[test]
    fn exact_subject_matching_rejects_prefix_lookalikes_and_unrelated_paths() {
        let output = output(vec![
            "cross_layer_path:path:update-attacker".to_owned(),
            "invariant:invariant:tenant-binding-attacker".to_owned(),
        ]);
        let contexts = vec![context("path:update", InvariantEvaluationState::Violated)];
        assert!(
            BusinessLogicExplainContext::from_output(&output, &contexts)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn exact_path_match_is_not_suppressed_by_unrelated_invariant_subject() {
        let output = output(vec![
            "cross_layer_path:path:update".to_owned(),
            "invariant:invariant:unrelated".to_owned(),
            "invariant_evaluation:eval:unrelated".to_owned(),
        ]);
        let contexts = vec![context("path:update", InvariantEvaluationState::Violated)];
        let explanation = BusinessLogicExplainContext::from_output(&output, &contexts)
            .unwrap()
            .expect("exact path match must retain its bounded chain");

        assert_eq!(explanation.chains().len(), 1);
        assert_eq!(explanation.chains()[0].path_id, "path:update");
        assert_eq!(explanation.chains()[0].invariants.len(), 1);
        assert_eq!(
            explanation.chains()[0].invariants[0].invariant_id,
            "invariant:tenant-binding"
        );
    }

    #[test]
    fn exact_invariant_subject_can_select_one_invariant_without_path_subject() {
        let output = output(vec!["invariant:invariant:tenant-binding".to_owned()]);
        let contexts = vec![context("path:update", InvariantEvaluationState::Satisfied)];
        let explanation = BusinessLogicExplainContext::from_output(&output, &contexts)
            .unwrap()
            .expect("invariant subject selects its chain");
        assert_eq!(explanation.chains().len(), 1);
        assert_eq!(explanation.chains()[0].invariants.len(), 1);
    }

    #[test]
    fn resource_cap_and_duplicate_path_ids_fail_visibly() {
        let output = output(vec!["cross_layer_path:path:0".to_owned()]);
        let too_many: Vec<_> = (0..=DEFAULT_MAX_R3_EXPLAIN_CONTEXTS)
            .map(|index| context(&format!("path:{index}"), InvariantEvaluationState::Unknown))
            .collect();
        assert!(matches!(
            BusinessLogicExplainContext::from_output(&output, &too_many),
            Err(BusinessLogicExplainError::TooManyContexts { .. })
        ));

        let duplicates = vec![
            context("path:update", InvariantEvaluationState::Violated),
            context("path:update", InvariantEvaluationState::Violated),
        ];
        assert!(matches!(
            BusinessLogicExplainContext::from_output(&output, &duplicates),
            Err(BusinessLogicExplainError::DuplicatePathId(value)) if value == "path:update"
        ));
    }
}
