//! Output-only Supabase R2 context for `sentrdel explain`.
//!
//! This module derives presentation context only from an already-canonical
//! Finding and matching static provider Coverage. It never creates or mutates a
//! Finding and never performs provider, network, SQL, or target execution.

use sentrdel_schema::coverage::ProviderCoverageDimension;

use crate::explain::ExplainOutput;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupabaseExplainContext {
    pub affected_object: String,
    pub control_layer: &'static str,
    pub static_provenance: &'static str,
    pub limitation: &'static str,
}

impl SupabaseExplainContext {
    #[must_use]
    pub fn from_output(output: &ExplainOutput) -> Option<Self> {
        let draft = output.finding().draft();
        let control_layer = control_layer(&draft.category)?;
        let has_static_supabase_coverage = output.envelope().coverage.iter().any(|record| {
            record.provider_dimension == Some(ProviderCoverageDimension::StaticPosture)
                && record
                    .producer
                    .as_deref()
                    .is_some_and(|producer| producer.starts_with("sentrdel.supabase."))
        });
        if !has_static_supabase_coverage {
            return None;
        }

        Some(Self {
            affected_object: draft
                .primary_location
                .clone()
                .unwrap_or_else(|| draft.category.clone()),
            control_layer,
            static_provenance: "repository-derived Supabase R2 static Evidence/Coverage",
            limitation: "R2 does not execute or prove credentialed live Supabase posture; live posture remains a separate coverage dimension.",
        })
    }

    #[must_use]
    pub fn render_human(&self) -> String {
        format!(
            "Supabase provider context:\n- provenance: {}\n- affected object: {}\n- control layer: {}\n- limitation: {}\n",
            self.static_provenance, self.affected_object, self.control_layer, self.limitation
        )
    }
}

#[must_use]
pub fn render_explain_human_with_supabase_context(output: &ExplainOutput) -> String {
    let mut rendered = output.render_human();
    if let Some(context) = SupabaseExplainContext::from_output(output) {
        if !rendered.ends_with('\n') {
            rendered.push('\n');
        }
        rendered.push('\n');
        rendered.push_str(&context.render_human());
    }
    rendered
}

fn control_layer(category: &str) -> Option<&'static str> {
    if !category.starts_with("supabase_") {
        return None;
    }
    if category.starts_with("supabase_storage_") {
        Some("STORAGE")
    } else if category.starts_with("supabase_edge_function_") {
        Some("EDGE_FUNCTIONS")
    } else if category.starts_with("supabase_elevated_key_") {
        Some("KEY_BOUNDARY")
    } else if category.starts_with("supabase_auth_") {
        Some("AUTH_CONFIG")
    } else if category.starts_with("supabase_rls_")
        || category.starts_with("supabase_policy_")
        || category.starts_with("supabase_api_role_")
        || category.starts_with("supabase_function_")
        || category.starts_with("supabase_api_exposure")
    {
        Some("DATABASE")
    } else {
        Some("STATIC_POSTURE")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_cli::{CliRepository, CliTiming};
    use sentrdel_schema::SCHEMA_V1;
    use sentrdel_schema::coverage::{CoverageRecord, CoverageState};
    use sentrdel_schema::finding::{
        EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity,
    };

    fn finding(category: &str) -> Finding {
        let reconciler =
            ReconcilerAuthority::from_runtime("sentrdel-reconciler", "sha256:r2-t026-config")
                .unwrap();
        Finding::new_reconciled(
            ReconciledFindingDraft {
                schema_version: SCHEMA_V1.to_owned(),
                fingerprint: format!("r2-t026:{category}"),
                title: "Supabase static posture finding".to_owned(),
                impact_statement: "Repository-derived posture exposes risky authority.".to_owned(),
                category: category.to_owned(),
                severity: Severity::High,
                epistemic_state: EpistemicState::Corroborated,
                evidence_ids: vec!["evidence:r2".to_owned()],
                contradiction_ids: Vec::new(),
                primary_location: Some("supabase/migrations/20260901010101_policy.sql".to_owned()),
                affected_subjects: vec!["relation:public.notes".to_owned()],
                first_seen_commit: None,
                last_seen_commit: None,
                remediation: None,
                updated_at: "2026-09-01T01:00:00Z".to_owned(),
            },
            &reconciler,
        )
        .unwrap()
    }

    fn coverage(dimension: Option<ProviderCoverageDimension>) -> CoverageRecord {
        CoverageRecord {
            schema_version: SCHEMA_V1.to_owned(),
            coverage_id: "coverage:r2:database".to_owned(),
            capability: "STATIC_POSTURE_DATABASE".to_owned(),
            scope: ".".to_owned(),
            producer: Some("sentrdel.supabase.rls-posture".to_owned()),
            provider_dimension: dimension,
            state: CoverageState::Covered,
            reason_code: None,
            details: Some("repository-derived static posture".to_owned()),
            input_digests: vec!["sha256:r2".to_owned()],
            observed_at: "2026-09-01T01:00:00Z".to_owned(),
        }
    }

    fn output(category: &str, coverage: Vec<CoverageRecord>) -> ExplainOutput {
        ExplainOutput::new(
            1,
            finding(category),
            CliRepository::new("repo:r2", ".").unwrap(),
            crate::explain::ImpactComponents::new("anon", "select", "public.notes").unwrap(),
            coverage,
            CliTiming::default(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn supabase_static_finding_renders_provenance_object_layer_and_non_live_limit() {
        let output = output(
            "supabase_rls_posture",
            vec![coverage(Some(ProviderCoverageDimension::StaticPosture))],
        );
        let rendered = render_explain_human_with_supabase_context(&output);
        assert!(rendered.contains("repository-derived Supabase R2 static Evidence/Coverage"));
        assert!(rendered.contains("supabase/migrations/20260901010101_policy.sql"));
        assert!(rendered.contains("control layer: DATABASE"));
        assert!(rendered.contains("does not execute or prove credentialed live Supabase posture"));
    }

    #[test]
    fn provider_context_requires_matching_static_supabase_coverage() {
        let output = output("supabase_rls_posture", Vec::new());
        assert!(SupabaseExplainContext::from_output(&output).is_none());

        let output = output(
            "supabase_rls_posture",
            vec![coverage(Some(
                ProviderCoverageDimension::CredentialedLivePosture,
            ))],
        );
        assert!(SupabaseExplainContext::from_output(&output).is_none());
    }

    #[test]
    fn non_supabase_findings_do_not_gain_provider_context() {
        let output = output(
            "dependency_vulnerability",
            vec![coverage(Some(ProviderCoverageDimension::StaticPosture))],
        );
        assert!(SupabaseExplainContext::from_output(&output).is_none());
    }
}
