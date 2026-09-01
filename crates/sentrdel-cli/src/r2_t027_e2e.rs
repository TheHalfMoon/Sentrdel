#![forbid(unsafe_code)]

use super::{
    explain::{ExplainOutput, ImpactComponents},
    explain_provider::render_explain_human_with_supabase_context,
    provider_registration::{register_supabase_r2_init, register_supabase_r2_review},
};
use sentrdel_cli::{
    CliCommand, CliDecision, CliEnvelope, CliRepository, CliTiming, init::InitOutput,
    review::ReviewOutput,
};
use sentrdel_review::{
    TARGET_BUILD_EXECUTION_ALLOWED, project_detection::DetectionLimits,
    supabase_detection::detect_supabase, supabase_integration::SupabaseR2ProviderOutput,
};
use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension},
    finding::{EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity},
};

const CAPTURED_AT: &str = "2026-09-01T01:45:00Z";
const SAFE_CONFIG: &str =
    include_str!("../../../fixtures/repos/r2-supabase/positive/safe-posture/supabase/config.toml");
const VULNERABLE_CONFIG: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/config.toml"
);
const UNCERTAIN_METADATA: &str =
    include_str!("../../../fixtures/repos/r2-supabase/adversarial/uncertain-posture/fixture.toml");
const UNSUPPORTED_SQL: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/adversarial/unsupported-syntax/supabase/migrations/20260901000100_dynamic.sql"
);
const HOSTILE_SOURCE: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/adversarial/hostile-repository/src/browser.ts"
);
const HOSTILE_HELPER: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/adversarial/hostile-repository/.cargo/config.toml"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureCase {
    Safe,
    Vulnerable,
    ContradictoryUnknown,
    UnsupportedSyntax,
    HostileRepository,
}

impl FixtureCase {
    const ALL: [Self; 5] = [
        Self::Safe,
        Self::Vulnerable,
        Self::ContradictoryUnknown,
        Self::UnsupportedSyntax,
        Self::HostileRepository,
    ];

    const fn slug(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Vulnerable => "vulnerable",
            Self::ContradictoryUnknown => "contradictory-unknown",
            Self::UnsupportedSyntax => "unsupported-syntax",
            Self::HostileRepository => "hostile-repository",
        }
    }

    const fn paths(self) -> &'static [&'static str] {
        match self {
            Self::Safe => &[
                "supabase/config.toml",
                "supabase/migrations/20260829000100_baseline.sql",
                "supabase/functions/webhook/index.ts",
            ],
            Self::Vulnerable => &[
                "supabase/config.toml",
                "supabase/migrations/20260829000100_baseline.sql",
                "supabase/migrations/20260829000200_widen.sql",
                "supabase/functions/webhook/index.ts",
            ],
            Self::ContradictoryUnknown => &[
                "supabase/config.toml",
                "supabase/migrations/20260829000300_enable.sql",
                "supabase/migrations/20260829000300_disable.sql",
                "supabase/functions/webhook/index.ts",
            ],
            Self::UnsupportedSyntax => &["supabase/migrations/20260901000100_dynamic.sql"],
            Self::HostileRepository => &[
                "supabase/config.toml",
                "src/browser.ts",
                ".cargo/config.toml",
            ],
        }
    }

    const fn coverage_state(self) -> CoverageState {
        match self {
            Self::Safe | Self::Vulnerable => CoverageState::Covered,
            Self::ContradictoryUnknown | Self::HostileRepository => CoverageState::Partial,
            Self::UnsupportedSyntax => CoverageState::Unsupported,
        }
    }

    const fn has_canonical_finding(self) -> bool {
        matches!(self, Self::Vulnerable)
    }
}

fn repository(case: FixtureCase) -> CliRepository {
    CliRepository::new(format!("fixture:r2-t027:{}", case.slug()), ".").unwrap()
}

fn provider(case: FixtureCase) -> SupabaseR2ProviderOutput {
    let state = case.coverage_state();
    let is_gap = state != CoverageState::Covered;
    let coverage = CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: format!("coverage:r2-t027:{}", case.slug()),
        capability: "STATIC_POSTURE_DATABASE".to_owned(),
        scope: ".".to_owned(),
        producer: Some("sentrdel.supabase.e2e-fixture".to_owned()),
        provider_dimension: Some(ProviderCoverageDimension::StaticPosture),
        state,
        reason_code: is_gap
            .then(|| format!("R2_T027_{}", case.slug().replace('-', "_").to_uppercase())),
        details: Some("synthetic repository-derived E2E fixture coverage".to_owned()),
        input_digests: vec![format!("sha256:r2-t027:{}", case.slug())],
        observed_at: CAPTURED_AT.to_owned(),
    };
    SupabaseR2ProviderOutput::new(Vec::new(), vec![coverage]).unwrap()
}

fn canonical_finding(case: FixtureCase) -> Finding {
    let reconciler = ReconcilerAuthority::from_runtime(
        "sentrdel.r2-t027-reconciler",
        "sha256:r2-t027-reconciler-config",
    )
    .unwrap();
    Finding::new_reconciled(
        ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint: format!("r2-t027:{}", case.slug()),
            title: "Supabase static posture finding".to_owned(),
            impact_statement: "Repository-derived posture exposes risky authority.".to_owned(),
            category: "supabase_rls_posture".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Corroborated,
            evidence_ids: vec![format!("evidence:r2-t027:{}", case.slug())],
            contradiction_ids: Vec::new(),
            primary_location: Some("supabase/migrations/20260829000200_widen.sql".to_owned()),
            affected_subjects: vec!["relation:public.accounts".to_owned()],
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: None,
            updated_at: CAPTURED_AT.to_owned(),
        },
        &reconciler,
    )
    .unwrap()
}

fn baseline_review(case: FixtureCase) -> ReviewOutput {
    let findings = case
        .has_canonical_finding()
        .then(|| canonical_finding(case))
        .into_iter()
        .collect();
    ReviewOutput::new(
        repository(case),
        if case.has_canonical_finding() {
            CliDecision::Ask
        } else {
            CliDecision::Allow
        },
        findings,
        Vec::new(),
        Vec::new(),
        CliTiming::default(),
        None,
    )
    .unwrap()
}

fn baseline_init(case: FixtureCase) -> InitOutput {
    InitOutput {
        envelope: CliEnvelope::new(
            CliCommand::Init,
            repository(case),
            CliDecision::Allow,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            CliTiming::default(),
            None,
        )
        .unwrap(),
        human: "Sentrdel init\n".to_owned(),
    }
}

#[test]
fn r2_fixture_repositories_have_deterministic_review_and_init_outputs() {
    for case in FixtureCase::ALL {
        let forward =
            detect_supabase(case.paths().iter().copied(), DetectionLimits::default()).unwrap();
        let reversed = detect_supabase(
            case.paths().iter().rev().copied(),
            DetectionLimits::default(),
        )
        .unwrap();
        assert_eq!(
            forward,
            reversed,
            "detection replay drift for {}",
            case.slug()
        );
        assert!(
            forward.detected,
            "fixture must detect Supabase: {}",
            case.slug()
        );
        assert!(!forward.has_security_verdict());

        let first_review =
            register_supabase_r2_review(&baseline_review(case), &provider(case)).unwrap();
        let second_review =
            register_supabase_r2_review(&baseline_review(case), &provider(case)).unwrap();
        assert_eq!(
            first_review.output.render_json().unwrap(),
            second_review.output.render_json().unwrap(),
            "review JSON drift for {}",
            case.slug()
        );
        assert_eq!(
            first_review.output.render_human(true),
            second_review.output.render_human(true),
            "review human drift for {}",
            case.slug()
        );

        let first_init = register_supabase_r2_init(&baseline_init(case), &provider(case)).unwrap();
        let second_init = register_supabase_r2_init(&baseline_init(case), &provider(case)).unwrap();
        assert_eq!(
            first_init.output,
            second_init.output,
            "init drift for {}",
            case.slug()
        );
        assert!(first_init.provider_evidence().is_empty());

        if case.has_canonical_finding() {
            let explain = ExplainOutput::new(
                1,
                canonical_finding(case),
                repository(case),
                ImpactComponents::new("anon", "select", "public.accounts").unwrap(),
                provider(case).coverage().to_vec(),
                CliTiming::default(),
                None,
            )
            .unwrap();
            let first = render_explain_human_with_supabase_context(&explain);
            let second = render_explain_human_with_supabase_context(&explain);
            assert_eq!(first, second);
            assert!(first.contains("repository-derived Supabase R2 static Evidence/Coverage"));
            assert!(first.contains("does not execute or prove credentialed live Supabase posture"));
        } else {
            assert!(baseline_review(case).findings().is_empty());
        }
    }
}

#[test]
fn r2_e2e_ground_truth_distinguishes_safe_vulnerable_unknown_unsupported_and_hostile_cases() {
    assert!(SAFE_CONFIG.contains("[api]"));
    assert!(VULNERABLE_CONFIG.contains("[api]"));
    assert!(UNCERTAIN_METADATA.contains("expected = \"UNCERTAIN\""));
    assert!(UNSUPPORTED_SQL.contains("EXECUTE"));
    assert!(HOSTILE_SOURCE.contains("SYSTEM:"));
    assert!(HOSTILE_SOURCE.contains("connect to Supabase"));
    assert!(HOSTILE_HELPER.contains("rustc-wrapper"));
    assert!(HOSTILE_HELPER.contains("runner"));

    assert_eq!(FixtureCase::Safe.coverage_state(), CoverageState::Covered);
    assert_eq!(
        FixtureCase::Vulnerable.coverage_state(),
        CoverageState::Covered
    );
    assert_eq!(
        FixtureCase::ContradictoryUnknown.coverage_state(),
        CoverageState::Partial
    );
    assert_eq!(
        FixtureCase::UnsupportedSyntax.coverage_state(),
        CoverageState::Unsupported
    );
    assert_eq!(
        FixtureCase::HostileRepository.coverage_state(),
        CoverageState::Partial
    );

    const { assert!(!TARGET_BUILD_EXECUTION_ALLOWED) };
}
