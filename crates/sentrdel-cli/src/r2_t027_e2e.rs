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
    TARGET_BUILD_EXECUTION_ALLOWED,
    project_detection::DetectionLimits,
    reconcile::{ReconciliationRule, reconcile_evidence},
    supabase::{
        SupabaseMigrationDiscoveryError, SupabaseMigrationDiscoveryLimits,
        discover_migration_paths,
        key_authority::{KeyAuthorityLocation, observe_key_literal},
        key_boundary::observe_elevated_key_client_boundary,
        source_context::{
            SourceContextLimits, SourceExecutionContext, classify_source_execution_context,
        },
        sql::SqlScanLimits,
        sql_model::{SqlParseCoverage, parse_sql_model},
    },
    supabase_detection::detect_supabase,
    supabase_integration::SupabaseR2ProviderOutput,
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::{
    SCHEMA_V1,
    canonical::content_id,
    coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension},
    evidence::Evidence,
    finding::{Finding, ReconcilerAuthority, Severity},
};

const CAPTURED_AT: &str = "2026-09-01T01:45:00Z";
const SAFE_CONFIG: &str =
    include_str!("../../../fixtures/repos/r2-supabase/positive/safe-posture/supabase/config.toml");
const SAFE_BROWSER: &str =
    include_str!("../../../fixtures/repos/r2-supabase/positive/safe-posture/src/browser.ts");
const VULNERABLE_CONFIG: &str = include_str!(
    "../../../fixtures/repos/r2-supabase/negative/unsafe-posture/supabase/config.toml"
);
const VULNERABLE_BROWSER: &str =
    include_str!("../../../fixtures/repos/r2-supabase/negative/unsafe-posture/src/browser.ts");
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
                "src/browser.ts",
            ],
            Self::Vulnerable => &[
                "supabase/config.toml",
                "supabase/migrations/20260829000100_baseline.sql",
                "supabase/migrations/20260829000200_widen.sql",
                "supabase/functions/webhook/index.ts",
                "src/browser.ts",
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
}

fn repository(case: FixtureCase) -> CliRepository {
    CliRepository::new(format!("fixture:r2-t027:{}", case.slug()), ".").unwrap()
}

fn normalized_path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).unwrap()
}

fn first_supabase_key_literal(source: &str) -> Option<(&str, usize)> {
    let mut token_start = None;
    for (offset, character) in source.char_indices() {
        let is_token = character.is_ascii_alphanumeric() || character == '_';
        match (token_start, is_token) {
            (None, true) => token_start = Some(offset),
            (Some(start), false) => {
                let token = &source[start..offset];
                if token.starts_with("sb_") {
                    return Some((token, start));
                }
                token_start = None;
            }
            _ => {}
        }
    }

    token_start.and_then(|start| {
        let token = &source[start..];
        token.starts_with("sb_").then_some((token, start))
    })
}

fn source_key_boundary_evidence(path: &str, source: &str) -> Vec<Evidence> {
    let context = classify_source_execution_context(
        &normalized_path(path),
        source,
        SourceContextLimits::default(),
    )
    .unwrap();
    let Some((raw, byte_offset)) = first_supabase_key_literal(source) else {
        return Vec::new();
    };

    let line = source[..byte_offset]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u64
        + 1;
    let line_start = source[..byte_offset]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let start_column = (byte_offset - line_start) as u64 + 1;
    let observation = observe_key_literal(
        raw,
        KeyAuthorityLocation {
            path: normalized_path(path),
            line,
            start_column,
            end_column: start_column + raw.len() as u64,
        },
    )
    .unwrap()
    .expect("fixture key token must classify");
    let digest = content_id("r2-t027-source", &source).unwrap();

    observe_elevated_key_client_boundary(&observation, context, &digest, CAPTURED_AT)
        .unwrap()
        .into_iter()
        .collect()
}

fn analyze_fixture(case: FixtureCase) -> (CoverageState, Vec<Evidence>) {
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

    match case {
        FixtureCase::Safe => {
            let evidence = source_key_boundary_evidence("src/browser.ts", SAFE_BROWSER);
            assert!(evidence.is_empty());
            (CoverageState::Covered, evidence)
        }
        FixtureCase::Vulnerable => {
            let evidence = source_key_boundary_evidence("src/browser.ts", VULNERABLE_BROWSER);
            assert_eq!(evidence.len(), 1);
            assert_eq!(
                evidence[0].claim().category,
                "supabase_elevated_key_client_boundary"
            );
            (CoverageState::Covered, evidence)
        }
        FixtureCase::ContradictoryUnknown => {
            let result = discover_migration_paths(
                case.paths().iter().copied(),
                SupabaseMigrationDiscoveryLimits::default(),
            );
            assert!(matches!(
                result,
                Err(SupabaseMigrationDiscoveryError::AmbiguousOrderKey { .. })
            ));
            (CoverageState::Partial, Vec::new())
        }
        FixtureCase::UnsupportedSyntax => {
            let model = parse_sql_model(UNSUPPORTED_SQL, SqlScanLimits::default()).unwrap();
            assert!(model.statements.iter().any(|statement| {
                statement.coverage == SqlParseCoverage::UnsupportedSecurityRelevant
            }));
            (CoverageState::Unsupported, Vec::new())
        }
        FixtureCase::HostileRepository => {
            let context = classify_source_execution_context(
                &normalized_path("src/browser.ts"),
                HOSTILE_SOURCE,
                SourceContextLimits::default(),
            )
            .unwrap();
            assert_eq!(context, SourceExecutionContext::BrowserOrClient);
            let evidence = source_key_boundary_evidence("src/browser.ts", HOSTILE_SOURCE);
            assert!(evidence.is_empty());
            (CoverageState::Covered, evidence)
        }
    }
}

fn fixture_digest(case: FixtureCase) -> String {
    match case {
        FixtureCase::Safe => content_id(
            "r2-t027-fixture",
            &(case.paths(), SAFE_CONFIG, SAFE_BROWSER),
        ),
        FixtureCase::Vulnerable => content_id(
            "r2-t027-fixture",
            &(case.paths(), VULNERABLE_CONFIG, VULNERABLE_BROWSER),
        ),
        FixtureCase::ContradictoryUnknown => {
            content_id("r2-t027-fixture", &(case.paths(), UNCERTAIN_METADATA))
        }
        FixtureCase::UnsupportedSyntax => {
            content_id("r2-t027-fixture", &(case.paths(), UNSUPPORTED_SQL))
        }
        FixtureCase::HostileRepository => content_id(
            "r2-t027-fixture",
            &(case.paths(), HOSTILE_SOURCE, HOSTILE_HELPER),
        ),
    }
    .unwrap()
}

fn provider(case: FixtureCase) -> SupabaseR2ProviderOutput {
    let (state, evidence) = analyze_fixture(case);
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
        details: Some(
            "R2-T027 coverage derived from bounded production analyzers over fixture bytes"
                .to_owned(),
        ),
        input_digests: vec![fixture_digest(case)],
        observed_at: CAPTURED_AT.to_owned(),
    };
    SupabaseR2ProviderOutput::new(evidence, vec![coverage]).unwrap()
}

fn reconciled_findings(provider: &SupabaseR2ProviderOutput) -> Vec<Finding> {
    if provider.evidence().is_empty() {
        return Vec::new();
    }

    let rule = ReconciliationRule::from_runtime(
        "supabase_elevated_key_client_boundary",
        "supabase_elevated_key_client_boundary",
        "Elevated Supabase authority is referenced from browser/client code",
        "Repository-derived browser/client source references an elevated Supabase key authority class.",
        Severity::High,
    )
    .unwrap();
    let reconciler = ReconcilerAuthority::from_runtime(
        "sentrdel.r2-t027-reconciler",
        "sha256:r2-t027-reconciler-config",
    )
    .unwrap();
    reconcile_evidence(provider.evidence(), &rule, &reconciler, CAPTURED_AT).unwrap()
}

fn baseline_review(case: FixtureCase, provider: &SupabaseR2ProviderOutput) -> ReviewOutput {
    let findings = reconciled_findings(provider);
    let decision = if findings.is_empty() {
        CliDecision::Allow
    } else {
        CliDecision::Ask
    };
    ReviewOutput::new(
        repository(case),
        decision,
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
        let first_provider = provider(case);
        let second_provider = provider(case);
        assert_eq!(
            first_provider,
            second_provider,
            "provider replay drift for {}",
            case.slug()
        );

        let first_review =
            register_supabase_r2_review(&baseline_review(case, &first_provider), &first_provider)
                .unwrap();
        let second_review =
            register_supabase_r2_review(&baseline_review(case, &second_provider), &second_provider)
                .unwrap();
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

        let first_init = register_supabase_r2_init(&baseline_init(case), &first_provider).unwrap();
        let second_init =
            register_supabase_r2_init(&baseline_init(case), &second_provider).unwrap();
        assert_eq!(
            first_init.output,
            second_init.output,
            "init drift for {}",
            case.slug()
        );
        assert_eq!(
            first_init.provider_evidence(),
            first_provider.evidence(),
            "init must register analyzed provider Evidence for {}",
            case.slug()
        );

        let findings = reconciled_findings(&first_provider);
        if let Some(finding) = findings.into_iter().next() {
            let explain = ExplainOutput::new(
                1,
                finding,
                repository(case),
                ImpactComponents::new("browser-client", "reference", "supabase-key-authority")
                    .unwrap(),
                first_provider.coverage().to_vec(),
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
            assert!(baseline_review(case, &first_provider).findings().is_empty());
        }
    }
}

#[test]
fn r2_e2e_ground_truth_is_derived_from_fixture_bytes_and_production_analyzers() {
    assert!(SAFE_CONFIG.contains("[api]"));
    assert!(VULNERABLE_CONFIG.contains("[api]"));
    assert!(UNCERTAIN_METADATA.contains("expected = \"UNCERTAIN\""));
    assert!(UNSUPPORTED_SQL.contains("EXECUTE"));
    assert!(HOSTILE_SOURCE.contains("SYSTEM:"));
    assert!(HOSTILE_SOURCE.contains("connect to Supabase"));
    assert!(HOSTILE_HELPER.contains("rustc-wrapper"));
    assert!(HOSTILE_HELPER.contains("runner"));

    let safe = provider(FixtureCase::Safe);
    let vulnerable = provider(FixtureCase::Vulnerable);
    let contradictory = provider(FixtureCase::ContradictoryUnknown);
    let unsupported = provider(FixtureCase::UnsupportedSyntax);
    let hostile = provider(FixtureCase::HostileRepository);

    assert_eq!(safe.coverage()[0].state, CoverageState::Covered);
    assert!(safe.evidence().is_empty());
    assert_eq!(vulnerable.coverage()[0].state, CoverageState::Covered);
    assert_eq!(vulnerable.evidence().len(), 1);
    assert_eq!(contradictory.coverage()[0].state, CoverageState::Partial);
    assert!(contradictory.evidence().is_empty());
    assert_eq!(unsupported.coverage()[0].state, CoverageState::Unsupported);
    assert!(unsupported.evidence().is_empty());
    assert_eq!(hostile.coverage()[0].state, CoverageState::Covered);
    assert!(hostile.evidence().is_empty());
    assert!(
        !format!("{vulnerable:?}").contains("SENTRDEL_CANARY_BROWSER_ELEVATED_NOT_A_CREDENTIAL")
    );

    const { assert!(!TARGET_BUILD_EXECUTION_ALLOWED) };
}
