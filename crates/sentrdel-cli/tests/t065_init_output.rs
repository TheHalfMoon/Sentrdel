use sentrdel_cli::CliDecision;
use sentrdel_cli::init::build_init_output;
use sentrdel_review::config_detection::CiMcpConfigDetection;
use sentrdel_review::pack_registry::SecurityPackRegistry;
use sentrdel_review::profile::build_project_profile_snapshot;
use sentrdel_review::project_detection::{DetectionLimits, LanguageEcosystemDetection};
use sentrdel_review::stack_detection::{
    PathMatchRule, StackDetectorRegistry, StackDetectorSpec, StackKind,
};
use sentrdel_review::supabase_detection::detect_supabase;
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::CoverageState;
use sentrdel_schema::pack::{SecurityPackManifest, SourceProvenance};
use serde_json::Value;

const NEXT_RULES: &[PathMatchRule] = &[PathMatchRule::Basename("next.config.mjs")];
const FIREBASE_RULES: &[PathMatchRule] = &[PathMatchRule::Exact("firebase.json")];
const STACK_SPECS: &[StackDetectorSpec] = &[
    StackDetectorSpec::new("firebase", StackKind::Provider, FIREBASE_RULES),
    StackDetectorSpec::new("nextjs", StackKind::Framework, NEXT_RULES),
];

fn pack() -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: "nextjs-r1".to_owned(),
        version: "0.1.0".to_owned(),
        provider_or_framework: "nextjs".to_owned(),
        source_provenance: SourceProvenance {
            source_id: "sentrdel-owned".to_owned(),
            exact_ref: "t065-fixture".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec!["nextjs.detect".to_owned()],
        evidence_capabilities: vec!["nextjs.posture".to_owned()],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: vec!["DETECTION".to_owned(), "STATIC_POSTURE".to_owned()],
    }
}

fn snapshot() -> sentrdel_review::profile::ProjectProfileSnapshot {
    let stacks = StackDetectorRegistry::new(STACK_SPECS)
        .unwrap()
        .detect(
            ["apps/web/next.config.mjs", "firebase.json"],
            DetectionLimits::default(),
        )
        .unwrap();
    let supabase = detect_supabase(["supabase/config.toml"], DetectionLimits::default()).unwrap();
    let mut packs = SecurityPackRegistry::new();
    packs.register(pack()).unwrap();
    build_project_profile_snapshot(
        "repo:fixture",
        "sha256:root-fixture",
        &LanguageEcosystemDetection {
            languages: vec!["typescript".to_owned()],
            package_ecosystems: vec!["npm".to_owned()],
        },
        &CiMcpConfigDetection {
            ci_systems: vec!["github-actions".to_owned()],
            mcp_configurations: vec!["cursor-mcp".to_owned()],
        },
        &stacks,
        &supabase,
        &packs,
        "2026-08-29T00:00:00Z",
        "2026-08-29T00:00:00Z",
    )
    .unwrap()
}

#[test]
fn human_init_output_leads_with_inventory_and_makes_gaps_visible() {
    let output = build_init_output(&snapshot(), ".", 7).unwrap();
    assert_eq!(output.envelope.decision, CliDecision::Allow);
    assert!(
        output
            .human
            .starts_with("Sentrdel init\nRepository: repo:fixture (.)\n")
    );
    for expected in [
        "Languages: typescript",
        "Package ecosystems: npm",
        "CI: github-actions",
        "MCP configurations: cursor-mcp",
        "Providers: firebase, supabase",
        "Frameworks: nextjs",
        "Security packs: nextjs-r1",
        "framework nextjs / STATIC_POSTURE: Unavailable (PACK_REGISTERED_NOT_RUN)",
        "provider supabase / STATIC_POSTURE: Unsupported (R1_POSTURE_NOT_IMPLEMENTED)",
        "Warning:",
    ] {
        assert!(output.human.contains(expected), "missing {expected:?}");
    }
}

#[test]
fn json_init_output_preserves_frozen_envelope_and_explicit_pack_dimensions() {
    let output = build_init_output(&snapshot(), ".", 7).unwrap();
    let json = output.json_line().unwrap();
    let value: Value = serde_json::from_str(json.trim_end()).unwrap();
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
    assert_eq!(object["command"], "init");
    assert_eq!(object["decision"], "ALLOW");
    assert_eq!(object["repository"]["identity"], "repo:fixture");

    let coverage = object["coverage"].as_array().unwrap();
    assert_eq!(coverage.len(), 15);
    assert!(coverage.iter().any(|record| {
        record["capability"] == "framework.nextjs.STATIC_POSTURE"
            && record["state"] == "UNAVAILABLE"
            && record["reason_code"] == "PACK_REGISTERED_NOT_RUN"
    }));
    assert!(coverage.iter().any(|record| {
        record["capability"] == "provider.supabase.STATIC_POSTURE"
            && record["state"] == "UNSUPPORTED"
            && record["provider_dimension"] == "STATIC_POSTURE"
            && record["reason_code"] == "R1_POSTURE_NOT_IMPLEMENTED"
    }));
    assert!(coverage.iter().all(|record| {
        record["state"] != serde_json::to_value(CoverageState::Covered).unwrap()
            || record["capability"]
                .as_str()
                .is_some_and(|capability| capability.ends_with(".DETECTION"))
    }));

    let diagnostics = object["diagnostics"].as_array().unwrap();
    assert!(diagnostics.iter().any(|diagnostic| {
        diagnostic["code"] == "INIT_LANGUAGES"
            && diagnostic["message"] == "Detected languages: typescript"
    }));
}

#[test]
fn identical_snapshot_has_deterministic_json_except_duration() {
    let first = build_init_output(&snapshot(), ".", 7).unwrap();
    let second = build_init_output(&snapshot(), ".", 7).unwrap();
    assert_eq!(first.json_line().unwrap(), second.json_line().unwrap());
}
