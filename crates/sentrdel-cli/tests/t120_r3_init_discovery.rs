use sentrdel_cli::init::build_init_output;
use sentrdel_review::business_logic::{
    R3_BUSINESS_LOGIC_PACK_ID, R3_BUSINESS_LOGIC_PROVIDER, manifest as r3_manifest,
    register_r3_pack,
};
use sentrdel_review::config_detection::CiMcpConfigDetection;
use sentrdel_review::pack_registry::{PackCoverageDimension, SecurityPackRegistry};
use sentrdel_review::profile::{ProjectCoverageSubjectKind, build_project_profile_snapshot};
use sentrdel_review::project_detection::{DetectionLimits, LanguageEcosystemDetection};
use sentrdel_review::stack_detection::{
    PathMatchRule, StackDetectorRegistry, StackDetectorSpec, StackKind,
};
use sentrdel_review::supabase_detection::detect_supabase;
use sentrdel_schema::coverage::CoverageState;
use serde_json::Value;

const NEXT_RULES: &[PathMatchRule] = &[PathMatchRule::Basename("next.config.mjs")];
const STACK_SPECS: &[StackDetectorSpec] = &[
    StackDetectorSpec::new("nextjs", StackKind::Framework, NEXT_RULES),
];

fn snapshot(packs: &SecurityPackRegistry) -> sentrdel_review::profile::ProjectProfileSnapshot {
    let stacks = StackDetectorRegistry::new(STACK_SPECS)
        .unwrap()
        .detect(["apps/web/next.config.mjs"], DetectionLimits::default())
        .unwrap();
    let supabase = detect_supabase(std::iter::empty::<&str>(), DetectionLimits::default()).unwrap();
    build_project_profile_snapshot(
        "repo:r3-t028-fixture",
        "sha256:r3-t028-root",
        &LanguageEcosystemDetection {
            languages: vec!["typescript".to_owned()],
            package_ecosystems: vec!["npm".to_owned()],
        },
        &CiMcpConfigDetection {
            ci_systems: Vec::new(),
            mcp_configurations: Vec::new(),
        },
        &stacks,
        &supabase,
        packs,
        "2026-09-07T00:00:00Z",
        "2026-09-07T00:00:00Z",
    )
    .unwrap()
}

#[test]
fn canonical_r3_pack_is_discoverable_without_widening_framework_coverage() {
    let mut packs = SecurityPackRegistry::new();
    register_r3_pack(&mut packs).unwrap();

    let snapshot = snapshot(&packs);
    assert_eq!(
        snapshot.profile.security_packs,
        vec![R3_BUSINESS_LOGIC_PACK_ID.to_owned()]
    );

    let business_logic = snapshot
        .coverage
        .get(
            ProjectCoverageSubjectKind::Project,
            R3_BUSINESS_LOGIC_PROVIDER,
            PackCoverageDimension::BusinessLogic,
        )
        .expect("project-level R3 capability discovery");
    assert_eq!(business_logic.state, CoverageState::Unavailable);
    assert_eq!(
        business_logic.reason_code.as_deref(),
        Some("PACK_REGISTERED_NOT_RUN")
    );

    let unsupported_framework = snapshot
        .coverage
        .get(
            ProjectCoverageSubjectKind::Framework,
            "nextjs",
            PackCoverageDimension::BusinessLogic,
        )
        .expect("existing framework coverage row");
    assert_eq!(unsupported_framework.state, CoverageState::Unsupported);
    assert_eq!(
        unsupported_framework.reason_code.as_deref(),
        Some("R1_POSTURE_NOT_IMPLEMENTED")
    );
}

#[test]
fn init_surfaces_r3_capability_as_unavailable_until_analysis_runs() {
    let mut packs = SecurityPackRegistry::new();
    register_r3_pack(&mut packs).unwrap();
    let output = build_init_output(&snapshot(&packs), ".", 3).unwrap();

    assert!(
        output
            .human
            .contains("Security packs: sentrdel.business-logic.static")
    );
    assert!(output.human.contains(
        "project cross-layer / BUSINESS_LOGIC: Unavailable (PACK_REGISTERED_NOT_RUN)"
    ));

    let json = output.json_line().unwrap();
    let value: Value = serde_json::from_str(json.trim_end()).unwrap();
    let coverage = value["coverage"].as_array().unwrap();
    assert!(coverage.iter().any(|record| {
        record["capability"] == "project.cross-layer.BUSINESS_LOGIC"
            && record["state"] == "UNAVAILABLE"
            && record["reason_code"] == "PACK_REGISTERED_NOT_RUN"
            && record["provider_dimension"] == "CROSS_LAYER_BUSINESS_LOGIC"
    }));
    assert!(coverage.iter().all(|record| {
        record["capability"] != "framework.nextjs.BUSINESS_LOGIC"
            || record["state"] == "UNSUPPORTED"
    }));
}

#[test]
fn spoofed_r3_pack_id_is_not_reported_as_native_capability() {
    let mut spoof = r3_manifest();
    spoof.version = "spoofed".to_owned();
    spoof.evidence_capabilities = vec!["spoofed-evidence".to_owned()];
    let mut packs = SecurityPackRegistry::new();
    packs.register(spoof).unwrap();

    let snapshot = snapshot(&packs);
    assert!(snapshot.profile.security_packs.is_empty());
    assert!(
        snapshot
            .coverage
            .get(
                ProjectCoverageSubjectKind::Project,
                R3_BUSINESS_LOGIC_PROVIDER,
                PackCoverageDimension::BusinessLogic,
            )
            .is_none()
    );
}
