use sentrdel_review::config_detection::CiMcpConfigDetection;
use sentrdel_review::pack_registry::{PackCoverageDimension, SecurityPackRegistry};
use sentrdel_review::profile::{ProjectCoverageSubjectKind, build_project_profile_snapshot};
use sentrdel_review::project_detection::{DetectionLimits, LanguageEcosystemDetection};
use sentrdel_review::stack_detection::{
    PathMatchRule, StackDetectorRegistry, StackDetectorSpec, StackKind,
};
use sentrdel_review::supabase::{SUPABASE_R2_PACK_ID, register_r2_pack};
use sentrdel_review::supabase_detection::detect_supabase;
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::CoverageState;
use sentrdel_schema::pack::{SecurityPackManifest, SourceProvenance};
use sentrdel_schema::project::PackStatus;

const NEXT_RULES: &[PathMatchRule] = &[PathMatchRule::Basename("next.config.mjs")];
const FIREBASE_RULES: &[PathMatchRule] = &[PathMatchRule::Exact("firebase.json")];
const STACK_SPECS: &[StackDetectorSpec] = &[
    StackDetectorSpec::new("firebase", StackKind::Provider, FIREBASE_RULES),
    StackDetectorSpec::new("nextjs", StackKind::Framework, NEXT_RULES),
];

fn pack(pack_id: &str, subject: &str) -> SecurityPackManifest {
    SecurityPackManifest {
        schema_version: SCHEMA_V1.to_owned(),
        pack_id: pack_id.to_owned(),
        version: "0.1.0".to_owned(),
        provider_or_framework: subject.to_owned(),
        source_provenance: SourceProvenance {
            source_id: "sentrdel-owned".to_owned(),
            exact_ref: "t064-fixture".to_owned(),
            license_expression: "Apache-2.0".to_owned(),
            integrity_digest: None,
        },
        detection_capabilities: vec![format!("{subject}.detect")],
        evidence_capabilities: vec![format!("{subject}.posture")],
        required_engines: Vec::new(),
        required_features: Vec::new(),
        coverage_dimensions: vec!["DETECTION".to_owned(), "STATIC_POSTURE".to_owned()],
    }
}

#[test]
fn project_profile_and_coverage_are_deterministic_and_honest() {
    let stacks = StackDetectorRegistry::new(STACK_SPECS)
        .unwrap()
        .detect(
            ["apps/web/next.config.mjs", "firebase.json"],
            DetectionLimits::default(),
        )
        .unwrap();
    let supabase = detect_supabase(
        [
            "supabase/config.toml",
            "supabase/migrations/20260829_init.sql",
        ],
        DetectionLimits::default(),
    )
    .unwrap();

    let mut packs = SecurityPackRegistry::new();
    packs.register(pack("nextjs-r1", "nextjs")).unwrap();
    register_r2_pack(&mut packs).unwrap();

    let snapshot = build_project_profile_snapshot(
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
    .unwrap();

    assert_eq!(snapshot.profile.schema_version, SCHEMA_V1);
    assert_eq!(snapshot.profile.languages, vec!["typescript"]);
    assert_eq!(snapshot.profile.package_ecosystems, vec!["npm"]);
    assert_eq!(snapshot.profile.ci_systems, vec!["github-actions"]);
    assert_eq!(snapshot.profile.mcp_configurations, vec!["cursor-mcp"]);
    assert_eq!(
        snapshot.profile.security_packs,
        vec!["nextjs-r1".to_owned(), SUPABASE_R2_PACK_ID.to_owned()]
    );

    let supabase_provider = snapshot
        .profile
        .detected_providers
        .iter()
        .find(|provider| provider.provider_id == "supabase")
        .unwrap();
    assert_eq!(supabase_provider.pack_status, PackStatus::Available);
    assert!(supabase_provider.evidence_ids.is_empty());

    let firebase_detection = snapshot
        .coverage
        .get(
            ProjectCoverageSubjectKind::Provider,
            "firebase",
            PackCoverageDimension::Detection,
        )
        .unwrap();
    assert_eq!(firebase_detection.state, CoverageState::Covered);
    assert!(firebase_detection.reason_code.is_none());

    let supabase_static = snapshot
        .coverage
        .get(
            ProjectCoverageSubjectKind::Provider,
            "supabase",
            PackCoverageDimension::StaticPosture,
        )
        .unwrap();
    assert_eq!(supabase_static.state, CoverageState::Unavailable);
    assert_eq!(
        supabase_static.reason_code.as_deref(),
        Some("PACK_REGISTERED_NOT_RUN")
    );

    for dimension in [
        PackCoverageDimension::LivePosture,
        PackCoverageDimension::BusinessLogic,
        PackCoverageDimension::Runtime,
    ] {
        let gap = snapshot
            .coverage
            .get(ProjectCoverageSubjectKind::Provider, "supabase", dimension)
            .unwrap();
        assert_eq!(gap.state, CoverageState::Unsupported);
        assert_eq!(
            gap.reason_code.as_deref(),
            Some("SUPABASE_R2_DIMENSION_NOT_IMPLEMENTED")
        );
    }

    let next_static = snapshot
        .coverage
        .get(
            ProjectCoverageSubjectKind::Framework,
            "nextjs",
            PackCoverageDimension::StaticPosture,
        )
        .unwrap();
    assert_eq!(next_static.state, CoverageState::Unavailable);
    assert_eq!(
        next_static.reason_code.as_deref(),
        Some("PACK_REGISTERED_NOT_RUN")
    );
    assert!(snapshot.coverage.gap_count > 0);
}

#[test]
fn supabase_without_registered_native_pack_is_not_reported_as_implemented() {
    let stacks = StackDetectorRegistry::new(&[])
        .unwrap()
        .detect(std::iter::empty::<&str>(), DetectionLimits::default())
        .unwrap();
    let supabase = detect_supabase(["supabase/config.toml"], DetectionLimits::default()).unwrap();
    let packs = SecurityPackRegistry::new();

    let snapshot = build_project_profile_snapshot(
        "repo:fixture",
        "sha256:root",
        &LanguageEcosystemDetection {
            languages: Vec::new(),
            package_ecosystems: Vec::new(),
        },
        &CiMcpConfigDetection {
            ci_systems: Vec::new(),
            mcp_configurations: Vec::new(),
        },
        &stacks,
        &supabase,
        &packs,
        "2026-08-29T00:00:00Z",
        "2026-08-29T00:00:00Z",
    )
    .unwrap();

    let provider = snapshot
        .profile
        .detected_providers
        .iter()
        .find(|provider| provider.provider_id == "supabase")
        .unwrap();
    assert_eq!(provider.pack_status, PackStatus::NotInstalled);
    assert!(snapshot.profile.security_packs.is_empty());
}

#[test]
fn spoofed_supabase_pack_id_does_not_gain_native_r2_availability() {
    let stacks = StackDetectorRegistry::new(&[])
        .unwrap()
        .detect(std::iter::empty::<&str>(), DetectionLimits::default())
        .unwrap();
    let supabase = detect_supabase(["supabase/config.toml"], DetectionLimits::default()).unwrap();
    let mut spoof = sentrdel_review::supabase::manifest();
    spoof.version = "spoofed".to_owned();
    spoof.evidence_capabilities = vec!["spoofed-capability".to_owned()];
    let mut packs = SecurityPackRegistry::new();
    packs.register(spoof).unwrap();

    let snapshot = build_project_profile_snapshot(
        "repo:fixture",
        "sha256:root",
        &LanguageEcosystemDetection {
            languages: Vec::new(),
            package_ecosystems: Vec::new(),
        },
        &CiMcpConfigDetection {
            ci_systems: Vec::new(),
            mcp_configurations: Vec::new(),
        },
        &stacks,
        &supabase,
        &packs,
        "2026-08-29T00:00:00Z",
        "2026-08-29T00:00:00Z",
    )
    .unwrap();

    let provider = snapshot
        .profile
        .detected_providers
        .iter()
        .find(|provider| provider.provider_id == "supabase")
        .unwrap();
    assert_eq!(provider.pack_status, PackStatus::NotInstalled);
    let static_gap = snapshot
        .coverage
        .get(
            ProjectCoverageSubjectKind::Provider,
            "supabase",
            PackCoverageDimension::StaticPosture,
        )
        .unwrap();
    assert_eq!(static_gap.state, CoverageState::Unavailable);
    assert_eq!(
        static_gap.reason_code.as_deref(),
        Some("PACK_REGISTERED_NOT_RUN")
    );
}

#[test]
fn profile_rejects_blank_persistence_identity_inputs() {
    let stacks = StackDetectorRegistry::new(&[])
        .unwrap()
        .detect(std::iter::empty::<&str>(), DetectionLimits::default())
        .unwrap();
    let supabase = detect_supabase(std::iter::empty::<&str>(), DetectionLimits::default()).unwrap();
    let packs = SecurityPackRegistry::new();
    let languages = LanguageEcosystemDetection {
        languages: Vec::new(),
        package_ecosystems: Vec::new(),
    };
    let configs = CiMcpConfigDetection {
        ci_systems: Vec::new(),
        mcp_configurations: Vec::new(),
    };

    assert!(
        build_project_profile_snapshot(
            " ",
            "sha256:root",
            &languages,
            &configs,
            &stacks,
            &supabase,
            &packs,
            "2026-08-29T00:00:00Z",
            "2026-08-29T00:00:00Z",
        )
        .is_err()
    );
    assert!(
        build_project_profile_snapshot(
            "repo:fixture",
            " ",
            &languages,
            &configs,
            &stacks,
            &supabase,
            &packs,
            "2026-08-29T00:00:00Z",
            "2026-08-29T00:00:00Z",
        )
        .is_err()
    );
}
