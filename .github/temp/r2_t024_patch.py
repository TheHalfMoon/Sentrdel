from pathlib import Path


def replace(path: str, old: str, new: str, count: int = 1) -> None:
    file = Path(path)
    text = file.read_text()
    actual = text.count(old)
    if actual != count:
        raise SystemExit(f"{path}: expected {count} matches, got {actual}: {old!r}")
    file.write_text(text.replace(old, new, count))


replace(
    "crates/sentrdel-review/src/supabase.rs",
    'pub const SUPABASE_R2_MANIFEST_COVERAGE_DIMENSIONS: &[&str] = &[\n    COVERAGE_DETECTION,\n    "STATIC_POSTURE",\n    COVERAGE_LIVE_POSTURE,\n    COVERAGE_BUSINESS_LOGIC,\n    COVERAGE_RUNTIME,\n];',
    'pub const SUPABASE_R2_MANIFEST_COVERAGE_DIMENSIONS: &[&str] = &[\n    COVERAGE_DETECTION,\n    "STATIC_POSTURE",\n];',
)
replace(
    "crates/sentrdel-review/src/profile.rs",
    "use crate::supabase::SUPABASE_R2_PACK_ID;",
    "use crate::supabase::{SUPABASE_R2_PACK_ID, manifest as supabase_r2_manifest};",
)
replace(
    "crates/sentrdel-review/src/profile.rs",
    "        let pack_status = if packs.get(SUPABASE_R2_PACK_ID).is_some() {",
    "        let pack_status = if native_supabase_r2_pack_registered(packs) {",
)
replace(
    "crates/sentrdel-review/src/profile.rs",
    "    let supabase_r2_registered = packs.get(SUPABASE_R2_PACK_ID).is_some();",
    "    let supabase_r2_registered = native_supabase_r2_pack_registered(packs);",
)
profile = Path("crates/sentrdel-review/src/profile.rs")
text = profile.read_text()
marker = "fn build_project_coverage_matrix(\n"
helper = """fn native_supabase_r2_pack_registered(packs: &SecurityPackRegistry) -> bool {
    packs
        .get(SUPABASE_R2_PACK_ID)
        .is_some_and(|pack| pack.manifest() == &supabase_r2_manifest())
}

"""
if helper not in text:
    if text.count(marker) != 1:
        raise SystemExit("profile helper insertion marker mismatch")
    profile.write_text(text.replace(marker, helper + marker, 1))

replace(
    "crates/sentrdel-cli/tests/t065_init_output.rs",
    '        "provider supabase / STATIC_POSTURE: Partial (SUPABASE_STATIC_POSTURE_NOT_IMPLEMENTED)",',
    '        "provider supabase / STATIC_POSTURE: Unsupported (R1_POSTURE_NOT_IMPLEMENTED)",',
)
replace(
    "crates/sentrdel-cli/tests/t065_init_output.rs",
    '''        record["capability"] == "provider.supabase.STATIC_POSTURE"
            && record["state"] == "PARTIAL"
            && record["provider_dimension"] == "STATIC_POSTURE"''',
    '''        record["capability"] == "provider.supabase.STATIC_POSTURE"
            && record["state"] == "UNSUPPORTED"
            && record["provider_dimension"] == "STATIC_POSTURE"
            && record["reason_code"] == "R1_POSTURE_NOT_IMPLEMENTED"''',
)
replace(
    "crates/sentrdel-cli/tests/t066_init_adversarial.rs",
    "fn supabase_detection_reports_partial_coverage_without_provider_security_verdict() {",
    "fn supabase_detection_without_registered_r2_pack_reports_unsupported_without_verdict() {",
)
replace(
    "crates/sentrdel-cli/tests/t066_init_adversarial.rs",
    '''    assert_eq!(supabase_static.state, CoverageState::Partial);
    assert_eq!(
        supabase_static.reason_code.as_deref(),
        Some("SUPABASE_STATIC_POSTURE_NOT_IMPLEMENTED")
    );
    assert!(output.human.contains(
        "provider supabase / STATIC_POSTURE: Partial (SUPABASE_STATIC_POSTURE_NOT_IMPLEMENTED)"
    ));''',
    '''    assert_eq!(supabase_static.state, CoverageState::Unsupported);
    assert_eq!(
        supabase_static.reason_code.as_deref(),
        Some("R1_POSTURE_NOT_IMPLEMENTED")
    );
    assert!(output.human.contains(
        "provider supabase / STATIC_POSTURE: Unsupported (R1_POSTURE_NOT_IMPLEMENTED)"
    ));''',
)

t064 = Path("crates/sentrdel-review/tests/t064_project_profile.rs")
text = t064.read_text()
marker = "#[test]\nfn profile_rejects_blank_persistence_identity_inputs() {"
test = '''#[test]
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

'''
if test not in text:
    if text.count(marker) != 1:
        raise SystemExit("t064 test insertion marker mismatch")
    t064.write_text(text.replace(marker, test + marker, 1))
