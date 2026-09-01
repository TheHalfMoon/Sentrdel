#![forbid(unsafe_code)]

use sentrdel_review::business_logic;
use sentrdel_review::business_logic::invariant::{
    ProjectInvariantContractError, ProjectInvariantLimits, validate_project_invariant_id,
    validate_project_invariant_keys,
};
use sentrdel_review::pack_registry::{PackOutputKind, SecurityPackRegistry, ValidatedPackManifest};

const DEVELOPMENT_CORPUS: &[u8] =
    include_bytes!("../../../tests/benchmark/development-evaluation/t090-development-corpus.json");
const FIXTURE_MATRIX: &str = include_str!("../../../fixtures/repos/r3-business-logic/README.md");
const SAFE_INVARIANT: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/project-invariants/safe-tightening/.sentrdel/invariants.toml"
);
const FORBIDDEN_SUPPRESSION: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/project-invariants/forbidden-suppression/.sentrdel/invariants.toml"
);
const FORBIDDEN_AUTHORITY: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/project-invariants/forbidden-authority/.sentrdel/invariants.toml"
);
const BUILTIN_IMPERSONATION: &str = include_str!(
    "../../../fixtures/repos/r3-business-logic/project-invariants/builtin-impersonation/.sentrdel/invariants.toml"
);

#[test]
fn r3_pack_registers_with_evidence_coverage_only_authority() {
    let mut registry = SecurityPackRegistry::new();
    let registered = business_logic::register_r3_pack(&mut registry).expect("register R3 pack");
    assert_eq!(registered.pack_id(), business_logic::R3_BUSINESS_LOGIC_PACK_ID);
    assert_eq!(
        ValidatedPackManifest::output_kinds(),
        [PackOutputKind::Evidence, PackOutputKind::Coverage]
    );
    assert!(registered.manifest().required_engines.is_empty());
    assert!(registered.manifest().required_features.is_empty());
    assert!(!registered.manifest().declares_capability("finding"));
    assert!(!registered.manifest().declares_capability("policy-override"));
}

#[test]
fn phase1_development_corpus_freezes_r3_ground_truth_without_release_gating() {
    let value: serde_json::Value = serde_json::from_slice(DEVELOPMENT_CORPUS).expect("valid corpus");
    assert_eq!(value["corpus_class"], "DEVELOPMENT_EVALUATION");
    assert_eq!(value["release_gating"], false);

    let cases = value["cases"].as_array().expect("cases array");
    for expected in [
        "r3-express-safe-tenant-ground-truth",
        "r3-next-safe-role-ground-truth",
        "r3-edge-unsafe-elevated-ground-truth",
        "r3-adversarial-unknown-ground-truth",
    ] {
        assert!(
            cases.iter().any(|case| case["case_id"] == expected),
            "missing R3 ground-truth case {expected}"
        );
    }

    for case in cases.iter().filter(|case| {
        case["case_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("r3-"))
    }) {
        assert_eq!(case["expected_findings"], serde_json::json!([]));
        assert_eq!(case["emitted_findings"], serde_json::json!([]));
        let assertions = case["authority_assertions"]
            .as_array()
            .expect("authority assertions");
        assert!(assertions.iter().any(|value| {
            value == "no-target-execution"
                || value == "r3-output-is-evidence-or-coverage-only"
        }));
    }
}

#[test]
fn fixture_matrix_covers_safe_unsafe_unknown_and_hostile_authority_cases() {
    for required in [
        "express/safe-tenant",
        "express/unsafe-tenant",
        "next-app/safe-role",
        "next-pages/unknown-dynamic-guard",
        "supabase-edge/safe-owner",
        "supabase-edge/unsafe-elevated",
        "supabase-data/safe-properties",
        "supabase-data/unsafe-properties",
        "adversarial/dynamic-unsupported",
        "adversarial/unsupported-framework",
        "adversarial/hostile-repository",
    ] {
        assert!(FIXTURE_MATRIX.contains(required), "missing fixture matrix entry {required}");
    }
    assert!(FIXTURE_MATRIX.contains("SENTRDEL_CANARY"));
    assert!(FIXTURE_MATRIX.contains("never grant authority"));
}

#[test]
fn project_invariant_fixtures_encode_tightening_and_adversarial_contracts() {
    assert!(SAFE_INVARIANT.contains("accounts-tenant-binding"));
    validate_project_invariant_id("accounts-tenant-binding", ProjectInvariantLimits::default())
        .expect("safe id");
    validate_project_invariant_keys(
        &["id", "type", "resource", "route", "methods", "tenant_field", "actor"],
        ProjectInvariantLimits::default(),
    )
    .expect("safe keys");

    assert!(FORBIDDEN_SUPPRESSION.contains("suppress = true"));
    assert!(matches!(
        validate_project_invariant_keys(
            &["id", "type", "resource", "suppress"],
            ProjectInvariantLimits::default()
        ),
        Err(ProjectInvariantContractError::ForbiddenAuthorityKey(value)) if value == "suppress"
    ));

    assert!(FORBIDDEN_AUTHORITY.contains("provider_credentials"));
    assert!(FORBIDDEN_AUTHORITY.contains("command"));
    assert!(matches!(
        validate_project_invariant_keys(
            &["id", "type", "provider_credentials"],
            ProjectInvariantLimits::default()
        ),
        Err(ProjectInvariantContractError::ForbiddenAuthorityKey(value)) if value == "provider_credentials"
    ));

    assert!(BUILTIN_IMPERSONATION.contains("sentrdel.builtin.tenant-binding"));
    assert!(
        validate_project_invariant_id(
            "sentrdel.builtin.tenant-binding",
            ProjectInvariantLimits::default()
        )
        .is_err()
    );
}
