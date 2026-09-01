#![forbid(unsafe_code)]

use sentrdel_review::business_logic;
use sentrdel_review::business_logic::invariant::{
    ProjectInvariantContractError, ProjectInvariantLimits, validate_project_invariant_id,
    validate_project_invariant_keys,
};
use sentrdel_review::pack_registry::{PackOutputKind, SecurityPackRegistry, ValidatedPackManifest};

const DEVELOPMENT_CORPUS: &[u8] =
    include_bytes!("../../../tests/benchmark/development-evaluation/t090-development-corpus.json");
const HOLDOUT_ELIGIBILITY: &[u8] = include_bytes!(
    "../../../tests/benchmark/development-evaluation/r3-phase1-holdout-eligibility.json"
);
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

const R3_FIXTURE_CATEGORIES: &[&str] = &[
    "express/safe-tenant",
    "express/unsafe-tenant",
    "next-app/safe-role",
    "next-pages/unknown-dynamic-guard",
    "supabase-edge/safe-owner",
    "supabase-edge/unsafe-elevated",
    "supabase-data/safe-properties",
    "supabase-data/unsafe-properties",
    "adversarial/malformed-source",
    "adversarial/dynamic-unsupported",
    "adversarial/unsupported-framework",
    "adversarial/hostile-repository",
    "project-invariants/safe-tightening",
    "project-invariants/forbidden-suppression",
    "project-invariants/forbidden-authority",
    "project-invariants/builtin-impersonation",
];

#[test]
fn r3_pack_registers_with_evidence_coverage_only_authority() {
    let mut registry = SecurityPackRegistry::new();
    let registered = business_logic::register_r3_pack(&mut registry).expect("register R3 pack");
    assert_eq!(
        registered.pack_id(),
        business_logic::R3_BUSINESS_LOGIC_PACK_ID
    );
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
fn phase1_development_corpus_binds_every_declared_fixture_to_ground_truth() {
    let value: serde_json::Value =
        serde_json::from_slice(DEVELOPMENT_CORPUS).expect("valid corpus");
    assert_eq!(value["corpus_class"], "DEVELOPMENT_EVALUATION");
    assert_eq!(value["release_gating"], false);

    let cases = value["cases"].as_array().expect("cases array");
    let r3_cases = cases
        .iter()
        .filter(|case| {
            case["case_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("r3-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(r3_cases.len(), R3_FIXTURE_CATEGORIES.len());

    for category in R3_FIXTURE_CATEGORIES {
        assert!(FIXTURE_MATRIX.contains(category), "missing fixture matrix entry {category}");
        let expected_root = format!("fixtures/repos/r3-business-logic/{category}");
        let case = r3_cases
            .iter()
            .find(|case| case["fixture_root"] == expected_root)
            .unwrap_or_else(|| panic!("fixture category {category} is not bound to a development case"));
        assert_eq!(case["expected_findings"], serde_json::json!([]));
        assert_eq!(case["emitted_findings"], serde_json::json!([]));
        assert!(case["expected_coverage"].is_array());
        assert!(case["expected_coverage_gaps"].is_array());
        let assertions = case["authority_assertions"]
            .as_array()
            .expect("authority assertions");
        assert!(assertions.iter().any(|entry| {
            entry == "no-target-execution"
                || entry == "no-network-or-target-execution"
                || entry == "r3-output-is-evidence-or-coverage-only"
                || entry == "no-provider-access"
        }));
    }

    assert!(FIXTURE_MATRIX.contains("SENTRDEL_CANARY"));
    assert!(FIXTURE_MATRIX.contains("never grant authority"));
}

#[test]
fn phase1_holdout_metadata_tracks_the_complete_r3_case_set_but_is_not_eligible() {
    let corpus: serde_json::Value =
        serde_json::from_slice(DEVELOPMENT_CORPUS).expect("valid development corpus");
    let holdout: serde_json::Value =
        serde_json::from_slice(HOLDOUT_ELIGIBILITY).expect("valid holdout eligibility metadata");

    assert_eq!(holdout["corpus_revision"], corpus["corpus_revision"]);
    assert_eq!(holdout["release_gating"], false);
    assert_eq!(
        holdout["protected_holdout_status"],
        "NOT_ELIGIBLE_PRE_RELEASE_GATING"
    );

    let holdout_ids = holdout["case_ids"]
        .as_array()
        .expect("holdout case ids")
        .iter()
        .map(|value| value.as_str().expect("case id"))
        .collect::<std::collections::BTreeSet<_>>();
    let corpus_ids = corpus["cases"]
        .as_array()
        .expect("corpus cases")
        .iter()
        .filter_map(|case| case["case_id"].as_str())
        .filter(|id| id.starts_with("r3-"))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(holdout_ids, corpus_ids);
    assert_eq!(holdout_ids.len(), R3_FIXTURE_CATEGORIES.len());
}

#[test]
fn project_invariant_fixtures_encode_tightening_and_adversarial_contracts() {
    assert!(SAFE_INVARIANT.contains("accounts-tenant-binding"));
    validate_project_invariant_id("accounts-tenant-binding", ProjectInvariantLimits::default())
        .expect("safe id");
    validate_project_invariant_keys(
        &[
            "id",
            "type",
            "resource",
            "route",
            "methods",
            "tenant_field",
            "actor",
        ],
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
