#![forbid(unsafe_code)]

use sentrdel_review::business_logic::model::InvariantEvaluationState;
use sentrdel_review::regression::model::{
    FROZEN_INVARIANT_TRANSITIONS, ProducerContractIdentity, RegressionLimits, RevisionIdentity,
    RevisionPair, RevisionRole, SecurityDeltaDisposition, SemanticSnapshotContract,
    SnapshotCompatibility,
};
use sentrdel_review::regression::{
    S1_DIRECT_FINDING_CREATION_ALLOWED, S1_FACT_VERIFIED_MINTING_ALLOWED,
    S1_FORGE_DISCOVERY_ALLOWED, S1_GRAPH_OR_MODEL_AUTHORITY_ALLOWED, S1_KERNEL_OVERRIDE_ALLOWED,
    S1_LLM_OR_EXTERNAL_ENGINE_ALLOWED, S1_MISSING_OUTPUT_CAN_BECOME_PASS,
    S1_NETWORK_ACCESS_ALLOWED, S1_POLICY_OVERRIDE_ALLOWED, S1_PROVIDER_CREDENTIALS_ALLOWED,
    S1_RECONCILER_OVERRIDE_ALLOWED, S1_TARGET_EXECUTION_ALLOWED,
};

const FIXTURE_PAIRS: &[u8] =
    include_bytes!("../../../fixtures/repos/s1-security-regression/pairs.json");
const AUTHORITY_CANARIES: &[u8] =
    include_bytes!("../../../fixtures/repos/s1-security-regression/authority-canaries.json");
const FIXTURE_MATRIX: &str =
    include_str!("../../../fixtures/repos/s1-security-regression/README.md");
const DEVELOPMENT_CORPUS: &[u8] = include_bytes!(
    "../../../tests/benchmark/development-evaluation/s1-phase1-development-corpus.json"
);
const HOLDOUT_ELIGIBILITY: &[u8] = include_bytes!(
    "../../../tests/benchmark/development-evaluation/s1-phase1-holdout-eligibility.json"
);

const S1_PAIR_IDS: &[&str] = &[
    "s1-identical-clean-replay",
    "s1-safe-semantic-change",
    "s1-satisfied-to-violated",
    "s1-violated-to-satisfied",
    "s1-satisfied-to-unknown-coverage-loss",
    "s1-violated-to-unknown-never-improvement",
    "s1-unknown-to-satisfied-coverage-gain",
    "s1-unknown-to-violated-coverage-gain",
    "s1-producer-disappearance",
    "s1-move-only-continuity",
    "s1-ambiguous-rename-unmatched",
    "s1-added-object-complete-base-coverage",
    "s1-added-object-incomplete-base-coverage",
    "s1-removed-object-complete-candidate-coverage",
    "s1-removed-object-incomplete-candidate-coverage",
    "s1-project-invariant-removal",
    "s1-invariant-definition-conflict",
    "s1-graph-metadata-only-change",
    "s1-hostile-metadata-authority-canary",
    "s1-resource-cap-exhaustion",
];

fn producer(version: &str) -> ProducerContractIdentity {
    ProducerContractIdentity::new(
        "sentrdel.r3.business-logic",
        version,
        "config:fixture",
        "BUSINESS_LOGIC",
        "1",
        RegressionLimits::default(),
    )
    .expect("producer contract")
}

#[test]
fn s1_fixture_pair_contract_is_ordered_deterministic_and_compatibility_bounded() {
    let base = RevisionIdentity::fixture(
        RevisionRole::TrustedBase,
        "phase1-base",
        "digest:phase1-base",
        RegressionLimits::default(),
    )
    .expect("fixture base");
    let candidate = RevisionIdentity::fixture(
        RevisionRole::Candidate,
        "phase1-candidate",
        "digest:phase1-candidate",
        RegressionLimits::default(),
    )
    .expect("fixture candidate");
    let pair = RevisionPair::new(base.clone(), candidate.clone()).expect("pair");
    let replay = RevisionPair::new(base.clone(), candidate.clone()).expect("pair replay");
    assert_eq!(pair.pair_id(), replay.pair_id());
    assert!(pair.trusted_base().is_fixture_only());
    assert!(pair.candidate().is_fixture_only());

    let reversed = RevisionPair::new(
        RevisionIdentity::fixture(
            RevisionRole::TrustedBase,
            "phase1-candidate",
            "digest:phase1-candidate",
            RegressionLimits::default(),
        )
        .expect("reversed base"),
        RevisionIdentity::fixture(
            RevisionRole::Candidate,
            "phase1-base",
            "digest:phase1-base",
            RegressionLimits::default(),
        )
        .expect("reversed candidate"),
    )
    .expect("reversed pair");
    assert_ne!(pair.pair_id(), reversed.pair_id());

    let base_snapshot = SemanticSnapshotContract::new(
        base,
        "schema-v1",
        vec![producer("1")],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    )
    .expect("base snapshot");
    let candidate_snapshot = SemanticSnapshotContract::new(
        candidate,
        "schema-v1",
        vec![producer("1")],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    )
    .expect("candidate snapshot");
    assert_eq!(
        base_snapshot.compatibility_with(&candidate_snapshot),
        SnapshotCompatibility::Compatible
    );

    let incompatible = SemanticSnapshotContract::new(
        RevisionIdentity::fixture(
            RevisionRole::Candidate,
            "phase1-candidate-v2",
            "digest:phase1-candidate-v2",
            RegressionLimits::default(),
        )
        .expect("incompatible candidate"),
        "schema-v1",
        vec![producer("2")],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    )
    .expect("incompatible snapshot");
    assert_eq!(
        base_snapshot.compatibility_with(&incompatible),
        SnapshotCompatibility::ProducerContractMismatch
    );
}

#[test]
fn s1_frozen_transition_matrix_keeps_regression_and_uncertainty_distinct() {
    let regression = FROZEN_INVARIANT_TRANSITIONS
        .iter()
        .find(|rule| {
            rule.base == InvariantEvaluationState::Satisfied
                && rule.candidate == InvariantEvaluationState::Violated
        })
        .expect("regression transition");
    assert_eq!(
        regression.allowed_dispositions,
        &[SecurityDeltaDisposition::Regression]
    );

    let violated_to_unknown = FROZEN_INVARIANT_TRANSITIONS
        .iter()
        .find(|rule| {
            rule.base == InvariantEvaluationState::Violated
                && rule.candidate == InvariantEvaluationState::Unknown
        })
        .expect("violated to unknown");
    assert!(
        violated_to_unknown
            .allowed_dispositions
            .contains(&SecurityDeltaDisposition::CoverageLost)
    );
    assert!(
        violated_to_unknown
            .allowed_dispositions
            .contains(&SecurityDeltaDisposition::Unknown)
    );
    assert!(
        !violated_to_unknown
            .allowed_dispositions
            .contains(&SecurityDeltaDisposition::Improvement)
    );
}

#[test]
fn s1_fixture_pairs_and_development_metadata_freeze_the_same_ground_truth() {
    let fixtures: serde_json::Value =
        serde_json::from_slice(FIXTURE_PAIRS).expect("valid fixture pairs");
    let corpus: serde_json::Value =
        serde_json::from_slice(DEVELOPMENT_CORPUS).expect("valid development corpus");

    assert_eq!(fixtures["schema"], "sentrdel-s1-fixture-pairs/v1");
    assert_eq!(fixtures["fixture_only"], true);
    assert_eq!(fixtures["network_allowed"], false);
    assert_eq!(fixtures["forge_discovery_allowed"], false);
    assert_eq!(fixtures["provider_credentials_allowed"], false);
    assert_eq!(fixtures["target_execution_allowed"], false);
    assert_eq!(fixtures["external_model_authority_allowed"], false);

    assert_eq!(corpus["corpus_class"], "DEVELOPMENT_EVALUATION");
    assert_eq!(corpus["release_gating"], false);
    assert_eq!(corpus["pair_ground_truth_frozen"], true);
    assert_eq!(
        corpus["comparison_implementation_status"],
        "GROUND_TRUTH_ONLY_NOT_IMPLEMENTED"
    );

    let fixture_ids = fixtures["pairs"]
        .as_array()
        .expect("fixture pairs")
        .iter()
        .map(|pair| pair["pair_id"].as_str().expect("fixture pair id"))
        .collect::<std::collections::BTreeSet<_>>();
    let corpus_ids = corpus["cases"]
        .as_array()
        .expect("development cases")
        .iter()
        .map(|case| case["fixture_pair_id"].as_str().expect("fixture pair id"))
        .collect::<std::collections::BTreeSet<_>>();
    let expected_ids = S1_PAIR_IDS
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(fixture_ids, expected_ids);
    assert_eq!(corpus_ids, expected_ids);
    assert_eq!(fixture_ids.len(), 20);

    for case in corpus["cases"].as_array().expect("development cases") {
        assert_eq!(case["expected_findings"], serde_json::json!([]));
        assert_eq!(case["emitted_findings"], serde_json::json!([]));
        assert_eq!(case["expected_comparison_records"], 1);
        assert!(case["observed_comparison_records"].is_null());
        let assertions = case["authority_assertions"]
            .as_array()
            .expect("authority assertions");
        assert!(
            assertions
                .iter()
                .any(|entry| entry == "comparison-record-is-not-a-finding")
        );
        assert!(
            assertions
                .iter()
                .any(|entry| entry == "missing-output-is-not-pass")
        );
    }

    let clean_cases = corpus["cases"]
        .as_array()
        .expect("development cases")
        .iter()
        .filter(|case| case["clean_case"] == true)
        .collect::<Vec<_>>();
    assert!(!clean_cases.is_empty());
    assert!(
        clean_cases
            .iter()
            .all(|case| case["expected_false_positive"] == false)
    );

    let known_regressions = corpus["cases"]
        .as_array()
        .expect("development cases")
        .iter()
        .filter(|case| case["known_regression_ground_truth"] == true)
        .collect::<Vec<_>>();
    assert!(!known_regressions.is_empty());
    assert!(
        known_regressions
            .iter()
            .all(|case| case["expected_known_miss_after_supported_implementation"] == false)
    );

    assert!(FIXTURE_MATRIX.contains("SENTRDEL_CANARY"));
    assert!(FIXTURE_MATRIX.contains("never a canonical Finding"));
    assert!(FIXTURE_MATRIX.contains("`REINTRODUCED`"));
}

#[test]
fn s1_holdout_metadata_tracks_every_frozen_pair_but_is_not_yet_eligible() {
    let corpus: serde_json::Value =
        serde_json::from_slice(DEVELOPMENT_CORPUS).expect("valid development corpus");
    let holdout: serde_json::Value =
        serde_json::from_slice(HOLDOUT_ELIGIBILITY).expect("valid holdout metadata");

    assert_eq!(holdout["corpus_revision"], corpus["corpus_revision"]);
    assert_eq!(holdout["release_gating"], false);
    assert_eq!(
        holdout["protected_holdout_status"],
        "NOT_ELIGIBLE_PRE_RELEASE_GATING"
    );

    let holdout_ids = holdout["case_ids"]
        .as_array()
        .expect("holdout ids")
        .iter()
        .map(|value| value.as_str().expect("case id"))
        .collect::<std::collections::BTreeSet<_>>();
    let expected_ids = S1_PAIR_IDS
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(holdout_ids, expected_ids);
}

#[test]
fn s1_authority_canaries_and_code_constants_deny_privilege_widening() {
    const { assert!(!S1_DIRECT_FINDING_CREATION_ALLOWED) };
    const { assert!(!S1_FACT_VERIFIED_MINTING_ALLOWED) };
    const { assert!(!S1_POLICY_OVERRIDE_ALLOWED) };
    const { assert!(!S1_KERNEL_OVERRIDE_ALLOWED) };
    const { assert!(!S1_RECONCILER_OVERRIDE_ALLOWED) };
    const { assert!(!S1_GRAPH_OR_MODEL_AUTHORITY_ALLOWED) };
    const { assert!(!S1_NETWORK_ACCESS_ALLOWED) };
    const { assert!(!S1_FORGE_DISCOVERY_ALLOWED) };
    const { assert!(!S1_PROVIDER_CREDENTIALS_ALLOWED) };
    const { assert!(!S1_TARGET_EXECUTION_ALLOWED) };
    const { assert!(!S1_LLM_OR_EXTERNAL_ENGINE_ALLOWED) };
    const { assert!(!S1_MISSING_OUTPUT_CAN_BECOME_PASS) };

    let authority: serde_json::Value =
        serde_json::from_slice(AUTHORITY_CANARIES).expect("valid authority canaries");
    let forbidden = authority["forbidden_authority"]
        .as_object()
        .expect("forbidden authority object");
    assert!(forbidden.values().all(|value| value == false));

    let canaries = authority["canaries"].as_array().expect("canaries");
    assert!(canaries.iter().any(|entry| {
        entry["canary_id"] == "instruction-shaped-metadata"
            && entry["untrusted_value"]
                .as_str()
                .is_some_and(|value| value.contains("SENTRDEL_CANARY"))
            && entry["expected_behavior"] == "INERT_UNTRUSTED_DATA"
    }));
    assert!(canaries.iter().any(|entry| {
        entry["canary_id"] == "missing-output"
            && entry["expected_behavior"] == "UNKNOWN_OR_COVERAGE_GAP_NEVER_PASS"
    }));
}
