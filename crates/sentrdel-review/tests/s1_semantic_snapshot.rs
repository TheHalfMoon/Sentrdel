#![forbid(unsafe_code)]

use sentrdel_review::business_logic::coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS;
use sentrdel_review::business_logic::graph::{R3GraphLimits, map_validated_observations};
use sentrdel_review::business_logic::model::{
    BusinessLogicCoverage, BusinessLogicLimits, InvariantDefinition, InvariantEvaluation,
    InvariantEvaluationState, InvariantKind, InvariantRequirement, InvariantScope, InvariantSource,
    SourceLocation, StableSemanticId,
};
use sentrdel_review::business_logic::producer::{
    BusinessLogicProducerOutput, R3_BUSINESS_LOGIC_PRODUCER_ID, R3_BUSINESS_LOGIC_PRODUCER_VERSION,
    produce_business_logic_outputs,
};
use sentrdel_review::regression::model::{
    ProducerContractIdentity, RegressionLimits, RevisionIdentity, RevisionPair, RevisionRole,
    SemanticSnapshotContract, SnapshotCompatibility,
};
use sentrdel_review::regression::snapshot::{
    SemanticSnapshot, SnapshotCompositionError, validate_snapshot_pair,
};
use sentrdel_review::view::NormalizedRepoPath;
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::coverage::CoverageState;

fn source(path: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse(path, 4_096).expect("normalized path"),
        start,
        start + 8,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("source location")
}

fn stable_id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
        .expect("stable semantic id")
}

fn invariant(name: &str) -> InvariantDefinition {
    InvariantDefinition::new(
        stable_id("s1.t008.invariant", name),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        InvariantScope::new(
            None,
            Vec::new(),
            None,
            Vec::new(),
            Vec::new(),
            BusinessLogicLimits::default(),
        )
        .expect("invariant scope"),
        InvariantRequirement::RequiredRole {
            required_roles: vec!["admin".to_owned()],
        },
        vec![source(&format!("src/{name}.ts"), 0)],
        BusinessLogicLimits::default(),
    )
    .expect("invariant definition")
}

fn evaluation(name: &str, invariant: &InvariantDefinition) -> InvariantEvaluation {
    InvariantEvaluation::new(
        stable_id("s1.t008.evaluation", name),
        invariant.invariant_id().clone(),
        None,
        InvariantEvaluationState::Satisfied,
        vec![stable_id("s1.t008.observation", name)],
        Vec::new(),
        vec!["R3_T008_FIXTURE_COVERED".to_owned()],
        vec![source(&format!("src/{name}.ts"), 16)],
        BusinessLogicLimits::default(),
    )
    .expect("invariant evaluation")
}

fn coverage_matrix() -> Vec<BusinessLogicCoverage> {
    REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
        .into_iter()
        .map(|area| {
            BusinessLogicCoverage::new(
                area,
                CoverageState::Covered,
                "R3_T008_FIXTURE_COVERED",
                ".",
                vec!["sha256:s1-t008-input".to_owned()],
                R3_BUSINESS_LOGIC_PRODUCER_ID,
                BusinessLogicLimits::default(),
            )
            .expect("business logic coverage")
        })
        .collect()
}

fn producer_output(evaluations: &[InvariantEvaluation]) -> BusinessLogicProducerOutput {
    produce_business_logic_outputs(evaluations, &coverage_matrix(), "2026-09-08T00:00:00Z")
        .expect("canonical R3 producer output")
}

fn contract(
    revision: RevisionIdentity,
    producer_version: &str,
    limits: RegressionLimits,
) -> SemanticSnapshotContract {
    SemanticSnapshotContract::new(
        revision,
        "schema-v1",
        vec![
            ProducerContractIdentity::new(
                R3_BUSINESS_LOGIC_PRODUCER_ID,
                producer_version,
                "sha256:s1-t008-config",
                "BUSINESS_LOGIC",
                SCHEMA_V1,
                limits,
            )
            .expect("producer contract"),
        ],
        vec!["profile:default".to_owned()],
        limits,
    )
    .expect("snapshot contract")
}

fn snapshot(
    revision: RevisionIdentity,
    producer_version: &str,
    mut definitions: Vec<InvariantDefinition>,
    mut evaluations: Vec<InvariantEvaluation>,
    limits: RegressionLimits,
) -> Result<SemanticSnapshot, SnapshotCompositionError> {
    let output = producer_output(&evaluations);
    let graph = map_validated_observations(&[], &[], &definitions, R3GraphLimits::default())
        .expect("canonical R3 graph records");
    SemanticSnapshot::compose(
        contract(revision, producer_version, limits),
        std::mem::take(&mut definitions),
        std::mem::take(&mut evaluations),
        output,
        graph,
        limits,
    )
}

fn fixture_revision(role: RevisionRole, label: &str) -> RevisionIdentity {
    RevisionIdentity::fixture(
        role,
        format!("s1-t008-{label}"),
        format!("sha256:s1-t008-{label}-snapshot"),
        RegressionLimits::default(),
    )
    .expect("fixture revision")
}

#[test]
fn semantic_snapshot_composition_is_bounded_normalized_and_preserves_canonical_inputs() {
    let first = invariant("zeta");
    let second = invariant("alpha");
    let first_eval = evaluation("zeta", &first);
    let second_eval = evaluation("alpha", &second);
    let revision = fixture_revision(RevisionRole::TrustedBase, "base");

    let composed = snapshot(
        revision.clone(),
        R3_BUSINESS_LOGIC_PRODUCER_VERSION,
        vec![first.clone(), second.clone()],
        vec![first_eval.clone(), second_eval.clone()],
        RegressionLimits::default(),
    )
    .expect("semantic snapshot");
    let replay = snapshot(
        revision,
        R3_BUSINESS_LOGIC_PRODUCER_VERSION,
        vec![second, first],
        vec![second_eval, first_eval],
        RegressionLimits::default(),
    )
    .expect("semantic snapshot replay");

    assert_eq!(composed, replay);
    assert!(
        composed
            .invariant_definitions()
            .windows(2)
            .all(|pair| pair[0].invariant_id() < pair[1].invariant_id())
    );
    assert!(
        composed
            .invariant_evaluations()
            .windows(2)
            .all(|pair| pair[0].evaluation_id() < pair[1].evaluation_id())
    );
    assert!(
        composed
            .coverage_records()
            .windows(2)
            .all(|pair| pair[0].coverage_id < pair[1].coverage_id)
    );
    assert!(
        composed
            .evidence_refs()
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert_eq!(composed.coverage_records().len(), 12);
    assert_eq!(composed.evidence_refs().len(), 4);
    assert!(!composed.graph_nodes().is_empty());
    assert!(composed.input_bytes() > 0);
}

#[test]
fn snapshot_pair_validation_binds_exact_revision_pair_and_contract_compatibility() {
    let definition = invariant("role");
    let evaluation = evaluation("role", &definition);
    let base_revision = fixture_revision(RevisionRole::TrustedBase, "base-pair");
    let candidate_revision = fixture_revision(RevisionRole::Candidate, "candidate-pair");
    let pair = RevisionPair::new(base_revision.clone(), candidate_revision.clone()).expect("pair");

    let base = snapshot(
        base_revision,
        R3_BUSINESS_LOGIC_PRODUCER_VERSION,
        vec![definition.clone()],
        vec![evaluation.clone()],
        RegressionLimits::default(),
    )
    .expect("base snapshot");
    let candidate = snapshot(
        candidate_revision.clone(),
        R3_BUSINESS_LOGIC_PRODUCER_VERSION,
        vec![definition.clone()],
        vec![evaluation.clone()],
        RegressionLimits::default(),
    )
    .expect("candidate snapshot");
    validate_snapshot_pair(&pair, &base, &candidate).expect("compatible exact pair");

    let incompatible = snapshot(
        candidate_revision,
        "2",
        vec![definition.clone()],
        vec![evaluation.clone()],
        RegressionLimits::default(),
    )
    .expect("incompatible candidate snapshot");
    assert!(matches!(
        validate_snapshot_pair(&pair, &base, &incompatible),
        Err(SnapshotCompositionError::IncompatibleSnapshots(
            SnapshotCompatibility::ProducerContractMismatch
        ))
    ));

    let wrong_base = snapshot(
        fixture_revision(RevisionRole::TrustedBase, "wrong-base"),
        R3_BUSINESS_LOGIC_PRODUCER_VERSION,
        vec![definition],
        vec![evaluation],
        RegressionLimits::default(),
    )
    .expect("wrong base snapshot");
    assert!(matches!(
        validate_snapshot_pair(&pair, &wrong_base, &candidate),
        Err(SnapshotCompositionError::RevisionPairMismatch {
            side: "TRUSTED_BASE"
        })
    ));
}

#[test]
fn malformed_references_and_resource_caps_fail_visible_before_comparison() {
    let first = invariant("one");
    let second = invariant("two");
    let first_eval = evaluation("one", &first);
    let second_eval = evaluation("two", &second);
    let revision = fixture_revision(RevisionRole::TrustedBase, "bounded");

    let invariant_cap = RegressionLimits {
        max_snapshot_invariants: 1,
        ..RegressionLimits::default()
    };
    assert!(matches!(
        snapshot(
            revision.clone(),
            R3_BUSINESS_LOGIC_PRODUCER_VERSION,
            vec![first.clone(), second.clone()],
            vec![first_eval.clone(), second_eval],
            invariant_cap,
        ),
        Err(SnapshotCompositionError::TooManyCollectionItems {
            field: "invariant_definitions",
            ..
        })
    ));

    let orphan = evaluation("orphan", &second);
    assert!(matches!(
        snapshot(
            revision.clone(),
            R3_BUSINESS_LOGIC_PRODUCER_VERSION,
            vec![first.clone()],
            vec![orphan],
            RegressionLimits::default(),
        ),
        Err(SnapshotCompositionError::UnknownInvariantReference { .. })
    ));

    let duplicate = first.clone();
    assert!(matches!(
        snapshot(
            revision.clone(),
            R3_BUSINESS_LOGIC_PRODUCER_VERSION,
            vec![first.clone(), duplicate],
            vec![first_eval.clone()],
            RegressionLimits::default(),
        ),
        Err(SnapshotCompositionError::DuplicateInvariantId(_))
    ));

    let tiny_bytes = RegressionLimits {
        max_total_input_bytes: 32,
        ..RegressionLimits::default()
    };
    assert!(matches!(
        snapshot(
            revision,
            R3_BUSINESS_LOGIC_PRODUCER_VERSION,
            vec![first],
            vec![first_eval],
            tiny_bytes,
        ),
        Err(SnapshotCompositionError::TotalInputBytesExceeded { max: 32 })
    ));
}
