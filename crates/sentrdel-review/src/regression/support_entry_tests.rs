use crate::business_logic::coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS;
use crate::business_logic::graph::{R3GraphLimits, map_validated_observations};
use crate::business_logic::model::{
    BusinessLogicCoverage, BusinessLogicLimits, InvariantDefinition, InvariantEvaluation,
    InvariantEvaluationState, InvariantKind, InvariantRequirement, InvariantScope, InvariantSource,
    SourceLocation, StableSemanticId,
};
use crate::business_logic::producer::{
    BusinessLogicProducerOutput, R3_BUSINESS_LOGIC_PRODUCER_ID, produce_business_logic_outputs,
};
use crate::regression::model::{RegressionLimits, RevisionIdentity, RevisionPair, RevisionRole};
use crate::regression::snapshot::{SemanticSnapshot, derive_snapshot_input_digest};
use crate::regression::support::{BilateralSupportError, preserve_bilateral_support};
use crate::view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath};
use sentrdel_schema::coverage::CoverageState;

const PRODUCER_CONFIGURATION_DIGEST: &str = "sha256:s1-t011-entrypoint-config";

fn source(path: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse(path, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path"),
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
        stable_id("s1.t011.invariant", name),
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
        stable_id("s1.t011.evaluation", name),
        invariant.invariant_id().clone(),
        None,
        InvariantEvaluationState::Satisfied,
        vec![stable_id("s1.t011.observation", name)],
        Vec::new(),
        vec!["R3_T011_FIXTURE_COVERED".to_owned()],
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
                "R3_T011_FIXTURE_COVERED",
                ".",
                vec!["sha256:s1-t011-input".to_owned()],
                R3_BUSINESS_LOGIC_PRODUCER_ID,
                BusinessLogicLimits::default(),
            )
            .expect("business logic coverage")
        })
        .collect()
}

fn producer_output(evaluations: &[InvariantEvaluation]) -> BusinessLogicProducerOutput {
    produce_business_logic_outputs(evaluations, &coverage_matrix(), "2026-09-16T00:00:00Z")
        .expect("canonical R3 producer output")
}

fn fixture_snapshot(
    role: RevisionRole,
    fixture_identity: &str,
    semantic_name: &str,
) -> (RevisionIdentity, SemanticSnapshot) {
    let definition = invariant(semantic_name);
    let evaluation = evaluation(semantic_name, &definition);
    let output = producer_output(std::slice::from_ref(&evaluation));
    let graph = map_validated_observations(
        &[],
        &[],
        std::slice::from_ref(&definition),
        R3GraphLimits::default(),
    )
    .expect("canonical R3 graph records");
    let limits = RegressionLimits::default();
    let snapshot_input_digest = derive_snapshot_input_digest(
        vec![definition.clone()],
        vec![evaluation.clone()],
        &output,
        &graph,
        limits,
    )
    .expect("canonical snapshot input digest");
    let revision = RevisionIdentity::fixture(
        role,
        fixture_identity,
        snapshot_input_digest,
        limits,
    )
    .expect("fixture revision");
    let snapshot = SemanticSnapshot::compose(
        revision.clone(),
        PRODUCER_CONFIGURATION_DIGEST,
        vec!["profile:default".to_owned()],
        vec![definition],
        vec![evaluation],
        output,
        graph,
        limits,
    )
    .expect("semantic snapshot");
    (revision, snapshot)
}

#[test]
fn preserve_entrypoint_rejects_snapshot_revision_mismatch() {
    let (base_revision, base) =
        fixture_snapshot(RevisionRole::TrustedBase, "s1-t011-base", "base");
    let (candidate_revision, _candidate) =
        fixture_snapshot(RevisionRole::Candidate, "s1-t011-candidate", "candidate");
    let (_rogue_revision, rogue_candidate) =
        fixture_snapshot(RevisionRole::Candidate, "s1-t011-rogue", "candidate");
    let pair = RevisionPair::new(base_revision, candidate_revision).expect("revision pair");

    let error = preserve_bilateral_support(
        &pair,
        &base,
        Vec::new(),
        &[],
        &rogue_candidate,
        Vec::new(),
        &[],
        RegressionLimits::default(),
    )
    .expect_err("snapshot revision mismatch must fail closed");

    assert!(matches!(error, BilateralSupportError::Snapshot(_)));
}

#[test]
fn preserve_entrypoint_enforces_one_aggregate_byte_cap_across_both_sides() {
    let (base_revision, base) =
        fixture_snapshot(RevisionRole::TrustedBase, "s1-t011-base", "base");
    let (candidate_revision, candidate) =
        fixture_snapshot(RevisionRole::Candidate, "s1-t011-candidate", "candidate");
    let pair = RevisionPair::new(base_revision, candidate_revision).expect("revision pair");
    let base_ref = base
        .evidence_refs()
        .first()
        .expect("base fixture evidence")
        .clone();
    let candidate_ref = candidate
        .evidence_refs()
        .first()
        .expect("candidate fixture evidence")
        .clone();
    let max_total_input_bytes = base_ref
        .len()
        .checked_add(candidate_ref.len())
        .and_then(|bytes| bytes.checked_sub(1))
        .expect("non-empty fixture evidence identities");
    let limits = RegressionLimits {
        max_total_input_bytes,
        ..RegressionLimits::default()
    };

    let error = preserve_bilateral_support(
        &pair,
        &base,
        vec![base_ref],
        &[],
        &candidate,
        vec![candidate_ref],
        &[],
        limits,
    )
    .expect_err("combined bilateral input must share one aggregate byte cap");

    assert!(matches!(
        error,
        BilateralSupportError::TotalInputBytesExceeded { max }
            if max == max_total_input_bytes
    ));
}
