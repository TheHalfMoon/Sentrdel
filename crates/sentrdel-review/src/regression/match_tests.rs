use crate::business_logic::coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS;
use crate::business_logic::graph::{R3GraphLimits, map_validated_observations};
use crate::business_logic::model::{
    BusinessLogicCoverage, BusinessLogicLimits, DataOperation, DataOperationKind, HttpMethod,
    InvariantDefinition, InvariantEvaluation, InvariantEvaluationState, InvariantKind,
    InvariantRequirement, InvariantScope, InvariantSource, ResourceKind, ResourceRef,
    SourceLocation, StableSemanticId,
};
use crate::business_logic::producer::{
    R3_BUSINESS_LOGIC_PRODUCER_ID, produce_business_logic_outputs,
};
use crate::regression::invariant_match::{
    InvariantDefinitionCompatibility, InvariantMatchError, SemanticObjectKind,
    SemanticObjectMatchError, match_invariants, match_semantic_objects,
};
use crate::regression::model::{
    ContinuityBasis, PairPresence, RegressionLimits, RevisionIdentity, RevisionPair, RevisionRole,
    SnapshotCompatibility,
};
use crate::regression::snapshot::{
    SemanticSnapshot, SnapshotCompositionError, derive_invariant_definition_digest,
    derive_snapshot_input_digest,
};
use crate::view::NormalizedRepoPath;
use sentrdel_schema::coverage::CoverageState;

const PRODUCER_CONFIGURATION_DIGEST: &str = "sha256:s1-t009-config";

fn source(path: &str, start: usize) -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse(path, 4_096).expect("normalized path"),
        start,
        start + 8,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("source location")
}

fn stable_id(label: &str) -> StableSemanticId {
    StableSemanticId::from_parts(
        "s1.t009.invariant",
        &[label],
        BusinessLogicLimits::default(),
    )
    .expect("stable semantic id")
}

fn scope(route: &str, methods: Vec<HttpMethod>, target_paths: Vec<&str>) -> InvariantScope {
    InvariantScope::new(
        Some(route.to_owned()),
        methods,
        None,
        Vec::new(),
        target_paths
            .into_iter()
            .map(|path| NormalizedRepoPath::parse(path, 4_096).expect("target path"))
            .collect(),
        BusinessLogicLimits::default(),
    )
    .expect("invariant scope")
}

fn required_role(
    id: &str,
    invariant_source: InvariantSource,
    route: &str,
    roles: Vec<&str>,
    provenance_path: &str,
) -> InvariantDefinition {
    InvariantDefinition::new(
        stable_id(id),
        InvariantKind::RequiredRole,
        invariant_source,
        scope(route, vec![HttpMethod::Post], vec!["src/policy.ts"]),
        InvariantRequirement::RequiredRole {
            required_roles: roles.into_iter().map(str::to_owned).collect(),
        },
        vec![source(provenance_path, 0)],
        BusinessLogicLimits::default(),
    )
    .expect("required-role invariant")
}

fn protected_properties(id: &str, route: &str, provenance_path: &str) -> InvariantDefinition {
    InvariantDefinition::new(
        stable_id(id),
        InvariantKind::ProtectedProperties,
        InvariantSource::BuiltIn,
        scope(route, vec![HttpMethod::Post], vec!["src/policy.ts"]),
        InvariantRequirement::ProtectedProperties {
            protected_properties: vec!["owner_id".to_owned()],
            mutation_operations: vec![DataOperationKind::Update],
        },
        vec![source(provenance_path, 0)],
        BusinessLogicLimits::default(),
    )
    .expect("protected-properties invariant")
}

fn normalized_role_invariant(
    id: &str,
    provenance_path: &str,
    reversed: bool,
) -> InvariantDefinition {
    let methods = if reversed {
        vec![HttpMethod::Post, HttpMethod::Get, HttpMethod::Post]
    } else {
        vec![HttpMethod::Get, HttpMethod::Post]
    };
    let targets = if reversed {
        vec!["src/z.ts", "src/a.ts", "src/z.ts"]
    } else {
        vec!["src/a.ts", "src/z.ts"]
    };
    let roles = if reversed {
        vec!["operator", "admin", "operator"]
    } else {
        vec!["admin", "operator"]
    };
    InvariantDefinition::new(
        stable_id(id),
        InvariantKind::RequiredRole,
        InvariantSource::BuiltIn,
        scope("/admin", methods, targets),
        InvariantRequirement::RequiredRole {
            required_roles: roles.into_iter().map(str::to_owned).collect(),
        },
        vec![source(provenance_path, if reversed { 32 } else { 0 })],
        BusinessLogicLimits::default(),
    )
    .expect("normalized invariant")
}

fn coverage_matrix() -> Vec<BusinessLogicCoverage> {
    REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS
        .into_iter()
        .map(|area| {
            BusinessLogicCoverage::new(
                area,
                CoverageState::Covered,
                "R3_T009_FIXTURE_COVERED",
                ".",
                vec!["sha256:s1-t009-input".to_owned()],
                R3_BUSINESS_LOGIC_PRODUCER_ID,
                BusinessLogicLimits::default(),
            )
            .expect("business logic coverage")
        })
        .collect()
}

fn snapshot(
    role: RevisionRole,
    label: &str,
    definitions: Vec<InvariantDefinition>,
    configuration_identity: Vec<String>,
    limits: RegressionLimits,
) -> SemanticSnapshot {
    let evaluations = Vec::new();
    let output =
        produce_business_logic_outputs(&evaluations, &coverage_matrix(), "2026-09-09T00:00:00Z")
            .expect("canonical producer output");
    let graph = map_validated_observations(&[], &[], &definitions, R3GraphLimits::default())
        .expect("canonical graph records");
    let digest = derive_snapshot_input_digest(
        definitions.clone(),
        evaluations.clone(),
        &output,
        &graph,
        limits,
    )
    .expect("snapshot input digest");
    let revision =
        RevisionIdentity::fixture(role, label, digest, limits).expect("fixture revision");
    SemanticSnapshot::compose(
        revision,
        PRODUCER_CONFIGURATION_DIGEST,
        configuration_identity,
        definitions,
        evaluations,
        output,
        graph,
        limits,
    )
    .expect("semantic snapshot")
}

fn pair(base: &SemanticSnapshot, candidate: &SemanticSnapshot) -> RevisionPair {
    RevisionPair::new(
        base.contract().revision().clone(),
        candidate.contract().revision().clone(),
    )
    .expect("revision pair")
}

fn data_operation(
    label: &str,
    handler_label: &str,
    resource_name: &str,
    provenance_path: &str,
) -> DataOperation {
    DataOperation::new(
        StableSemanticId::from_parts(
            "s1.t010.operation",
            &[label],
            BusinessLogicLimits::default(),
        )
        .expect("operation id"),
        DataOperationKind::Read,
        ResourceRef::new(
            Some("supabase".to_owned()),
            Some("public".to_owned()),
            resource_name,
            ResourceKind::Table,
            None,
            BusinessLogicLimits::default(),
        )
        .expect("resource"),
        None,
        Vec::new(),
        None,
        None,
        None,
        Some(
            StableSemanticId::from_parts(
                "s1.t010.handler",
                &[handler_label],
                BusinessLogicLimits::default(),
            )
            .expect("handler id"),
        ),
        vec![source(provenance_path, 0)],
        CoverageState::Covered,
        BusinessLogicLimits::default(),
    )
    .expect("data operation")
}

fn t010_semantic_id(namespace: &str, label: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[label], BusinessLogicLimits::default())
        .expect("T010 semantic id")
}

fn invariant_evaluation(
    invariant: &InvariantDefinition,
    evaluation_label: &str,
    path_label: &str,
    supporting: Vec<&str>,
    contradicting: Vec<&str>,
    provenance_path: &str,
) -> InvariantEvaluation {
    InvariantEvaluation::new(
        t010_semantic_id("s1.t010.evaluation", evaluation_label),
        invariant.invariant_id().clone(),
        Some(t010_semantic_id("s1.t010.path", path_label)),
        InvariantEvaluationState::Satisfied,
        supporting
            .into_iter()
            .map(|label| t010_semantic_id("s1.t010.observation", label))
            .collect(),
        contradicting
            .into_iter()
            .map(|label| t010_semantic_id("s1.t010.observation", label))
            .collect(),
        Vec::new(),
        vec![source(provenance_path, 0)],
        BusinessLogicLimits::default(),
    )
    .expect("invariant evaluation")
}

fn snapshot_with_operations(
    role: RevisionRole,
    label: &str,
    operations: Vec<DataOperation>,
    configuration_identity: Vec<String>,
    limits: RegressionLimits,
) -> SemanticSnapshot {
    let definitions = Vec::new();
    let evaluations = Vec::new();
    let output =
        produce_business_logic_outputs(&evaluations, &coverage_matrix(), "2026-09-09T00:00:00Z")
            .expect("canonical producer output");
    let graph =
        map_validated_observations(&[], &operations, &definitions, R3GraphLimits::default())
            .expect("canonical graph records");
    let digest = derive_snapshot_input_digest(
        definitions.clone(),
        evaluations.clone(),
        &output,
        &graph,
        limits,
    )
    .expect("snapshot input digest");
    let revision =
        RevisionIdentity::fixture(role, label, digest, limits).expect("fixture revision");
    SemanticSnapshot::compose(
        revision,
        PRODUCER_CONFIGURATION_DIGEST,
        configuration_identity,
        definitions,
        evaluations,
        output,
        graph,
        limits,
    )
    .expect("semantic snapshot")
}

fn snapshot_with_evaluations(
    role: RevisionRole,
    label: &str,
    definitions: Vec<InvariantDefinition>,
    evaluations: Vec<InvariantEvaluation>,
    configuration_identity: Vec<String>,
    limits: RegressionLimits,
) -> SemanticSnapshot {
    let output =
        produce_business_logic_outputs(&evaluations, &coverage_matrix(), "2026-09-09T00:00:00Z")
            .expect("canonical producer output");
    let graph = map_validated_observations(&[], &[], &definitions, R3GraphLimits::default())
        .expect("canonical graph records");
    let digest = derive_snapshot_input_digest(
        definitions.clone(),
        evaluations.clone(),
        &output,
        &graph,
        limits,
    )
    .expect("snapshot input digest");
    let revision =
        RevisionIdentity::fixture(role, label, digest, limits).expect("fixture revision");
    SemanticSnapshot::compose(
        revision,
        PRODUCER_CONFIGURATION_DIGEST,
        configuration_identity,
        definitions,
        evaluations,
        output,
        graph,
        limits,
    )
    .expect("semantic snapshot")
}

#[test]
fn definition_digest_normalizes_semantics_and_excludes_provenance() {
    let base = normalized_role_invariant("normalized", "src/old.ts", false);
    let moved = normalized_role_invariant("normalized", "src/new.ts", true);

    let base_digest = derive_invariant_definition_digest(&base).expect("base digest");
    let moved_digest = derive_invariant_definition_digest(&moved).expect("moved digest");

    assert_eq!(base_digest, moved_digest);
}

#[test]
fn stable_key_matching_is_deterministic_and_never_fuzzy_joins_different_ids() {
    let shared_base = required_role(
        "shared",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/base-shared.ts",
    );
    let shared_candidate = required_role(
        "shared",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/candidate-shared.ts",
    );
    let rename_base = required_role(
        "rename-base",
        InvariantSource::BuiltIn,
        "/same",
        vec!["admin"],
        "src/base.ts",
    );
    let rename_candidate = required_role(
        "rename-candidate",
        InvariantSource::BuiltIn,
        "/same",
        vec!["admin"],
        "src/candidate.ts",
    );
    assert_eq!(
        derive_invariant_definition_digest(&rename_base).expect("base definition digest"),
        derive_invariant_definition_digest(&rename_candidate).expect("candidate definition digest")
    );

    let base = snapshot(
        RevisionRole::TrustedBase,
        "stable-key-base",
        vec![rename_base.clone(), shared_base.clone()],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot(
        RevisionRole::Candidate,
        "stable-key-candidate",
        vec![shared_candidate.clone(), rename_candidate.clone()],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let revision_pair = pair(&base, &candidate);

    let first = match_invariants(
        &revision_pair,
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("stable keyed match");
    let replay = match_invariants(
        &revision_pair,
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("stable keyed replay");
    assert_eq!(first, replay);
    assert_eq!(first.len(), 3);
    assert!(
        first
            .windows(2)
            .all(|window| window[0].stable_invariant_id() < window[1].stable_invariant_id())
    );

    let shared = first
        .iter()
        .find(|record| record.stable_invariant_id() == shared_base.invariant_id().as_str())
        .expect("shared invariant match");
    assert_eq!(shared.pair_presence(), PairPresence::Matched);
    assert_eq!(shared.continuity_basis(), ContinuityBasis::ExactStableId);
    assert_eq!(
        shared.definition_compatibility(),
        InvariantDefinitionCompatibility::Compatible
    );
    assert!(shared.is_comparable_match());
    assert_eq!(
        shared.base_definition_digest(),
        shared.candidate_definition_digest()
    );

    let removed = first
        .iter()
        .find(|record| record.stable_invariant_id() == rename_base.invariant_id().as_str())
        .expect("base-only invariant");
    assert_eq!(removed.pair_presence(), PairPresence::BaseOnly);
    assert_eq!(removed.continuity_basis(), ContinuityBasis::Unmatched);
    assert_eq!(
        removed.definition_compatibility(),
        InvariantDefinitionCompatibility::Unpaired
    );
    assert!(!removed.is_comparable_match());

    let added = first
        .iter()
        .find(|record| record.stable_invariant_id() == rename_candidate.invariant_id().as_str())
        .expect("candidate-only invariant");
    assert_eq!(added.pair_presence(), PairPresence::CandidateOnly);
    assert_eq!(added.continuity_basis(), ContinuityBasis::Unmatched);
    assert!(!added.is_comparable_match());
}

#[test]
fn same_stable_id_with_kind_source_scope_or_requirement_change_is_conflict() {
    let base = vec![
        required_role(
            "kind-conflict",
            InvariantSource::BuiltIn,
            "/kind",
            vec!["admin"],
            "src/base-kind.ts",
        ),
        required_role(
            "source-conflict",
            InvariantSource::BuiltIn,
            "/source",
            vec!["admin"],
            "src/base-source.ts",
        ),
        required_role(
            "scope-conflict",
            InvariantSource::BuiltIn,
            "/scope-a",
            vec!["admin"],
            "src/base-scope.ts",
        ),
        required_role(
            "requirement-conflict",
            InvariantSource::BuiltIn,
            "/requirement",
            vec!["admin"],
            "src/base-requirement.ts",
        ),
    ];
    let candidate = vec![
        protected_properties("kind-conflict", "/kind", "src/candidate-kind.ts"),
        required_role(
            "source-conflict",
            InvariantSource::ProjectDeclaration,
            "/source",
            vec!["admin"],
            "src/candidate-source.ts",
        ),
        required_role(
            "scope-conflict",
            InvariantSource::BuiltIn,
            "/scope-b",
            vec!["admin"],
            "src/candidate-scope.ts",
        ),
        required_role(
            "requirement-conflict",
            InvariantSource::BuiltIn,
            "/requirement",
            vec!["operator"],
            "src/candidate-requirement.ts",
        ),
    ];

    let trusted_base = snapshot(
        RevisionRole::TrustedBase,
        "conflict-base",
        base,
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot(
        RevisionRole::Candidate,
        "conflict-candidate",
        candidate,
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let matches = match_invariants(
        &pair(&trusted_base, &candidate),
        &trusted_base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("definition conflicts are fail-visible records");

    assert_eq!(matches.len(), 4);
    for record in matches {
        assert_eq!(record.pair_presence(), PairPresence::Matched);
        assert_eq!(record.continuity_basis(), ContinuityBasis::ExactStableId);
        assert!(record.definition_compatibility().is_conflict());
        assert_eq!(
            record.definition_compatibility().as_str(),
            "INVARIANT_DEFINITION_CONFLICT"
        );
        assert!(!record.is_comparable_match());
        assert_ne!(
            record.base_definition_digest(),
            record.candidate_definition_digest()
        );
    }
}

#[test]
fn matcher_rejects_incompatible_snapshot_contract_before_key_matching() {
    let definition = required_role(
        "shared",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/shared.ts",
    );
    let base = snapshot(
        RevisionRole::TrustedBase,
        "incompatible-base",
        vec![definition.clone()],
        vec!["profile:base".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot(
        RevisionRole::Candidate,
        "incompatible-candidate",
        vec![definition],
        vec!["profile:candidate".to_owned()],
        RegressionLimits::default(),
    );

    let error = match_invariants(
        &pair(&base, &candidate),
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect_err("incompatible snapshots must fail before matching");
    assert!(matches!(
        error,
        InvariantMatchError::Snapshot(SnapshotCompositionError::IncompatibleSnapshots(
            SnapshotCompatibility::ConfigurationIdentityMismatch
        ))
    ));
}

#[test]
fn matcher_enforces_bounded_pair_result_count() {
    let limits = RegressionLimits {
        max_pair_results: 1,
        ..RegressionLimits::default()
    };
    let base = snapshot(
        RevisionRole::TrustedBase,
        "cap-base",
        vec![required_role(
            "base-only",
            InvariantSource::BuiltIn,
            "/same",
            vec!["admin"],
            "src/base.ts",
        )],
        vec!["profile:default".to_owned()],
        limits,
    );
    let candidate = snapshot(
        RevisionRole::Candidate,
        "cap-candidate",
        vec![required_role(
            "candidate-only",
            InvariantSource::BuiltIn,
            "/same",
            vec!["admin"],
            "src/candidate.ts",
        )],
        vec!["profile:default".to_owned()],
        limits,
    );

    let error = match_invariants(&pair(&base, &candidate), &base, &candidate, limits)
        .expect_err("union larger than max_pair_results must fail visible");
    assert!(matches!(
        error,
        InvariantMatchError::TooManyMatchResults { count: 2, max: 1 }
    ));
}

#[test]
fn semantic_object_continuity_matches_exact_ids_across_provenance_move() {
    let base = snapshot_with_operations(
        RevisionRole::TrustedBase,
        "semantic-move-base",
        vec![data_operation(
            "read-users",
            "handler",
            "users",
            "src/old.ts",
        )],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot_with_operations(
        RevisionRole::Candidate,
        "semantic-move-candidate",
        vec![data_operation(
            "read-users",
            "handler",
            "users",
            "src/new.ts",
        )],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );

    assert_ne!(base.graph_nodes(), candidate.graph_nodes());
    assert_ne!(base.graph_edges(), candidate.graph_edges());
    assert_eq!(
        base.graph_nodes()
            .iter()
            .map(|node| node.node_id.as_str())
            .collect::<Vec<_>>(),
        candidate
            .graph_nodes()
            .iter()
            .map(|node| node.node_id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        base.graph_edges()
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect::<Vec<_>>(),
        candidate
            .graph_edges()
            .iter()
            .map(|edge| edge.edge_id.as_str())
            .collect::<Vec<_>>()
    );

    let revision_pair = pair(&base, &candidate);
    let first = match_semantic_objects(
        &revision_pair,
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("exact semantic continuity");
    let replay = match_semantic_objects(
        &revision_pair,
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("exact semantic continuity replay");

    assert_eq!(first, replay);
    assert_eq!(first.len(), 3);
    assert!(first.iter().all(|record| {
        record.pair_presence() == PairPresence::Matched
            && record.continuity_basis() == ContinuityBasis::ExactStableId
    }));
    assert_eq!(
        first
            .iter()
            .filter(|record| record.object_kind() == SemanticObjectKind::GraphNode)
            .count(),
        2
    );
    assert_eq!(
        first
            .iter()
            .filter(|record| record.object_kind() == SemanticObjectKind::GraphEdge)
            .count(),
        1
    );
}

#[test]
fn semantic_object_rename_with_same_graph_shape_stays_explicitly_unmatched() {
    let base = snapshot_with_operations(
        RevisionRole::TrustedBase,
        "semantic-rename-base",
        vec![data_operation(
            "read-users",
            "old-handler",
            "users",
            "src/old.ts",
        )],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot_with_operations(
        RevisionRole::Candidate,
        "semantic-rename-candidate",
        vec![data_operation(
            "read-users",
            "new-handler",
            "users",
            "src/new.ts",
        )],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );

    let matches = match_semantic_objects(
        &pair(&base, &candidate),
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("ambiguous rename remains explicit");

    assert_eq!(matches.len(), 5);
    assert_eq!(
        matches
            .iter()
            .filter(|record| record.pair_presence() == PairPresence::Matched)
            .count(),
        1
    );
    assert_eq!(
        matches
            .iter()
            .filter(|record| record.pair_presence() == PairPresence::BaseOnly)
            .count(),
        2
    );
    assert_eq!(
        matches
            .iter()
            .filter(|record| record.pair_presence() == PairPresence::CandidateOnly)
            .count(),
        2
    );
    assert!(matches.iter().all(|record| {
        record.continuity_basis() != ContinuityBasis::ProvenDeterministicContinuity
    }));
    assert!(matches.iter().all(|record| {
        (record.pair_presence() == PairPresence::Matched
            && record.continuity_basis() == ContinuityBasis::ExactStableId)
            || (record.pair_presence() != PairPresence::Matched
                && record.continuity_basis() == ContinuityBasis::Unmatched)
    }));
}

#[test]
fn semantic_object_matching_rejects_incompatible_snapshot_before_continuity() {
    let operation = data_operation("read-users", "handler", "users", "src/shared.ts");
    let base = snapshot_with_operations(
        RevisionRole::TrustedBase,
        "semantic-incompatible-base",
        vec![operation.clone()],
        vec!["profile:base".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot_with_operations(
        RevisionRole::Candidate,
        "semantic-incompatible-candidate",
        vec![operation],
        vec!["profile:candidate".to_owned()],
        RegressionLimits::default(),
    );

    let error = match_semantic_objects(
        &pair(&base, &candidate),
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect_err("snapshot compatibility must precede semantic continuity");
    assert!(matches!(
        error,
        SemanticObjectMatchError::Snapshot(SnapshotCompositionError::IncompatibleSnapshots(
            SnapshotCompatibility::ConfigurationIdentityMismatch
        ))
    ));
}

#[test]
fn semantic_object_matching_enforces_union_caps_without_truncation() {
    let limits = RegressionLimits {
        max_graph_edges: 1,
        ..RegressionLimits::default()
    };
    let base = snapshot_with_operations(
        RevisionRole::TrustedBase,
        "semantic-cap-base",
        vec![data_operation(
            "read-users",
            "base-handler",
            "users",
            "src/base.ts",
        )],
        vec!["profile:default".to_owned()],
        limits,
    );
    let candidate = snapshot_with_operations(
        RevisionRole::Candidate,
        "semantic-cap-candidate",
        vec![data_operation(
            "read-users",
            "candidate-handler",
            "users",
            "src/candidate.ts",
        )],
        vec!["profile:default".to_owned()],
        limits,
    );

    let error = match_semantic_objects(&pair(&base, &candidate), &base, &candidate, limits)
        .expect_err("edge union larger than cap must fail visible");
    assert!(matches!(
        error,
        SemanticObjectMatchError::TooManySemanticObjects {
            object_kind: SemanticObjectKind::GraphEdge,
            count: 2,
            max: 1
        }
    ));
}

#[test]
fn evaluation_paths_and_observations_use_exact_stable_continuity() {
    let base_definition = required_role(
        "path-continuity",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/old.ts",
    );
    let candidate_definition = required_role(
        "path-continuity",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/new.ts",
    );
    let base_evaluation = invariant_evaluation(
        &base_definition,
        "base-evaluation",
        "shared-path",
        vec!["shared", "role-switch", "base-only"],
        Vec::new(),
        "src/old.ts",
    );
    let candidate_evaluation = invariant_evaluation(
        &candidate_definition,
        "candidate-evaluation",
        "shared-path",
        vec!["shared", "candidate-only"],
        vec!["role-switch"],
        "src/new.ts",
    );
    let base = snapshot_with_evaluations(
        RevisionRole::TrustedBase,
        "path-continuity-base",
        vec![base_definition],
        vec![base_evaluation],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot_with_evaluations(
        RevisionRole::Candidate,
        "path-continuity-candidate",
        vec![candidate_definition],
        vec![candidate_evaluation],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );

    let matches = match_semantic_objects(
        &pair(&base, &candidate),
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("exact evaluation semantic continuity");

    let paths = matches
        .iter()
        .filter(|record| record.object_kind() == SemanticObjectKind::EvaluationPath)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].pair_presence(), PairPresence::Matched);
    assert_eq!(paths[0].continuity_basis(), ContinuityBasis::ExactStableId);

    let observations = matches
        .iter()
        .filter(|record| record.object_kind() == SemanticObjectKind::Observation)
        .collect::<Vec<_>>();
    assert_eq!(observations.len(), 4);
    assert_eq!(
        observations
            .iter()
            .filter(|record| record.pair_presence() == PairPresence::Matched)
            .count(),
        2
    );
    assert_eq!(
        observations
            .iter()
            .filter(|record| record.pair_presence() == PairPresence::BaseOnly)
            .count(),
        1
    );
    assert_eq!(
        observations
            .iter()
            .filter(|record| record.pair_presence() == PairPresence::CandidateOnly)
            .count(),
        1
    );
    assert!(observations.iter().all(|record| {
        (record.pair_presence() == PairPresence::Matched
            && record.continuity_basis() == ContinuityBasis::ExactStableId)
            || (record.pair_presence() != PairPresence::Matched
                && record.continuity_basis() == ContinuityBasis::Unmatched)
    }));
}

#[test]
fn semantic_path_rename_stays_unmatched_even_with_shared_observations() {
    let base_definition = required_role(
        "path-rename",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/base.ts",
    );
    let candidate_definition = required_role(
        "path-rename",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/candidate.ts",
    );
    let base_evaluation = invariant_evaluation(
        &base_definition,
        "path-rename-base-evaluation",
        "old-path",
        vec!["shared-observation"],
        Vec::new(),
        "src/base.ts",
    );
    let candidate_evaluation = invariant_evaluation(
        &candidate_definition,
        "path-rename-candidate-evaluation",
        "new-path",
        vec!["shared-observation"],
        Vec::new(),
        "src/candidate.ts",
    );
    let base = snapshot_with_evaluations(
        RevisionRole::TrustedBase,
        "path-rename-base",
        vec![base_definition],
        vec![base_evaluation],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );
    let candidate = snapshot_with_evaluations(
        RevisionRole::Candidate,
        "path-rename-candidate",
        vec![candidate_definition],
        vec![candidate_evaluation],
        vec!["profile:default".to_owned()],
        RegressionLimits::default(),
    );

    let matches = match_semantic_objects(
        &pair(&base, &candidate),
        &base,
        &candidate,
        RegressionLimits::default(),
    )
    .expect("path rename remains explicit");
    let paths = matches
        .iter()
        .filter(|record| record.object_kind() == SemanticObjectKind::EvaluationPath)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().all(|record| {
        record.pair_presence() != PairPresence::Matched
            && record.continuity_basis() == ContinuityBasis::Unmatched
    }));
    assert!(matches.iter().all(|record| {
        record.continuity_basis() != ContinuityBasis::ProvenDeterministicContinuity
    }));
}

#[test]
fn semantic_observation_matching_enforces_pair_cap_without_truncation() {
    let limits = RegressionLimits {
        max_pair_results: 1,
        ..RegressionLimits::default()
    };
    let base_definition = required_role(
        "observation-cap",
        InvariantSource::BuiltIn,
        "/admin",
        vec!["admin"],
        "src/base.ts",
    );
    let candidate_definition = base_definition.clone();
    let base_evaluation = invariant_evaluation(
        &base_definition,
        "observation-cap-base-evaluation",
        "shared-path",
        vec!["base-observation"],
        Vec::new(),
        "src/base.ts",
    );
    let candidate_evaluation = invariant_evaluation(
        &candidate_definition,
        "observation-cap-candidate-evaluation",
        "shared-path",
        vec!["candidate-observation"],
        Vec::new(),
        "src/candidate.ts",
    );
    let base = snapshot_with_evaluations(
        RevisionRole::TrustedBase,
        "observation-cap-base",
        vec![base_definition],
        vec![base_evaluation],
        vec!["profile:default".to_owned()],
        limits,
    );
    let candidate = snapshot_with_evaluations(
        RevisionRole::Candidate,
        "observation-cap-candidate",
        vec![candidate_definition],
        vec![candidate_evaluation],
        vec!["profile:default".to_owned()],
        limits,
    );

    let error = match_semantic_objects(&pair(&base, &candidate), &base, &candidate, limits)
        .expect_err("observation union larger than pair cap must fail visible");
    assert!(matches!(
        error,
        SemanticObjectMatchError::TooManySemanticObjects {
            object_kind: SemanticObjectKind::Observation,
            count: 2,
            max: 1
        }
    ));
}
