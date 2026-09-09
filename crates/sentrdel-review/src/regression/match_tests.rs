use crate::business_logic::coverage::REQUIRED_BUSINESS_LOGIC_COVERAGE_AREAS;
use crate::business_logic::graph::{R3GraphLimits, map_validated_observations};
use crate::business_logic::model::{
    BusinessLogicCoverage, BusinessLogicLimits, DataOperationKind, HttpMethod, InvariantDefinition,
    InvariantKind, InvariantRequirement, InvariantScope, InvariantSource, SourceLocation,
    StableSemanticId,
};
use crate::business_logic::producer::{
    R3_BUSINESS_LOGIC_PRODUCER_ID, produce_business_logic_outputs,
};
use crate::regression::invariant_match::{
    InvariantDefinitionCompatibility, InvariantMatchError, match_invariants,
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
