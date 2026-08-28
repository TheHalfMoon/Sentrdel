#![forbid(unsafe_code)]

use serde::Deserialize;
use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    path::{Component, Path, PathBuf},
};

const LAYOUT_BYTES: &[u8] = include_bytes!("../../../tests/benchmark/corpus-layout.json");
const LEGACY_PUBLIC_BYTES: &[u8] = include_bytes!("../../../tests/benchmark/t089-core-corpus.json");
const PUBLIC_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/public-regression/t089-core-corpus.json");
const DEVELOPMENT_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/development-evaluation/t090-development-corpus.json");
const PROTECTED_MANIFEST_BYTES: &[u8] =
    include_bytes!("../../../tests/benchmark/protected-holdout/manifest.json");
const T089_SOURCE: &str = include_str!("t089_benchmark_core.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CorpusClass {
    PublicRegression,
    DevelopmentEvaluation,
    ProtectedHoldout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExpectedOutputLocation {
    RepositoryVisible,
    ExternalOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum CandidateExpectedOutputAccess {
    Allowed,
    Denied,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct CorpusBoundary {
    corpus_class: CorpusClass,
    root: String,
    committed_fixture_paths: Vec<String>,
    expected_output_location: ExpectedOutputLocation,
    candidate_generation_expected_output_access: CandidateExpectedOutputAccess,
    base_ci_requires_private_material: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct CorpusLayout {
    layout_version: String,
    public_regression: CorpusBoundary,
    development_evaluation: CorpusBoundary,
    protected_holdout: CorpusBoundary,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct CorpusHeader {
    corpus_revision: String,
    expected_outputs_revision: String,
    corpus_class: CorpusClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct ProtectedManifest {
    manifest_version: String,
    corpus_class: CorpusClass,
    case_material_location: ExpectedOutputLocation,
    expected_outputs_location: ExpectedOutputLocation,
    candidate_generation_expected_output_access: CandidateExpectedOutputAccess,
    base_ci_requires_private_material: bool,
    repository_committed_case_count: u64,
    repository_committed_expected_output_count: u64,
    qualification_receipt_fields: Vec<String>,
}

fn load_layout() -> Result<CorpusLayout, serde_json::Error> {
    serde_json::from_slice(LAYOUT_BYTES)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_repo_relative(path: &str) {
    let path = Path::new(path);
    assert!(
        !path.is_absolute(),
        "benchmark path must be repository-relative"
    );
    assert!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "benchmark path must not contain traversal or special components: {}",
        path.display()
    );
}

fn candidate_visible_fixture_paths(layout: &CorpusLayout) -> Vec<&str> {
    [
        &layout.public_regression,
        &layout.development_evaluation,
        &layout.protected_holdout,
    ]
    .into_iter()
    .filter(|boundary| {
        boundary.candidate_generation_expected_output_access
            == CandidateExpectedOutputAccess::Allowed
            && boundary.expected_output_location == ExpectedOutputLocation::RepositoryVisible
    })
    .flat_map(|boundary| boundary.committed_fixture_paths.iter().map(String::as_str))
    .collect()
}

#[test]
fn corpus_layout_separates_all_three_classes_without_private_base_ci_dependency()
-> Result<(), Box<dyn Error>> {
    let layout = load_layout()?;
    assert_eq!(layout.layout_version, "sentrdelbench-corpus-layout/t090-v1");

    assert_eq!(
        layout.public_regression.corpus_class,
        CorpusClass::PublicRegression
    );
    assert_eq!(
        layout.development_evaluation.corpus_class,
        CorpusClass::DevelopmentEvaluation
    );
    assert_eq!(
        layout.protected_holdout.corpus_class,
        CorpusClass::ProtectedHoldout
    );

    let roots = [
        layout.public_regression.root.as_str(),
        layout.development_evaluation.root.as_str(),
        layout.protected_holdout.root.as_str(),
    ];
    let unique_roots = roots.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(unique_roots.len(), 3, "corpus roots must be distinct");

    for root in unique_roots {
        assert_repo_relative(root);
        assert!(
            repo_root().join(root).is_dir(),
            "missing corpus root {root}"
        );
    }

    assert_eq!(
        layout.public_regression.expected_output_location,
        ExpectedOutputLocation::RepositoryVisible
    );
    assert_eq!(
        layout.development_evaluation.expected_output_location,
        ExpectedOutputLocation::RepositoryVisible
    );
    assert_eq!(
        layout.protected_holdout.expected_output_location,
        ExpectedOutputLocation::ExternalOnly
    );
    assert_eq!(
        layout
            .protected_holdout
            .candidate_generation_expected_output_access,
        CandidateExpectedOutputAccess::Denied
    );

    for boundary in [
        &layout.public_regression,
        &layout.development_evaluation,
        &layout.protected_holdout,
    ] {
        assert!(
            !boundary.base_ci_requires_private_material,
            "base CI must not require private benchmark material"
        );
    }
    assert!(layout.protected_holdout.committed_fixture_paths.is_empty());

    let mut fixture_paths = BTreeSet::new();
    for boundary in [&layout.public_regression, &layout.development_evaluation] {
        let root = format!("{}/", boundary.root);
        assert!(!boundary.committed_fixture_paths.is_empty());
        for fixture_path in &boundary.committed_fixture_paths {
            assert_repo_relative(fixture_path);
            assert!(fixture_path.starts_with(&root));
            assert!(fixture_paths.insert(fixture_path.as_str()));
            assert!(repo_root().join(fixture_path).is_file());
        }
    }

    Ok(())
}

#[test]
fn repository_visible_fixtures_match_their_declared_classes() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        LEGACY_PUBLIC_BYTES, PUBLIC_BYTES,
        "T089 compatibility fixture must stay byte-identical to the public-regression copy"
    );

    let public: CorpusHeader = serde_json::from_slice(PUBLIC_BYTES)?;
    let development: CorpusHeader = serde_json::from_slice(DEVELOPMENT_BYTES)?;

    assert_eq!(public.corpus_class, CorpusClass::PublicRegression);
    assert_eq!(development.corpus_class, CorpusClass::DevelopmentEvaluation);
    assert!(!public.corpus_revision.trim().is_empty());
    assert!(!public.expected_outputs_revision.trim().is_empty());
    assert!(!development.corpus_revision.trim().is_empty());
    assert!(!development.expected_outputs_revision.trim().is_empty());

    Ok(())
}

#[test]
fn protected_holdout_directory_is_metadata_only() -> Result<(), Box<dyn Error>> {
    let protected_dir = repo_root().join("tests/benchmark/protected-holdout");
    let committed_names = fs::read_dir(&protected_dir)?
        .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let allowed_names = [".gitignore", "README.md", "manifest.json"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(committed_names, allowed_names);

    let manifest: ProtectedManifest = serde_json::from_slice(PROTECTED_MANIFEST_BYTES)?;
    assert_eq!(
        manifest.manifest_version,
        "sentrdelbench-protected-holdout/t090-v1"
    );
    assert_eq!(manifest.corpus_class, CorpusClass::ProtectedHoldout);
    assert_eq!(
        manifest.case_material_location,
        ExpectedOutputLocation::ExternalOnly
    );
    assert_eq!(
        manifest.expected_outputs_location,
        ExpectedOutputLocation::ExternalOnly
    );
    assert_eq!(
        manifest.candidate_generation_expected_output_access,
        CandidateExpectedOutputAccess::Denied
    );
    assert!(!manifest.base_ci_requires_private_material);
    assert_eq!(manifest.repository_committed_case_count, 0);
    assert_eq!(manifest.repository_committed_expected_output_count, 0);

    let receipt_fields = manifest
        .qualification_receipt_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for forbidden in [
        "case_id",
        "expected_findings",
        "labels",
        "case_level_diagnostics",
    ] {
        assert!(
            !receipt_fields.contains(forbidden),
            "promotion receipt must not expose protected field {forbidden}"
        );
    }
    for required in [
        "candidate_identity",
        "evaluator_digest",
        "metric_contract_digest",
        "protected_corpus_digest",
        "expected_outputs_digest",
        "aggregate_metric_states",
        "aggregate_metric_components",
        "authority_assertion_results",
        "replay_status",
    ] {
        assert!(
            receipt_fields.contains(required),
            "promotion receipt is missing identity/aggregate field {required}"
        );
    }

    Ok(())
}

#[test]
fn candidate_generation_view_cannot_enumerate_protected_expected_outputs()
-> Result<(), Box<dyn Error>> {
    let layout = load_layout()?;
    let visible = candidate_visible_fixture_paths(&layout);

    assert_eq!(visible.len(), 2);
    assert!(
        visible
            .iter()
            .any(|path| path.contains("public-regression"))
    );
    assert!(
        visible
            .iter()
            .any(|path| path.contains("development-evaluation"))
    );
    assert!(
        visible
            .iter()
            .all(|path| !path.contains("protected-holdout"))
    );

    assert!(
        !T089_SOURCE.contains("protected-holdout"),
        "public/base benchmark harness must not load protected holdout material"
    );

    Ok(())
}
