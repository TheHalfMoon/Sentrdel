use sentrdel_cli::review::r3_link::{
    R3_SCIP_BRIDGE_CREATES_FINDINGS, R3_SCIP_BRIDGE_EXECUTES_TARGET_CODE,
    R3_SCIP_BRIDGE_PERFORMS_NETWORK_ACCESS, R3_SCIP_BRIDGE_QUALIFIES_PRODUCERS,
    ScipLinkingDiagnosticReason, ScipLinkingError, ScipSemanticInput, link_scip_semantics,
};
use sentrdel_graph::{
    ScipArtifact, ScipDocument, ScipIngestionError, ScipIngestionRequest, ScipOccurrence,
    ScipOccurrenceRole, ScipPosition, ScipProducerQualification, ScipRange, ingest_scip,
};
use sentrdel_review::{
    business_logic::model::{BusinessLogicLimits, ConfidenceBasis, LinkBasis, SourceLocation},
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::coverage::CoverageState;

fn provenance() -> SourceLocation {
    SourceLocation::new(
        NormalizedRepoPath::parse("src/routes.ts", DEFAULT_MAX_REPO_PATH_BYTES)
            .expect("normalized path"),
        0,
        7,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("source provenance")
}

fn request(qualification: ScipProducerQualification) -> ScipIngestionRequest {
    ScipIngestionRequest {
        artifact: ScipArtifact {
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            producer_name: "fixture-scip".to_owned(),
            producer_version: Some("1.0.0".to_owned()),
            documents: vec![ScipDocument {
                relative_path: "src/routes.ts".to_owned(),
                language: "typescript".to_owned(),
                occurrences: vec![ScipOccurrence {
                    symbol: "typescript npm fixture 1.0.0 handler().".to_owned(),
                    range: ScipRange {
                        start: ScipPosition {
                            line: 0,
                            character: 0,
                        },
                        end: ScipPosition {
                            line: 0,
                            character: 7,
                        },
                    },
                    role: ScipOccurrenceRole::Reference,
                }],
            }],
        },
        producer_qualification: qualification,
        scope: ".".to_owned(),
        observed_at: "2026-09-05T00:00:00Z".to_owned(),
    }
}

fn admitted(qualification: ScipProducerQualification, complete: bool) -> ScipSemanticInput {
    ScipSemanticInput::Admitted {
        ingestion: ingest_scip(request(qualification)).expect("canonical SCIP ingestion"),
        provenance: vec![provenance()],
        complete,
    }
}

#[test]
fn compiler_backed_ingestion_maps_only_after_canonical_ingestion() {
    let result = link_scip_semantics(
        admitted(
            ScipProducerQualification::CompilerBacked {
                qualification_id: "SCIPQ-fixture-compiler".to_owned(),
            },
            true,
        ),
        BusinessLogicLimits::default(),
    )
    .expect("compiler-backed bridge");

    assert_eq!(result.semantic_state(), &CoverageState::Covered);
    assert!(result.diagnostics().is_empty());
    assert!(result.links().iter().any(|link| {
        link.basis() == LinkBasis::ScipReference
            && link.confidence_basis() == ConfidenceBasis::Extracted
    }));
}

#[test]
fn heuristic_and_incomplete_ingestion_never_become_clean() {
    let heuristic = link_scip_semantics(
        admitted(
            ScipProducerQualification::Heuristic {
                qualification_id: "SCIPQ-fixture-heuristic".to_owned(),
            },
            true,
        ),
        BusinessLogicLimits::default(),
    )
    .expect("heuristic bridge");
    assert_eq!(heuristic.semantic_state(), &CoverageState::Partial);
    assert!(heuristic.links().iter().any(|link| {
        link.basis() == LinkBasis::ScipReference
            && link.confidence_basis() == ConfidenceBasis::Inferred
    }));
    assert!(
        heuristic.diagnostics().iter().any(|diagnostic| {
            diagnostic.reason() == ScipLinkingDiagnosticReason::ScipIncomplete
        })
    );

    let incomplete = link_scip_semantics(
        admitted(
            ScipProducerQualification::CompilerBacked {
                qualification_id: "SCIPQ-fixture-compiler".to_owned(),
            },
            false,
        ),
        BusinessLogicLimits::default(),
    )
    .expect("explicit incomplete bridge");
    assert_eq!(incomplete.semantic_state(), &CoverageState::Partial);
}

#[test]
fn semantic_absence_and_ambiguity_are_explicit_coverage_gaps() {
    let unavailable = link_scip_semantics(
        ScipSemanticInput::Unavailable,
        BusinessLogicLimits::default(),
    )
    .expect("unavailable bridge");
    assert_eq!(unavailable.semantic_state(), &CoverageState::Unavailable);
    assert!(unavailable.links().is_empty());
    assert_eq!(
        unavailable.diagnostics()[0].reason(),
        ScipLinkingDiagnosticReason::ScipUnavailable
    );

    let ambiguous = link_scip_semantics(
        ScipSemanticInput::Ambiguous {
            provenance: vec![provenance()],
        },
        BusinessLogicLimits::default(),
    )
    .expect("ambiguous bridge");
    assert_eq!(ambiguous.semantic_state(), &CoverageState::Partial);
    assert!(ambiguous.links().is_empty());
    assert_eq!(
        ambiguous.diagnostics()[0].reason(),
        ScipLinkingDiagnosticReason::ScipAmbiguous
    );
}

#[test]
fn unqualified_compiler_claim_fails_before_an_opaque_ingestion_result_exists() {
    let error = ingest_scip(request(ScipProducerQualification::CompilerBacked {
        qualification_id: "   ".to_owned(),
    }))
    .expect_err("blank qualification must fail canonical ingestion");

    assert!(matches!(error, ScipIngestionError::BlankQualificationId));
}

#[test]
fn provenance_caps_fail_closed() {
    let ingestion = ingest_scip(request(ScipProducerQualification::CompilerBacked {
        qualification_id: "SCIPQ-fixture-compiler".to_owned(),
    }))
    .expect("canonical ingestion");
    let limits = BusinessLogicLimits {
        max_provenance_per_record: 1,
        ..BusinessLogicLimits::default()
    };
    let error = link_scip_semantics(
        ScipSemanticInput::Admitted {
            ingestion,
            provenance: vec![
                provenance(),
                SourceLocation::new(
                    NormalizedRepoPath::parse("src/other.ts", DEFAULT_MAX_REPO_PATH_BYTES)
                        .expect("normalized path"),
                    0,
                    1,
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                )
                .expect("second provenance"),
            ],
            complete: true,
        },
        limits,
    )
    .expect_err("provenance cap must fail closed");

    assert!(matches!(
        error,
        ScipLinkingError::TooManyProvenance { count: 2, max: 1 }
    ));
}

#[test]
fn authority_canaries_remain_false() {
    const { assert!(!R3_SCIP_BRIDGE_EXECUTES_TARGET_CODE) };
    const { assert!(!R3_SCIP_BRIDGE_PERFORMS_NETWORK_ACCESS) };
    const { assert!(!R3_SCIP_BRIDGE_QUALIFIES_PRODUCERS) };
    const { assert!(!R3_SCIP_BRIDGE_CREATES_FINDINGS) };
}
