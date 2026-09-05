#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use sentrdel_review::{
    business_logic::{
        model::{
            BusinessLogicLimits, ProviderAuthorityClass, ProviderClientAuthority, ResourceKind,
            ResourceRef, SourceLocation, StableSemanticId,
        },
        r2_support::{
            R2_SUPPORT_CONFIDENCE_GRANTS_AUTHORITY, R2_SUPPORT_CREATES_FINDINGS,
            R2_SUPPORT_PROVES_LIVE_POSTURE, R2_SUPPORT_PROVIDER_NETWORK_ALLOWED,
            R2_SUPPORT_TARGET_EXECUTION_ALLOWED, R2SupportDiagnosticReason, R2SupportError,
            R2SupportKind, R2SupportLimits, R2SupportTargetKind, correlate_supabase_r2_support,
        },
    },
    supabase::{COVERAGE_LIVE_POSTURE, COVERAGE_STATIC_POSTURE_DATABASE},
    supabase_integration::SupabaseR2ProviderOutput,
    view::{DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath},
};
use sentrdel_schema::{
    SCHEMA_V1,
    coverage::{CoverageRecord, CoverageState, ProviderCoverageDimension},
    evidence::{
        EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, EvidenceLocation,
        EvidenceSubject, ProducerKind,
    },
};

const CAPTURED_AT: &str = "2026-09-05T18:00:00Z";

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path")
}

fn source_location(value: &str) -> SourceLocation {
    SourceLocation::new(path(value), 0, 1, "sha256:r3-t018-source").expect("source location")
}

fn semantic_id(namespace: &str, value: &str) -> StableSemanticId {
    StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
        .expect("stable semantic id")
}

fn evidence(category: &str, subject: Option<(&str, &str)>, file: &str) -> Evidence {
    let authority = EvidenceAuthority::from_runtime(
        "sentrdel.supabase.r3-t018-fixture",
        "1",
        ProducerKind::NativeRule,
    )
    .expect("R2 fixture authority");
    authority
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:r2-canonical-input".to_owned()],
            observation: format!("repository-derived {category} observation"),
            security_interpretation: None,
            category: category.to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: subject
                .map(|(kind, id)| {
                    vec![EvidenceSubject {
                        kind: kind.to_owned(),
                        id: id.to_owned(),
                    }]
                })
                .unwrap_or_default(),
            locations: vec![EvidenceLocation {
                repo_relative_path: file.to_owned(),
                start_line: Some(1),
                start_column: Some(1),
                end_line: Some(1),
                end_column: Some(12),
                symbol: None,
                content_digest: Some("sha256:r2-canonical-input".to_owned()),
            }],
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: CAPTURED_AT.to_owned(),
        })
        .expect("sealed R2 Evidence")
}

fn coverage(
    id: &str,
    capability: &str,
    dimension: ProviderCoverageDimension,
    state: CoverageState,
) -> CoverageRecord {
    CoverageRecord {
        schema_version: SCHEMA_V1.to_owned(),
        coverage_id: id.to_owned(),
        capability: capability.to_owned(),
        scope: ".".to_owned(),
        producer: Some("sentrdel.supabase.r3-t018-fixture".to_owned()),
        provider_dimension: Some(dimension),
        state,
        reason_code: None,
        details: Some("repository-derived provider coverage".to_owned()),
        input_digests: vec!["sha256:r2-canonical-input".to_owned()],
        observed_at: CAPTURED_AT.to_owned(),
    }
}

fn provider(evidence: Vec<Evidence>) -> SupabaseR2ProviderOutput {
    SupabaseR2ProviderOutput::new(
        evidence,
        vec![
            coverage(
                "coverage:r2:static-database",
                COVERAGE_STATIC_POSTURE_DATABASE,
                ProviderCoverageDimension::StaticPosture,
                CoverageState::Covered,
            ),
            coverage(
                "coverage:r2:live-gap",
                COVERAGE_LIVE_POSTURE,
                ProviderCoverageDimension::CredentialedLivePosture,
                CoverageState::Unavailable,
            ),
        ],
    )
    .expect("validated R2 provider output")
}

fn resource(subject: Option<&str>, name: &str) -> ResourceRef {
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some("public".to_owned()),
        name,
        ResourceKind::Table,
        subject.map(str::to_owned),
        BusinessLogicLimits::default(),
    )
    .expect("resource")
}

fn client(evidence_ids: Vec<String>, authority: ProviderAuthorityClass) -> ProviderClientAuthority {
    ProviderClientAuthority::new(
        semantic_id("r3-t018-client", "client"),
        "supabase",
        authority,
        evidence_ids,
        vec![source_location("src/server.ts")],
        BusinessLogicLimits::default(),
    )
    .expect("provider client")
}

#[test]
fn exact_r2_subject_match_preserves_canonical_evidence_identity_and_provenance() {
    let rls = evidence(
        "supabase_rls_posture",
        Some(("relation", "relation:public.accounts")),
        "supabase/migrations/20260905000100_accounts.sql",
    );
    let evidence_id = rls.evidence_id().to_owned();
    let output = provider(vec![rls]);
    let result = correlate_supabase_r2_support(
        &output,
        &[
            resource(Some("relation:public.accounts"), "accounts"),
            resource(Some("relation:public.account"), "account"),
        ],
        &[],
        R2SupportLimits::default(),
    )
    .expect("R2 support correlation");

    let matches = result
        .matches()
        .iter()
        .filter(|item| item.target_kind() == R2SupportTargetKind::ResourceSubject)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
    let matched = matches[0];
    assert_eq!(matched.target_id(), "relation:public.accounts");
    assert_eq!(matched.support_kind(), R2SupportKind::RlsPosture);
    assert_eq!(matched.evidence_id(), evidence_id);
    assert_eq!(matched.producer_id(), "sentrdel.supabase.r3-t018-fixture");
    assert_eq!(matched.subjects()[0].id, "relation:public.accounts");
    assert_eq!(
        matched.locations()[0].repo_relative_path,
        "supabase/migrations/20260905000100_accounts.sql"
    );
    assert_eq!(
        matched.input_digests(),
        &["sha256:r2-canonical-input".to_owned()]
    );
    assert!(result.diagnostics().iter().any(|item| {
        item.reason() == R2SupportDiagnosticReason::UnmatchedResourceSubject
            && item.subject() == Some("relation:public.account")
    }));
}

#[test]
fn lexical_resource_similarity_never_substitutes_for_r2_subject_identity() {
    let policy = evidence(
        "supabase_policy_posture",
        Some(("relation", "relation:public.accounts")),
        "supabase/migrations/20260905000100_accounts.sql",
    );
    let result = correlate_supabase_r2_support(
        &provider(vec![policy]),
        &[resource(None, "accounts")],
        &[],
        R2SupportLimits::default(),
    )
    .expect("R2 support correlation");

    assert!(result.matches().is_empty());
    assert!(result.diagnostics().is_empty());
}

#[test]
fn provider_client_requires_exact_canonical_evidence_id() {
    let key = evidence(
        "supabase_elevated_key_client_boundary",
        None,
        "src/server.ts",
    );
    let evidence_id = key.evidence_id().to_owned();
    let output = provider(vec![key]);
    let result = correlate_supabase_r2_support(
        &output,
        &[],
        &[
            client(
                vec![evidence_id.clone()],
                ProviderAuthorityClass::ServerUnknown,
            ),
            client(
                vec!["evidence:near-but-not-equal".to_owned()],
                ProviderAuthorityClass::ServerUnknown,
            ),
        ],
        R2SupportLimits::default(),
    )
    .expect("R2 support correlation");

    assert!(result.matches().iter().any(|item| {
        item.target_kind() == R2SupportTargetKind::ProviderClient
            && item.support_kind() == R2SupportKind::KeyClientBoundary
            && item.evidence_id() == evidence_id
    }));
    assert!(result.diagnostics().iter().any(|item| {
        item.reason() == R2SupportDiagnosticReason::UnmatchedClientEvidence
            && item.subject() == Some("evidence:near-but-not-equal")
    }));
}

#[test]
fn elevated_authority_never_uses_ordinary_rls_as_a_safety_guarantee() {
    let rls = evidence(
        "supabase_rls_posture",
        Some(("relation", "relation:public.accounts")),
        "supabase/migrations/20260905000100_accounts.sql",
    );
    let key = evidence(
        "supabase_elevated_key_client_boundary",
        None,
        "src/server.ts",
    );
    let key_id = key.evidence_id().to_owned();
    let result = correlate_supabase_r2_support(
        &provider(vec![rls, key]),
        &[resource(Some("relation:public.accounts"), "accounts")],
        &[client(
            vec![key_id],
            ProviderAuthorityClass::ElevatedSecretOrServiceRole,
        )],
        R2SupportLimits::default(),
    )
    .expect("R2 support correlation");

    assert!(result.diagnostics().iter().any(|item| {
        item.reason() == R2SupportDiagnosticReason::ElevatedAuthorityBypassesOrdinaryRls
    }));
    assert!(result.diagnostics().iter().any(|item| {
        item.reason() == R2SupportDiagnosticReason::StaticEvidenceDoesNotProveLivePosture
    }));
}

#[test]
fn canonical_coverage_is_preserved_without_t019_aggregation_or_live_upgrade() {
    let rls = evidence(
        "supabase_rls_posture",
        Some(("relation", "relation:public.accounts")),
        "supabase/migrations/20260905000100_accounts.sql",
    );
    let result = correlate_supabase_r2_support(
        &provider(vec![rls]),
        &[resource(Some("relation:public.accounts"), "accounts")],
        &[],
        R2SupportLimits::default(),
    )
    .expect("R2 support correlation");

    assert_eq!(result.coverage().len(), 2);
    assert_eq!(result.coverage()[0].coverage_id, "coverage:r2:live-gap");
    assert_eq!(result.coverage()[0].state, CoverageState::Unavailable);
    assert_eq!(result.coverage()[1].coverage_id, "coverage:r2:static-database");
    assert_eq!(result.coverage()[1].state, CoverageState::Covered);
}

#[test]
fn resource_caps_fail_closed_before_correlation() {
    let limits = R2SupportLimits {
        max_resources: 1,
        ..R2SupportLimits::default()
    };
    let error = correlate_supabase_r2_support(
        &provider(Vec::new()),
        &[resource(None, "one"), resource(None, "two")],
        &[],
        limits,
    )
    .expect_err("resource cap must fail closed");
    assert_eq!(
        error,
        R2SupportError::TooManyResources { count: 2, max: 1 }
    );
}

#[test]
fn t018_support_layer_has_no_execution_live_finding_or_confidence_authority() {
    const { assert!(!R2_SUPPORT_CREATES_FINDINGS) };
    const { assert!(!R2_SUPPORT_PROVES_LIVE_POSTURE) };
    const { assert!(!R2_SUPPORT_PROVIDER_NETWORK_ALLOWED) };
    const { assert!(!R2_SUPPORT_TARGET_EXECUTION_ALLOWED) };
    const { assert!(!R2_SUPPORT_CONFIDENCE_GRANTS_AUTHORITY) };
}
