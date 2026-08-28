use sentrdel_review::secrets::{MAX_SECRET_SCAN_BYTES, SecretScanError, scan_changed_secrets};
use sentrdel_review::view::NormalizedRepoPath;

const CAPTURED_AT: &str = "2026-08-28T18:00:00Z";
const GITHUB_PAT_A: &str = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const GITHUB_PAT_B: &str = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const AWS_KEY: &str = "AKIA1234567890ABCDEF";

fn path() -> NormalizedRepoPath {
    NormalizedRepoPath::parse("src/config.js", 128).unwrap()
}

#[test]
fn changed_secret_evidence_is_redacted_before_serialization() {
    let source = format!("const token = \"{GITHUB_PAT_A}\";\nconst key = \"{AWS_KEY}\";\n");
    let evidence = scan_changed_secrets(&path(), source.as_bytes(), CAPTURED_AT).unwrap();
    assert_eq!(evidence.len(), 2);

    let serialized = serde_json::to_string(
        &evidence
            .iter()
            .map(|item| item.to_record())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!serialized.contains(GITHUB_PAT_A));
    assert!(!serialized.contains(AWS_KEY));
    assert!(serialized.contains("[REDACTED:github_classic_pat]"));
    assert!(serialized.contains("[REDACTED:aws_access_key_id]"));
    assert!(!serialized.contains("content_digest"));
}

#[test]
fn sanitized_fingerprint_is_independent_of_secret_value() {
    let first = format!("const token = \"{GITHUB_PAT_A}\";\n");
    let second = format!("const token = \"{GITHUB_PAT_B}\";\n");
    let a = scan_changed_secrets(&path(), first.as_bytes(), CAPTURED_AT).unwrap();
    let b = scan_changed_secrets(&path(), second.as_bytes(), CAPTURED_AT).unwrap();

    let a_fingerprint = a[0].claim().attributes["sanitized_fingerprint"].as_str().unwrap();
    let b_fingerprint = b[0].claim().attributes["sanitized_fingerprint"].as_str().unwrap();
    assert_eq!(a_fingerprint, b_fingerprint);
    assert_eq!(a[0].claim().input_digests, Vec::<String>::new());
    assert!(a[0].claim().locations[0].content_digest.is_none());
}

#[test]
fn malformed_near_misses_do_not_emit_evidence() {
    let source = b"const a = 'ghp_short';\nconst b = 'Xghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';\nconst c = 'AKIA1234-lower-not-key';\n";
    assert!(scan_changed_secrets(&path(), source, CAPTURED_AT)
        .unwrap()
        .is_empty());
}

#[test]
fn evidence_locations_and_order_are_deterministic() {
    let source = format!("let b = \"{AWS_KEY}\";\nlet a = \"{GITHUB_PAT_A}\";\n");
    let first = scan_changed_secrets(&path(), source.as_bytes(), CAPTURED_AT).unwrap();
    let second = scan_changed_secrets(&path(), source.as_bytes(), CAPTURED_AT).unwrap();
    assert_eq!(first, second);
    assert_eq!(first[0].claim().locations[0].start_line, Some(1));
    assert_eq!(first[1].claim().locations[0].start_line, Some(2));
    assert!(first.iter().all(|item| item.claim().security_interpretation.is_none()));
}

#[test]
fn non_utf8_oversized_and_empty_timestamp_fail_closed() {
    assert!(matches!(
        scan_changed_secrets(&path(), &[0xff], CAPTURED_AT),
        Err(SecretScanError::NonUtf8Source)
    ));
    assert!(matches!(
        scan_changed_secrets(&path(), &vec![b'x'; MAX_SECRET_SCAN_BYTES + 1], CAPTURED_AT),
        Err(SecretScanError::DocumentTooLarge { .. })
    ));
    assert!(matches!(
        scan_changed_secrets(&path(), b"safe", "   "),
        Err(SecretScanError::EmptyCapturedAt)
    ));
}
