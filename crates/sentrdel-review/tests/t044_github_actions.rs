use sentrdel_review::github_actions::{
    ActionsScanError, MAX_WORKFLOW_BYTES, scan_changed_workflow,
};
use sentrdel_review::view::NormalizedRepoPath;
use serde_json::Value;
use std::collections::BTreeSet;

fn path() -> NormalizedRepoPath {
    NormalizedRepoPath::parse(".github/workflows/security.yml", 256).unwrap()
}

fn rule_ids(evidence: &[sentrdel_schema::evidence::Evidence]) -> BTreeSet<&str> {
    evidence
        .iter()
        .map(|item| {
            item.claim().attributes["rule_id"]
                .as_str()
                .expect("rule id")
        })
        .collect()
}

#[test]
fn high_signal_workflow_covers_required_t044_surfaces() {
    let before = br#"
on:
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789012345678901234567890123456789
"#;
    let after = br#"
on:
  pull_request:
  pull_request_target:
  workflow_run:
permissions:
  contents: write
  id-token: write
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@v6
      - uses: actions/download-artifact@v5
      - uses: actions/cache@v5
      - run: echo "${{ github.event.pull_request.title }}"
      - run: deploy "${{ secrets.DEPLOY_TOKEN }}"
"#;

    let evidence =
        scan_changed_workflow(&path(), Some(before), after, "2026-08-28T00:00:00Z").expect("scan");
    let ids = rule_ids(&evidence);
    for required in [
        "gha.permission-widening",
        "gha.oidc-id-token-write",
        "gha.pull-request-target",
        "gha.secret-in-untrusted-pr-path",
        "gha.untrusted-expression-shell",
        "gha.mutable-action-ref",
        "gha.self-hosted-runner-change",
        "gha.trust-sensitive-artifact-cache-handoff",
    ] {
        assert!(ids.contains(required), "missing {required}: {ids:?}");
    }
    assert!(evidence.iter().all(|item| {
        item.claim().epistemic_class == sentrdel_schema::evidence::EpistemicClass::Fact
            && item.claim().security_interpretation.is_none()
    }));
}

#[test]
fn unchanged_or_sha_pinned_safe_workflow_avoids_high_signal_observations() {
    let source = br#"
on:
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789012345678901234567890123456789
      - run: echo "fixed input"
"#;
    let evidence =
        scan_changed_workflow(&path(), Some(source), source, "2026-08-28T00:00:00Z").expect("scan");
    assert!(evidence.is_empty());
}

#[test]
fn write_permission_and_self_hosted_are_change_relative() {
    let before = br#"
on: push
permissions:
  contents: write
jobs:
  test:
    runs-on: self-hosted
    steps: []
"#;
    let after = before;
    let evidence =
        scan_changed_workflow(&path(), Some(before), after, "2026-08-28T00:00:00Z").expect("scan");
    let ids = rule_ids(&evidence);
    assert!(!ids.contains("gha.permission-widening"));
    assert!(!ids.contains("gha.self-hosted-runner-change"));
}

#[test]
fn pull_request_secret_and_privileged_handoff_are_context_sensitive() {
    let ordinary = br#"
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v5
      - run: echo "${{ secrets.SAFE_FOR_PUSH }}"
"#;
    let evidence =
        scan_changed_workflow(&path(), None, ordinary, "2026-08-28T00:00:00Z").expect("scan");
    let ids = rule_ids(&evidence);
    assert!(!ids.contains("gha.secret-in-untrusted-pr-path"));
    assert!(!ids.contains("gha.trust-sensitive-artifact-cache-handoff"));
}

#[test]
fn persisted_evidence_never_copies_expression_or_secret_identifier() {
    let source = br#"
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.body }} ${{ secrets.TOP_SECRET_NAME }}"
"#;
    let evidence =
        scan_changed_workflow(&path(), None, source, "2026-08-28T00:00:00Z").expect("scan");
    let serialized = serde_json::to_string(&evidence).unwrap();
    assert!(!serialized.contains("TOP_SECRET_NAME"));
    assert!(!serialized.contains("github.event.pull_request.body"));
    assert!(!serialized.contains("${{"));
    let values: Vec<Value> = serde_json::from_str(&serialized).unwrap();
    assert!(!values.is_empty());
}

#[test]
fn non_workflow_non_utf8_oversized_and_empty_timestamp_fail_closed() {
    let non_workflow = NormalizedRepoPath::parse("ci/workflow.yml", 256).unwrap();
    assert!(matches!(
        scan_changed_workflow(&non_workflow, None, b"on: push", "2026-08-28T00:00:00Z"),
        Err(ActionsScanError::NotWorkflowPath)
    ));
    assert!(matches!(
        scan_changed_workflow(&path(), None, &[0xff], "2026-08-28T00:00:00Z"),
        Err(ActionsScanError::NonUtf8Source)
    ));
    let oversized = vec![b'x'; MAX_WORKFLOW_BYTES + 1];
    assert!(matches!(
        scan_changed_workflow(&path(), None, &oversized, "2026-08-28T00:00:00Z"),
        Err(ActionsScanError::DocumentTooLarge { .. })
    ));
    assert!(matches!(
        scan_changed_workflow(&path(), None, b"on: push", " "),
        Err(ActionsScanError::EmptyCapturedAt)
    ));
}
