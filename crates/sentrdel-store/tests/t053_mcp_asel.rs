use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sentrdel_schema::{
    SCHEMA_V1,
    asel::{Actor, ActorType, AgentSecurityEvent, AgentSecurityEventDraft, EventKind, SessionIntegrity},
};
use sentrdel_store::Store;

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t053-{label}-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        cleanup_database_files(&path);
        Self { path }
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        cleanup_database_files(&self.path);
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn cleanup_database_files(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove temporary SQLite file: {error}"),
        }
    }
}

fn event(
    session_id: &str,
    sequence: u64,
    previous_event_hash: Option<String>,
    kind: EventKind,
    timestamp: &str,
    result_digest: Option<&str>,
) -> AgentSecurityEvent {
    let mut target = BTreeMap::new();
    target.insert("mcp.server".to_owned(), "fixture-server".to_owned());
    target.insert("mcp.tool".to_owned(), "fixture-tool".to_owned());

    let mut provenance = BTreeMap::new();
    provenance.insert("transport".to_owned(), "stdio".to_owned());
    provenance.insert("authority".to_owned(), "sentrdel-guard".to_owned());

    AgentSecurityEventDraft {
        schema_version: SCHEMA_V1.to_owned(),
        session_id: session_id.to_owned(),
        sequence,
        timestamp: timestamp.to_owned(),
        actor: Actor {
            actor_type: ActorType::System,
            id: "sentrdel-mcp-guard".to_owned(),
            vendor: None,
            version: None,
        },
        kind,
        intent_digest: Some("sha256:mcp-intent-fixture".to_owned()),
        target,
        params_digest: Some("sha256:mcp-params-fixture".to_owned()),
        result_digest: result_digest.map(str::to_owned),
        policy_decision: None,
        provenance,
        previous_event_hash,
    }
    .seal()
    .expect("T053 fixture event should seal")
}

#[test]
fn mcp_lifecycle_events_persist_in_one_verifiable_session_chain() {
    let temp = TempDb::new("lifecycle");
    let mut store = Store::open(&temp.path).expect("store should open");
    let session = "mcp-session-t053";
    let kinds = [
        EventKind::McpDiscovery,
        EventKind::McpInvocation,
        EventKind::Approval,
        EventKind::Denial,
        EventKind::ToolResult,
    ];

    let mut previous = None;
    let mut expected_hashes = Vec::new();
    for (index, kind) in kinds.into_iter().enumerate() {
        let timestamp = format!("2026-08-28T22:20:0{index}Z");
        let result_digest = matches!(kind, EventKind::ToolResult)
            .then_some("sha256:mcp-result-fixture");
        let event = event(
            session,
            index as u64,
            previous.clone(),
            kind,
            &timestamp,
            result_digest,
        );
        assert!(store.append_asel_event(&event).expect("append event"));
        previous = Some(event.event_hash().to_owned());
        expected_hashes.push(event.event_hash().to_owned());
    }

    assert_eq!(store.asel_event_count(session).expect("event count"), 5);
    assert_eq!(
        store.asel_session_head(session).expect("session head"),
        expected_hashes.last().cloned()
    );

    for (sequence, expected_hash) in expected_hashes.iter().enumerate() {
        let record = store
            .get_asel_event_record(session, sequence as u64)
            .expect("event lookup")
            .expect("persisted event");
        assert_eq!(&record.event_hash, expected_hash);
    }
}

#[test]
fn local_head_is_reported_without_claiming_tamper_proof_integrity() {
    let temp = TempDb::new("head-semantics");
    let mut store = Store::open(&temp.path).expect("store should open");
    let session = "mcp-session-head";
    let root = event(
        session,
        0,
        None,
        EventKind::McpDiscovery,
        "2026-08-28T22:21:00Z",
        None,
    );
    store.append_asel_event(&root).expect("append root");

    let local = store
        .verify_asel_session(session, None)
        .expect("local verification");
    assert_eq!(local.integrity, SessionIntegrity::NoTrustedHead);
    assert_eq!(local.event_count, 1);
    assert_eq!(local.computed_head.as_deref(), Some(root.event_hash()));

    let expected = store
        .verify_asel_session(session, Some(root.event_hash()))
        .expect("expected-head verification");
    assert_eq!(
        expected.integrity,
        SessionIntegrity::ValidRelativeToProvidedHead
    );

    let mismatched = store
        .verify_asel_session(
            session,
            Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )
        .expect("mismatched expected-head verification");
    assert_eq!(mismatched.integrity, SessionIntegrity::TrustedHeadMismatch);
}
