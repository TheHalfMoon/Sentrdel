use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sentrdel_schema::{
    SCHEMA_V1,
    asel::{
        Actor, ActorType, AgentSecurityEvent, AgentSecurityEventDraft, EventKind, SessionIntegrity,
    },
};
use sentrdel_store::Store;

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb(PathBuf);

impl TempDb {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t058-mcp-e2e-{}-{sequence}.sqlite3",
            std::process::id()
        ));
        cleanup_database_files(&path);
        Self(path)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        cleanup_database_files(&self.0);
    }
}

fn cleanup_database_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let candidate = PathBuf::from(format!("{}{}", path.display(), suffix));
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to remove temporary T058 database: {error}"),
        }
    }
}

fn asel_event(
    session_id: &str,
    sequence: u64,
    previous_event_hash: Option<String>,
    kind: EventKind,
) -> AgentSecurityEvent {
    let mut target = BTreeMap::new();
    target.insert("mcp.server".to_owned(), "sentrdel-t058-server".to_owned());
    target.insert("mcp.tool".to_owned(), "read_file".to_owned());

    let mut provenance = BTreeMap::new();
    provenance.insert("transport".to_owned(), "stdio".to_owned());
    provenance.insert("fixture".to_owned(), "t058".to_owned());

    AgentSecurityEventDraft {
        schema_version: SCHEMA_V1.to_owned(),
        session_id: session_id.to_owned(),
        sequence,
        timestamp: format!("2026-08-29T00:00:0{sequence}Z"),
        actor: Actor {
            actor_type: ActorType::System,
            id: "sentrdel-mcp-guard".to_owned(),
            vendor: None,
            version: None,
        },
        kind,
        intent_digest: Some("sha256:t058-intent".to_owned()),
        target,
        params_digest: Some("sha256:t058-params".to_owned()),
        result_digest: (kind == EventKind::ToolResult).then(|| "sha256:t058-result".to_owned()),
        policy_decision: None,
        provenance,
        previous_event_hash,
    }
    .seal()
    .expect("T058 ASEL event should seal")
}

#[test]
fn e2e_stdio_session_has_verifiable_asel_head_without_tamper_proof_overclaim() {
    let temp = TempDb::new();
    let mut store = Store::open(&temp.0).expect("store should open");
    let session = "t058-stdio-session";
    let mut previous = None;

    for (sequence, kind) in [
        EventKind::McpDiscovery,
        EventKind::McpInvocation,
        EventKind::ToolResult,
    ]
    .into_iter()
    .enumerate()
    {
        let event = asel_event(session, sequence as u64, previous.clone(), kind);
        assert!(store.append_asel_event(&event).expect("append ASEL event"));
        previous = Some(event.event_hash().to_owned());
    }

    let expected_head = previous.expect("session head");
    let local = store
        .verify_asel_session(session, None)
        .expect("local chain verification");
    assert_eq!(local.integrity, SessionIntegrity::NoTrustedHead);
    assert_eq!(local.event_count, 3);
    assert_eq!(local.computed_head.as_deref(), Some(expected_head.as_str()));

    let trusted = store
        .verify_asel_session(session, Some(&expected_head))
        .expect("trusted-head verification");
    assert_eq!(
        trusted.integrity,
        SessionIntegrity::ValidRelativeToProvidedHead
    );

    let mismatch = store
        .verify_asel_session(
            session,
            Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )
        .expect("mismatch verification");
    assert_eq!(mismatch.integrity, SessionIntegrity::TrustedHeadMismatch);
}
