use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{Connection, params};
use sentrdel_schema::{
    SCHEMA_V1,
    asel::{
        Actor, ActorType, AgentSecurityEvent, AgentSecurityEventDraft, EventKind, SessionIntegrity,
    },
    policy::{
        EnforcementFidelity, PolicyDecision, PolicyDecisionClaim, TrustedPolicyAuthority, Verdict,
    },
    project::ProjectProfile,
};
use sentrdel_store::{Store, StoreError, asel::AselStoreError};

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t020-{label}-{}-{sequence}.sqlite3",
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
    timestamp: &str,
) -> AgentSecurityEvent {
    AgentSecurityEventDraft {
        schema_version: SCHEMA_V1.to_owned(),
        session_id: session_id.to_owned(),
        sequence,
        timestamp: timestamp.to_owned(),
        actor: Actor {
            actor_type: ActorType::System,
            id: "sentrdel-t020-fixture".to_owned(),
            vendor: None,
            version: None,
        },
        kind: EventKind::McpDiscovery,
        intent_digest: None,
        target: BTreeMap::new(),
        params_digest: None,
        result_digest: None,
        policy_decision: None,
        provenance: BTreeMap::new(),
        previous_event_hash,
    }
    .seal()
    .expect("fixture ASEL event should seal")
}

fn event_with_target(
    session_id: &str,
    sequence: u64,
    previous_event_hash: Option<String>,
    target_value: &str,
) -> AgentSecurityEvent {
    let mut target = BTreeMap::new();
    target.insert("resource".to_owned(), target_value.to_owned());
    AgentSecurityEventDraft {
        schema_version: SCHEMA_V1.to_owned(),
        session_id: session_id.to_owned(),
        sequence,
        timestamp: "2026-08-24T17:00:00Z".to_owned(),
        actor: Actor {
            actor_type: ActorType::System,
            id: "sentrdel-t020-fixture".to_owned(),
            vendor: None,
            version: None,
        },
        kind: EventKind::FileRead,
        intent_digest: None,
        target,
        params_digest: None,
        result_digest: None,
        policy_decision: None,
        provenance: BTreeMap::new(),
        previous_event_hash,
    }
    .seal()
    .expect("fixture ASEL event should seal")
}

#[test]
fn append_is_atomic_idempotent_and_distinguishes_local_from_trusted_head() {
    let temp = TempDb::new("append-chain");
    let mut store = Store::open(&temp.path).expect("store should open");

    let root = event("session-a", 0, None, "2026-08-24T17:00:00Z");
    assert!(store.append_asel_event(&root).expect("root append"));
    assert!(!store.append_asel_event(&root).expect("root replay"));

    let second = event(
        "session-a",
        1,
        Some(root.event_hash().to_owned()),
        "2026-08-24T17:00:01Z",
    );
    assert!(store.append_asel_event(&second).expect("second append"));

    assert_eq!(store.asel_event_count("session-a").expect("count"), 2);
    assert_eq!(
        store
            .asel_session_head("session-a")
            .expect("head")
            .as_deref(),
        Some(second.event_hash())
    );

    let first_record = store
        .get_asel_event_record("session-a", 0)
        .expect("root lookup")
        .expect("root record");
    assert_eq!(first_record.event_hash, root.event_hash());
    assert_eq!(first_record.sequence, 0);

    let local = store
        .verify_asel_session("session-a", None)
        .expect("local verification");
    assert_eq!(local.integrity, SessionIntegrity::NoTrustedHead);
    assert_eq!(local.event_count, 2);
    assert_eq!(local.computed_head.as_deref(), Some(second.event_hash()));

    let trusted = store
        .verify_asel_session("session-a", Some(second.event_hash()))
        .expect("trusted verification");
    assert_eq!(
        trusted.integrity,
        SessionIntegrity::ValidRelativeToProvidedHead
    );

    let mismatched = store
        .verify_asel_session(
            "session-a",
            Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )
        .expect("mismatched trusted verification");
    assert_eq!(mismatched.integrity, SessionIntegrity::TrustedHeadMismatch);

    drop(store);
    let reopened = Store::open(&temp.path).expect("store should reopen");
    assert_eq!(
        reopened
            .asel_event_count("session-a")
            .expect("reopen count"),
        2
    );
    assert_eq!(
        reopened
            .verify_asel_session("session-a", None)
            .expect("reopen verification")
            .integrity,
        SessionIntegrity::NoTrustedHead
    );
}

#[test]
fn replay_rejects_tampered_stored_row_instead_of_masking_corruption() {
    let temp = TempDb::new("tampered-replay");
    let mut store = Store::open(&temp.path).expect("store should open");
    let root = event("session-tamper", 0, None, "2026-08-24T17:05:00Z");
    store.append_asel_event(&root).expect("root append");
    let second = event(
        "session-tamper",
        1,
        Some(root.event_hash().to_owned()),
        "2026-08-24T17:05:01Z",
    );
    store.append_asel_event(&second).expect("second append");

    let connection = Connection::open(&temp.path).expect("tamper fixture database");
    connection
        .execute_batch("DROP TRIGGER sentrdel_asel_immutable_update;")
        .expect("remove update guard only for corruption fixture");
    connection
        .execute(
            "UPDATE sentrdel_asel_events SET previous_event_hash = ?1 WHERE session_id = ?2 AND sequence = 1",
            params![
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "session-tamper"
            ],
        )
        .expect("tamper previous hash column");
    drop(connection);

    assert!(matches!(
        store.append_asel_event(&second),
        Err(AselStoreError::CorruptStoredEvent { sequence: 1, .. })
    ));
}

#[test]
fn gaps_wrong_links_and_conflicting_replays_fail_without_advancing_session() {
    let temp = TempDb::new("append-rejections");
    let mut store = Store::open(&temp.path).expect("store should open");
    let root = event("session-b", 0, None, "2026-08-24T17:10:00Z");
    store.append_asel_event(&root).expect("root append");

    let gap = event(
        "session-b",
        2,
        Some(root.event_hash().to_owned()),
        "2026-08-24T17:10:02Z",
    );
    assert!(matches!(
        store.append_asel_event(&gap),
        Err(AselStoreError::SequenceMismatch {
            expected: 1,
            found: 2,
            ..
        })
    ));

    let wrong_link = event(
        "session-b",
        1,
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned()),
        "2026-08-24T17:10:01Z",
    );
    assert!(matches!(
        store.append_asel_event(&wrong_link),
        Err(AselStoreError::PreviousHashMismatch { sequence: 1, .. })
    ));

    let conflicting_root = event("session-b", 0, None, "2026-08-24T17:10:09Z");
    assert!(matches!(
        store.append_asel_event(&conflicting_root),
        Err(AselStoreError::AppendConflict { sequence: 0, .. })
    ));

    assert_eq!(store.asel_event_count("session-b").expect("count"), 1);
    assert_eq!(
        store
            .asel_session_head("session-b")
            .expect("head")
            .as_deref(),
        Some(root.event_hash())
    );
}

#[test]
fn registered_secret_material_is_rejected_before_asel_sqlite_persistence() {
    let temp = TempDb::new("redaction");
    let mut store = Store::open(&temp.path).expect("store should open");
    let canary = "t020-super-secret-canary";
    store
        .register_discovered_secret(canary)
        .expect("register canary");

    let unsafe_event = event_with_target("session-secret", 0, None, canary);
    assert!(matches!(
        store.append_asel_event(&unsafe_event),
        Err(AselStoreError::Redaction(_))
    ));
    assert_eq!(
        store
            .asel_event_count("session-secret")
            .expect("secret session count"),
        0
    );
}

#[test]
fn policy_bearing_event_round_trips_through_stored_event_hash_verification() {
    let temp = TempDb::new("policy-event");
    let mut store = Store::open(&temp.path).expect("store should open");
    let authority = TrustedPolicyAuthority::from_runtime("t020-policy", "sha256:config");
    let claim = PolicyDecisionClaim {
        schema_version: SCHEMA_V1.to_owned(),
        verdict: Verdict::Deny,
        enforcement_fidelity: EnforcementFidelity::Enforced,
        reason_codes: vec!["fixture-deny".to_owned()],
        rule_ids: vec!["T020-FIXTURE".to_owned()],
        kernel_invariant_ids: vec!["fixture-kernel".to_owned()],
        policy_version_digests: vec!["sha256:policy".to_owned()],
        action_digest: "sha256:action".to_owned(),
        decided_at: "2026-08-24T17:20:00Z".to_owned(),
    };
    let decision = PolicyDecision::bind(claim, "sha256:action", &authority)
        .expect("fixture policy decision should bind");
    let event = AgentSecurityEventDraft {
        schema_version: SCHEMA_V1.to_owned(),
        session_id: "session-policy".to_owned(),
        sequence: 0,
        timestamp: "2026-08-24T17:20:00Z".to_owned(),
        actor: Actor {
            actor_type: ActorType::System,
            id: "sentrdel-t020-fixture".to_owned(),
            vendor: None,
            version: None,
        },
        kind: EventKind::Denial,
        intent_digest: Some("sha256:intent".to_owned()),
        target: BTreeMap::new(),
        params_digest: Some("sha256:params".to_owned()),
        result_digest: None,
        policy_decision: Some(decision),
        provenance: BTreeMap::new(),
        previous_event_hash: None,
    }
    .seal()
    .expect("policy event should seal");

    store
        .append_asel_event(&event)
        .expect("policy event append");
    let record = store
        .get_asel_event_record("session-policy", 0)
        .expect("policy record lookup")
        .expect("policy record");
    assert_eq!(record.event_hash, event.event_hash());
    assert!(record.policy_decision.is_some());
    assert_eq!(
        store
            .verify_asel_session("session-policy", None)
            .expect("policy session verify")
            .integrity,
        SessionIntegrity::NoTrustedHead
    );
}

#[test]
fn canonical_v3_store_upgrades_to_v4_and_preserves_prior_state() {
    let temp = TempDb::new("v3-upgrade");
    let prior_profile = ProjectProfile {
        schema_version: SCHEMA_V1.to_owned(),
        repository_id: "repo:t020-v3".to_owned(),
        repository_root_digest: "sha256:t020-v3-root".to_owned(),
        languages: vec!["Rust".to_owned()],
        package_ecosystems: vec!["cargo".to_owned()],
        ci_systems: Vec::new(),
        mcp_configurations: Vec::new(),
        detected_providers: Vec::new(),
        detected_frameworks: Vec::new(),
        security_packs: Vec::new(),
        created_at: "2026-08-24T17:30:00Z".to_owned(),
        refreshed_at: "2026-08-24T17:30:00Z".to_owned(),
    };
    {
        let store = Store::open(&temp.path).expect("latest store opens");
        assert!(
            store
                .put_project_profile(&prior_profile)
                .expect("seed prior v3-compatible state")
        );
    }

    let connection = Connection::open(&temp.path).expect("fixture database");
    connection
        .execute_batch(
            r#"
            DROP TABLE sentrdel_asel_events;
            DELETE FROM sentrdel_schema_migrations WHERE version = 4;
            PRAGMA user_version = 3;
            "#,
        )
        .expect("downgrade fixture to canonical v3");
    drop(connection);

    let store = Store::open(&temp.path).expect("canonical v3 upgrades to v4");
    assert_eq!(store.schema_version().expect("schema version"), 4);
    let restored = store
        .get_project_profile("repo:t020-v3")
        .expect("read prior state after v4 migration")
        .expect("prior profile survives migration");
    assert_eq!(restored, prior_profile);
    assert_eq!(store.asel_event_count("missing").expect("empty count"), 0);
}

#[test]
fn spoofed_v4_append_guard_is_rejected_on_preflight() {
    let temp = TempDb::new("spoofed-v4-trigger");
    {
        Store::open(&temp.path).expect("latest store opens");
    }

    let connection = Connection::open(&temp.path).expect("fixture database");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER sentrdel_asel_append_guard;
            CREATE TRIGGER sentrdel_asel_append_guard
            BEFORE INSERT ON sentrdel_asel_events
            WHEN 0
            BEGIN
                SELECT RAISE(ABORT, 'Sentrdel ASEL events must append to the exact session head');
            END;
            "#,
        )
        .expect("install spoofed ASEL append guard");
    drop(connection);

    assert!(matches!(
        Store::open(&temp.path),
        Err(StoreError::MigrationIntegrity { version: 4, .. })
    ));
}
