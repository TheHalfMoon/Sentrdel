use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;
use sentrdel_schema::{
    SCHEMA_V1,
    evidence::{EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind},
};
use sentrdel_store::{Store, StoreError};

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t018-{label}-{}-{sequence}.sqlite3",
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

fn authority() -> EvidenceAuthority {
    EvidenceAuthority::from_runtime("t018-fixture", "1", ProducerKind::NativeRule)
        .expect("fixture authority")
}

#[test]
fn canonical_v2_state_upgrades_to_latest_without_losing_evidence() {
    let temp = TempDb::new("upgrade");
    let authority = authority();
    let evidence = authority
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:fixture-input".to_owned()],
            observation: "preserve across v2 upgrade".to_owned(),
            security_interpretation: None,
            category: "fixture".to_owned(),
            epistemic_class: EpistemicClass::Fact,
            confidence_band: None,
            subjects: Vec::new(),
            locations: Vec::new(),
            attributes: BTreeMap::new(),
            reproduction: None,
            captured_at: "2026-08-24T00:00:00Z".to_owned(),
        })
        .expect("fixture evidence");

    {
        let store = Store::open(&temp.path).expect("latest store opens");
        store.put_evidence(&evidence).expect("persist evidence");
    }

    // Build an exact canonical v2 state by removing every post-v2 object from
    // a database whose v1/v2 objects were created by the canonical code.
    let connection = Connection::open(&temp.path).expect("fixture database");
    connection
        .execute_batch(
            r#"
            DROP TABLE sentrdel_graph_edge_history;
            DROP TABLE sentrdel_graph_edge_projection;
            DROP TABLE sentrdel_graph_node_history;
            DROP TABLE sentrdel_graph_node_projection;
            DROP TABLE sentrdel_asel_events;
            DROP TABLE sentrdel_finding_history;
            DROP TABLE sentrdel_finding_projection;
            DROP TABLE sentrdel_state_objects;
            DROP TABLE sentrdel_project_profiles;
            DELETE FROM sentrdel_schema_migrations WHERE version >= 3;
            PRAGMA user_version = 2;
            "#,
        )
        .expect("downgrade fixture to canonical v2 objects");
    drop(connection);

    let store = Store::open(&temp.path).expect("canonical v2 database upgrades");
    assert_eq!(store.schema_version().expect("schema version"), 5);
    assert_eq!(
        store
            .get_evidence(evidence.evidence_id(), &authority)
            .expect("evidence lookup"),
        Some(evidence)
    );

    let connection = Connection::open(&temp.path).expect("upgraded database");
    let ledger_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sentrdel_schema_migrations",
            [],
            |row| row.get(0),
        )
        .expect("migration ledger");
    let v3_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name IN ('sentrdel_finding_projection', 'sentrdel_finding_history', 'sentrdel_state_objects', 'sentrdel_project_profiles')",
            [],
            |row| row.get(0),
        )
        .expect("v3 tables");
    let v4_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'sentrdel_asel_events'",
            [],
            |row| row.get(0),
        )
        .expect("v4 ASEL table");
    let v5_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name IN ('sentrdel_graph_node_projection', 'sentrdel_graph_node_history', 'sentrdel_graph_edge_projection', 'sentrdel_graph_edge_history')",
            [],
            |row| row.get(0),
        )
        .expect("v5 graph tables");
    assert_eq!(ledger_count, 5);
    assert_eq!(v3_table_count, 4);
    assert_eq!(v4_table_count, 1);
    assert_eq!(v5_table_count, 4);
}

#[test]
fn spoofed_v3_immutability_trigger_is_rejected_on_preflight() {
    let temp = TempDb::new("spoofed-trigger");
    {
        Store::open(&temp.path).expect("latest store opens");
    }

    let connection = Connection::open(&temp.path).expect("fixture database");
    connection
        .execute_batch(
            r#"
            DROP TRIGGER sentrdel_state_objects_immutable_update;
            CREATE TRIGGER sentrdel_state_objects_immutable_update
            BEFORE UPDATE ON sentrdel_state_objects
            WHEN 0
            BEGIN
                SELECT RAISE(ABORT, 'Sentrdel immutable state objects cannot be updated');
            END;
            "#,
        )
        .expect("install conditional spoof trigger");
    drop(connection);

    assert!(matches!(
        Store::open(&temp.path),
        Err(StoreError::MigrationIntegrity { version: 3, .. })
    ));
}
