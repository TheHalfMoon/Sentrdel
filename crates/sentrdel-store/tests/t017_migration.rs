use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::Connection;
use sentrdel_store::Store;

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t017-upgrade-{}-{sequence}.sqlite3",
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

#[test]
fn canonical_v1_database_upgrades_to_v2_without_losing_v1_state() {
    let temp = TempDb::new();
    let connection = Connection::open(&temp.path).expect("v1 fixture database should open");
    connection
        .execute_batch(
            r#"
            PRAGMA application_id = 1397642308;
            PRAGMA user_version = 1;
            CREATE TABLE sentrdel_schema_migrations (
                version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                name TEXT NOT NULL UNIQUE
            ) STRICT;
            INSERT INTO sentrdel_schema_migrations(version, name)
            VALUES (1, 'bootstrap_store_metadata');
            CREATE TABLE sentrdel_store_metadata (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL
            ) STRICT;
            INSERT INTO sentrdel_store_metadata(key, value)
            VALUES ('fixture', 'preserved');
            "#,
        )
        .expect("canonical v1 fixture should be created");
    drop(connection);

    let store = Store::open(&temp.path).expect("canonical v1 database should upgrade");
    assert_eq!(store.schema_version().expect("schema version"), 2);
    drop(store);

    let connection = Connection::open(&temp.path).expect("upgraded database should reopen");
    let ledger_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sentrdel_schema_migrations",
            [],
            |row| row.get(0),
        )
        .expect("migration ledger should be queryable");
    let preserved: String = connection
        .query_row(
            "SELECT value FROM sentrdel_store_metadata WHERE key = 'fixture'",
            [],
            |row| row.get(0),
        )
        .expect("v1 metadata should survive upgrade");
    let evidence_table_exists: i64 = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'sentrdel_evidence_objects')",
            [],
            |row| row.get(0),
        )
        .expect("v2 table should be discoverable");

    assert_eq!(ledger_count, 2);
    assert_eq!(preserved, "preserved");
    assert_eq!(evidence_table_exists, 1);
}
