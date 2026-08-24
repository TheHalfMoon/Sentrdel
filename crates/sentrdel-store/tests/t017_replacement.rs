use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{Connection, params};
use sentrdel_schema::{
    SCHEMA_V1,
    evidence::{EpistemicClass, EvidenceAuthority, EvidenceClaim, ProducerKind},
};
use sentrdel_store::Store;

static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "sentrdel-t017-replace-{}-{sequence}.sqlite3",
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
fn insert_or_replace_cannot_change_existing_evidence_bytes() {
    let temp = TempDb::new();
    let store = Store::open(&temp.path).expect("store should open");
    let authority =
        EvidenceAuthority::from_runtime("replacement-fixture", "1", ProducerKind::NativeRule)
            .expect("fixture authority");
    let evidence = authority
        .seal(EvidenceClaim {
            schema_version: SCHEMA_V1.to_owned(),
            input_digests: vec!["sha256:fixture-input".to_owned()],
            observation: "immutable replacement target".to_owned(),
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
    store.put_evidence(&evidence).expect("initial persistence");

    let connection = Connection::open(&temp.path).expect("direct SQLite fixture connection");
    let replaced = connection
        .execute(
            "INSERT OR REPLACE INTO sentrdel_evidence_objects(evidence_id, canonical_json) VALUES (?1, ?2)",
            params![evidence.evidence_id(), b"{}".as_slice()],
        )
        .expect("reinsert guard should ignore replacement rather than mutate");
    assert_eq!(replaced, 0);
    drop(connection);

    let loaded = store
        .get_evidence(evidence.evidence_id(), &authority)
        .expect("stored Evidence should remain valid")
        .expect("stored Evidence should remain present");
    assert_eq!(loaded, evidence);
}
