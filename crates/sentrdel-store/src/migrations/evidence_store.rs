use std::{error::Error, fmt};

use rusqlite::{OptionalExtension, params};
use sentrdel_schema::{
    canonical::{CanonicalError, canonical_json_bytes},
    evidence::{Evidence, EvidenceAuthority, EvidenceRecord, EvidenceValidationError},
};

use crate::Store;

pub type EvidenceStoreResult<T> = Result<T, EvidenceStoreError>;

#[derive(Debug)]
pub enum EvidenceStoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Canonical(CanonicalError),
    EvidenceValidation(EvidenceValidationError),
    IdentityVerificationFailed {
        evidence_id: String,
    },
    ImmutableConflict {
        evidence_id: String,
    },
    CorruptStoredObject {
        evidence_id: String,
        detail: &'static str,
    },
}

impl fmt::Display for EvidenceStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite evidence-store error: {error}"),
            Self::Json(error) => write!(formatter, "stored Evidence JSON is invalid: {error}"),
            Self::Canonical(error) => write!(formatter, "Evidence canonicalization failed: {error}"),
            Self::EvidenceValidation(error) => {
                write!(formatter, "stored Evidence failed authority validation: {error}")
            }
            Self::IdentityVerificationFailed { evidence_id } => write!(
                formatter,
                "refusing Evidence whose canonical identity does not verify: {evidence_id}"
            ),
            Self::ImmutableConflict { evidence_id } => write!(
                formatter,
                "immutable Evidence id already exists with different canonical bytes: {evidence_id}"
            ),
            Self::CorruptStoredObject {
                evidence_id,
                detail,
            } => write!(
                formatter,
                "stored Evidence object {evidence_id} failed integrity validation: {detail}"
            ),
        }
    }
}

impl Error for EvidenceStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::EvidenceValidation(error) => Some(error),
            Self::IdentityVerificationFailed { .. }
            | Self::ImmutableConflict { .. }
            | Self::CorruptStoredObject { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for EvidenceStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for EvidenceStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<CanonicalError> for EvidenceStoreError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<EvidenceValidationError> for EvidenceStoreError {
    fn from(error: EvidenceValidationError) -> Self {
        Self::EvidenceValidation(error)
    }
}

impl Store {
    /// Persist sealed Evidence by canonical SHA-256 id.
    ///
    /// Returns `true` when a new immutable object was inserted and `false` for
    /// an idempotent replay of byte-identical canonical Evidence.
    pub fn put_evidence(&self, evidence: &Evidence) -> EvidenceStoreResult<bool> {
        if !evidence.verify_identity()? {
            return Err(EvidenceStoreError::IdentityVerificationFailed {
                evidence_id: evidence.evidence_id().to_owned(),
            });
        }

        let record = evidence.to_record();
        let canonical = canonical_json_bytes(&record)?;
        let evidence_id = evidence.evidence_id();

        let inserted = self.connection.execute(
            "INSERT INTO sentrdel_evidence_objects(evidence_id, canonical_json) VALUES (?1, ?2) ON CONFLICT(evidence_id) DO NOTHING",
            params![evidence_id, canonical],
        )?;

        if inserted == 1 {
            return Ok(true);
        }

        let existing: Vec<u8> = self.connection.query_row(
            "SELECT canonical_json FROM sentrdel_evidence_objects WHERE evidence_id = ?1",
            params![evidence_id],
            |row| row.get(0),
        )?;

        if existing != canonical {
            return Err(EvidenceStoreError::ImmutableConflict {
                evidence_id: evidence_id.to_owned(),
            });
        }

        Ok(false)
    }

    /// Load immutable Evidence only after canonical-byte, id, and runtime
    /// producer-authority validation succeeds.
    pub fn get_evidence(
        &self,
        evidence_id: &str,
        authority: &EvidenceAuthority,
    ) -> EvidenceStoreResult<Option<Evidence>> {
        let stored: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT canonical_json FROM sentrdel_evidence_objects WHERE evidence_id = ?1",
                params![evidence_id],
                |row| row.get(0),
            )
            .optional()?;

        let Some(stored) = stored else {
            return Ok(None);
        };

        let record: EvidenceRecord = serde_json::from_slice(&stored)?;
        if record.evidence_id != evidence_id {
            return Err(EvidenceStoreError::CorruptStoredObject {
                evidence_id: evidence_id.to_owned(),
                detail: "row key does not match the Evidence record id",
            });
        }

        let recanonical = canonical_json_bytes(&record)?;
        if recanonical != stored {
            return Err(EvidenceStoreError::CorruptStoredObject {
                evidence_id: evidence_id.to_owned(),
                detail: "stored bytes are not canonical JSON",
            });
        }

        let evidence = Evidence::try_from_record(record, authority)?;
        if evidence.evidence_id() != evidence_id || !evidence.verify_identity()? {
            return Err(EvidenceStoreError::CorruptStoredObject {
                evidence_id: evidence_id.to_owned(),
                detail: "Evidence identity verification failed after load",
            });
        }

        Ok(Some(evidence))
    }

    /// Check whether an immutable Evidence object exists without interpreting it.
    pub fn contains_evidence(&self, evidence_id: &str) -> EvidenceStoreResult<bool> {
        let exists: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sentrdel_evidence_objects WHERE evidence_id = ?1)",
            params![evidence_id],
            |row| row.get(0),
        )?;
        Ok(exists == 1)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::{Connection, params};
    use sentrdel_schema::{
        SCHEMA_V1,
        evidence::{
            EpistemicClass, Evidence, EvidenceAuthority, EvidenceClaim, ProducerKind,
        },
    };

    use super::EvidenceStoreError;
    use crate::Store;

    static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sentrdel-evidence-{label}-{}-{sequence}.sqlite3",
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
        EvidenceAuthority::from_runtime("native-fixture", "1", ProducerKind::NativeRule)
            .expect("fixture authority")
    }

    fn evidence(authority: &EvidenceAuthority, observation: &str) -> Evidence {
        authority
            .seal(EvidenceClaim {
                schema_version: SCHEMA_V1.to_owned(),
                input_digests: vec!["sha256:fixture-input".to_owned()],
                observation: observation.to_owned(),
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
            .expect("fixture evidence")
    }

    fn immutable_update_trigger_sql() -> &'static str {
        r#"
        CREATE TRIGGER sentrdel_evidence_immutable_update
        BEFORE UPDATE ON sentrdel_evidence_objects
        BEGIN
            SELECT RAISE(ABORT, 'Sentrdel Evidence objects are immutable');
        END;
        "#
    }

    #[test]
    fn insert_lookup_and_replay_are_idempotent() {
        let temp = TempDb::new("idempotent");
        let store = Store::open(&temp.path).expect("store opens");
        let authority = authority();
        let evidence = evidence(&authority, "bounded observation");

        assert!(store.put_evidence(&evidence).expect("first insert"));
        assert!(!store.put_evidence(&evidence).expect("idempotent replay"));
        assert!(
            store
                .contains_evidence(evidence.evidence_id())
                .expect("contains")
        );

        let loaded = store
            .get_evidence(evidence.evidence_id(), &authority)
            .expect("lookup")
            .expect("present");
        assert_eq!(loaded, evidence);
    }

    #[test]
    fn missing_lookup_is_none() {
        let temp = TempDb::new("missing");
        let store = Store::open(&temp.path).expect("store opens");
        assert!(
            store
                .get_evidence(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    &authority(),
                )
                .expect("lookup")
                .is_none()
        );
    }

    #[test]
    fn wrong_runtime_authority_cannot_load_evidence() {
        let temp = TempDb::new("authority");
        let store = Store::open(&temp.path).expect("store opens");
        let native = authority();
        let evidence = evidence(&native, "authority-bound observation");
        store.put_evidence(&evidence).expect("persist");

        let other = EvidenceAuthority::from_runtime("other", "1", ProducerKind::ExternalEngine)
            .expect("other authority");
        assert!(matches!(
            store.get_evidence(evidence.evidence_id(), &other),
            Err(EvidenceStoreError::EvidenceValidation(_))
        ));
    }

    #[test]
    fn sqlite_rejects_update_and_delete_of_evidence_rows() {
        let temp = TempDb::new("immutable");
        let store = Store::open(&temp.path).expect("store opens");
        let authority = authority();
        let evidence = evidence(&authority, "immutable observation");
        store.put_evidence(&evidence).expect("persist");

        let connection = Connection::open(&temp.path).expect("direct fixture connection");
        let update = connection.execute(
            "UPDATE sentrdel_evidence_objects SET canonical_json = ?1 WHERE evidence_id = ?2",
            params![b"{}".as_slice(), evidence.evidence_id()],
        );
        assert!(update.is_err());

        let delete = connection.execute(
            "DELETE FROM sentrdel_evidence_objects WHERE evidence_id = ?1",
            params![evidence.evidence_id()],
        );
        assert!(delete.is_err());
    }

    #[test]
    fn tampered_noncanonical_bytes_are_rejected_on_lookup() {
        let temp = TempDb::new("tampered");
        let store = Store::open(&temp.path).expect("store opens");
        let authority = authority();
        let evidence = evidence(&authority, "tamper target");
        store.put_evidence(&evidence).expect("persist");
        drop(store);

        let connection = Connection::open(&temp.path).expect("fixture connection");
        connection
            .execute_batch("DROP TRIGGER sentrdel_evidence_immutable_update;")
            .expect("test-only trigger removal");
        let noncanonical = serde_json::to_vec_pretty(&evidence.to_record()).expect("pretty json");
        connection
            .execute(
                "UPDATE sentrdel_evidence_objects SET canonical_json = ?1 WHERE evidence_id = ?2",
                params![noncanonical, evidence.evidence_id()],
            )
            .expect("test-only tamper");
        connection
            .execute_batch(immutable_update_trigger_sql())
            .expect("restore immutable trigger");
        drop(connection);

        let store = Store::open(&temp.path).expect("schema remains structurally valid");
        assert!(matches!(
            store.get_evidence(evidence.evidence_id(), &authority),
            Err(EvidenceStoreError::CorruptStoredObject { .. })
        ));
    }
}
