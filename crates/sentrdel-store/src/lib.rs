#![forbid(unsafe_code)]
//! Local SQLite persistence boundary for Sentrdel-owned state.

mod migrations;

use std::error::Error;
use std::fmt;
use std::path::Path;

use rusqlite::Connection;

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    FutureSchemaVersion { found: i64, supported: i64 },
    InconsistentSchemaVersion { pragma: i64, ledger: i64 },
    WalUnavailable { actual_mode: String },
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            Self::FutureSchemaVersion { found, supported } => write!(
                formatter,
                "database schema version {found} is newer than supported version {supported}"
            ),
            Self::InconsistentSchemaVersion { pragma, ledger } => write!(
                formatter,
                "database schema metadata is inconsistent: PRAGMA user_version={pragma}, migration ledger={ledger}"
            ),
            Self::WalUnavailable { actual_mode } => write!(
                formatter,
                "SQLite refused required WAL journal mode and returned {actual_mode:?}"
            ),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::FutureSchemaVersion { .. }
            | Self::InconsistentSchemaVersion { .. }
            | Self::WalUnavailable { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub struct Store {
    connection: Connection,
}

impl Store {
    /// Open or create a Sentrdel-owned SQLite database, enforce connection
    /// invariants, and migrate it to the current R1 schema version.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let mut connection = Connection::open(path)?;
        configure_connection(&connection)?;
        migrations::migrate(&mut connection)?;
        Ok(Self { connection })
    }

    /// Return the migration version recorded by SQLite itself.
    pub fn schema_version(&self) -> StoreResult<i64> {
        migrations::user_version(&self.connection)
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }
}

fn configure_connection(connection: &Connection) -> StoreResult<()> {
    connection.pragma_update(None, "foreign_keys", true)?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(StoreError::Sqlite(rusqlite::Error::InvalidQuery));
    }

    let journal_mode: String =
        connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::WalUnavailable {
            actual_mode: journal_mode,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::Connection;

    use super::{Store, StoreError, migrations};

    static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sentrdel-store-{label}-{}-{sequence}.sqlite3",
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
    fn open_enforces_wal_and_foreign_keys() {
        let temp = TempDb::new("connection-invariants");
        let store = Store::open(&temp.path).expect("store should open");

        let journal_mode: String = store
            .connection()
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode should be queryable");
        let foreign_keys: i64 = store
            .connection()
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign key state should be queryable");

        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn migrations_are_idempotent_across_reopen() {
        let temp = TempDb::new("migration-idempotency");

        {
            let store = Store::open(&temp.path).expect("initial store open should migrate");
            assert_eq!(
                store.schema_version().expect("schema version should read"),
                migrations::LATEST_SCHEMA_VERSION
            );
            let migration_count: i64 = store
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM sentrdel_schema_migrations",
                    [],
                    |row| row.get(0),
                )
                .expect("migration ledger should be queryable");
            assert_eq!(migration_count, migrations::LATEST_SCHEMA_VERSION);
        }

        {
            let store = Store::open(&temp.path).expect("reopen should be idempotent");
            let migration_count: i64 = store
                .connection()
                .query_row(
                    "SELECT COUNT(*) FROM sentrdel_schema_migrations",
                    [],
                    |row| row.get(0),
                )
                .expect("migration ledger should be queryable after reopen");
            assert_eq!(migration_count, migrations::LATEST_SCHEMA_VERSION);
        }
    }

    #[test]
    fn future_schema_version_is_rejected_before_migration() {
        let temp = TempDb::new("future-version");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        connection
            .pragma_update(None, "user_version", migrations::LATEST_SCHEMA_VERSION + 1)
            .expect("fixture user_version should update");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("future schema must be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            StoreError::FutureSchemaVersion {
                found,
                supported
            } if found == migrations::LATEST_SCHEMA_VERSION + 1
                && supported == migrations::LATEST_SCHEMA_VERSION
        ));
    }

    #[test]
    fn inconsistent_schema_metadata_is_rejected() {
        let temp = TempDb::new("inconsistent-version");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE sentrdel_schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                    name    TEXT NOT NULL UNIQUE
                ) STRICT;
                INSERT INTO sentrdel_schema_migrations(version, name)
                VALUES (1, 'fixture-only');
                "#,
            )
            .expect("fixture migration ledger should be created");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("inconsistent schema metadata must be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            StoreError::InconsistentSchemaVersion {
                pragma: 0,
                ledger: 1
            }
        ));
    }
}
