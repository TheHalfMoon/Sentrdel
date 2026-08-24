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
    FutureSchemaVersion {
        found: i64,
        supported: i64,
    },
    InconsistentSchemaVersion {
        pragma: i64,
        ledger: i64,
    },
    MigrationIntegrity {
        version: i64,
        detail: &'static str,
    },
    UnrecognizedDatabase {
        application_id: i64,
        user_object_count: i64,
    },
    ForeignKeysUnavailable {
        actual: i64,
    },
    WalUnavailable {
        actual_mode: String,
    },
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
            Self::MigrationIntegrity { version, detail } => write!(
                formatter,
                "database migration integrity check failed at version {version}: {detail}"
            ),
            Self::UnrecognizedDatabase {
                application_id,
                user_object_count,
            } => write!(
                formatter,
                "refusing non-empty or foreign SQLite database: application_id={application_id}, user schema objects={user_object_count}"
            ),
            Self::ForeignKeysUnavailable { actual } => write!(
                formatter,
                "SQLite refused required foreign_keys=ON invariant and returned {actual}"
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
            | Self::MigrationIntegrity { .. }
            | Self::UnrecognizedDatabase { .. }
            | Self::ForeignKeysUnavailable { .. }
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
    /// Open or create a Sentrdel-owned SQLite database, reject unrelated,
    /// unsupported, inconsistent, or spoofed schema state without mutating it,
    /// then enforce connection invariants and migrate to the current R1 schema.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let mut connection = Connection::open(path)?;
        migrations::preflight(&connection)?;
        configure_connection(&connection)?;
        migrations::migrate(&mut connection)?;
        Ok(Self { connection })
    }

    /// Return the migration version recorded by SQLite itself.
    pub fn schema_version(&self) -> StoreResult<i64> {
        migrations::user_version(&self.connection)
    }
}

fn configure_connection(connection: &Connection) -> StoreResult<()> {
    connection.pragma_update(None, "foreign_keys", true)?;
    let foreign_keys: i64 =
        connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(StoreError::ForeignKeysUnavailable {
            actual: foreign_keys,
        });
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

    use rusqlite::{Connection, params};

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

    fn journal_mode(connection: &Connection) -> String {
        connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode should be queryable")
    }

    fn application_id(connection: &Connection) -> i64 {
        connection
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .expect("application_id should be queryable")
    }

    fn mark_sentrdel_application(connection: &Connection) {
        connection
            .pragma_update(None, "application_id", migrations::SENTRDEL_APPLICATION_ID)
            .expect("fixture application_id should update");
    }

    fn table_exists(connection: &Connection, table: &str) -> bool {
        let exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                params![table],
                |row| row.get(0),
            )
            .expect("schema metadata should be queryable");
        exists == 1
    }

    fn migration_ledger_exists(connection: &Connection) -> bool {
        table_exists(connection, "sentrdel_schema_migrations")
    }

    fn create_empty_migration_ledger(connection: &Connection) {
        connection
            .execute_batch(
                r#"
                CREATE TABLE sentrdel_schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                    name    TEXT NOT NULL UNIQUE
                ) STRICT;
                "#,
            )
            .expect("fixture migration ledger should be created");
    }

    fn create_migration_ledger(connection: &Connection, migration_name: &str) {
        create_empty_migration_ledger(connection);
        connection
            .execute(
                "INSERT INTO sentrdel_schema_migrations(version, name) VALUES (1, ?1)",
                params![migration_name],
            )
            .expect("fixture migration row should be inserted");
    }

    fn create_v1_metadata_table(connection: &Connection) {
        connection
            .execute_batch(
                r#"
                CREATE TABLE sentrdel_store_metadata (
                    key   TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT;
                "#,
            )
            .expect("fixture v1 metadata table should be created");
    }

    #[test]
    fn open_enforces_wal_foreign_keys_and_application_identity() {
        let temp = TempDb::new("connection-invariants");
        let store = Store::open(&temp.path).expect("store should open");

        let foreign_keys: i64 = store
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign key state should be queryable");

        assert_eq!(journal_mode(&store.connection).to_ascii_lowercase(), "wal");
        assert_eq!(foreign_keys, 1);
        assert_eq!(
            application_id(&store.connection),
            migrations::SENTRDEL_APPLICATION_ID
        );
        assert!(table_exists(
            &store.connection,
            "sentrdel_schema_migrations"
        ));
        assert!(table_exists(&store.connection, "sentrdel_store_metadata"));
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
                .connection
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
                .connection
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
    fn incomplete_empty_ledger_is_rejected_without_wal_mutation() {
        let temp = TempDb::new("empty-ledger");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        create_empty_migration_ledger(&connection);
        mark_sentrdel_application(&connection);
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("empty migration ledger must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::MigrationIntegrity { version: 0, .. }
        ));

        let connection = Connection::open(&temp.path).expect("rejected fixture should reopen");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
    }

    #[test]
    fn unrelated_nonempty_database_is_rejected_without_persistent_mutation() {
        let temp = TempDb::new("unrecognized-database");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        connection
            .execute_batch("CREATE TABLE unrelated_data (id INTEGER NOT NULL) STRICT;")
            .expect("unrelated fixture table should be created");
        assert_eq!(application_id(&connection), 0);
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("unrecognized database must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::UnrecognizedDatabase {
                application_id: 0,
                user_object_count: 1
            }
        ));

        let connection = Connection::open(&temp.path).expect("rejected fixture should reopen");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        assert!(table_exists(&connection, "unrelated_data"));
        assert!(!migration_ledger_exists(&connection));
        assert_eq!(application_id(&connection), 0);
    }

    #[test]
    fn future_schema_version_is_rejected_without_persistent_mutation() {
        let temp = TempDb::new("future-version");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        connection
            .pragma_update(None, "user_version", migrations::LATEST_SCHEMA_VERSION + 1)
            .expect("fixture user_version should update");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        assert!(!migration_ledger_exists(&connection));
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

        let connection = Connection::open(&temp.path).expect("rejected fixture should reopen");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        assert!(!migration_ledger_exists(&connection));
    }

    #[test]
    fn inconsistent_schema_metadata_is_rejected_without_wal_mutation() {
        let temp = TempDb::new("inconsistent-version");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        create_migration_ledger(&connection, "fixture-only");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("inconsistent schema metadata must be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            StoreError::MigrationIntegrity { version: 1, .. }
        ));

        let connection = Connection::open(&temp.path).expect("rejected fixture should reopen");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
    }

    #[test]
    fn spoofed_current_version_without_v1_schema_is_rejected_without_wal_mutation() {
        let temp = TempDb::new("spoofed-current-schema");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        create_migration_ledger(&connection, "bootstrap_store_metadata");
        mark_sentrdel_application(&connection);
        connection
            .pragma_update(None, "user_version", migrations::LATEST_SCHEMA_VERSION)
            .expect("fixture user_version should update");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("spoofed current schema must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::MigrationIntegrity { version: 1, .. }
        ));

        let connection = Connection::open(&temp.path).expect("rejected fixture should reopen");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
    }

    #[test]
    fn wrong_canonical_migration_name_is_rejected_without_wal_mutation() {
        let temp = TempDb::new("wrong-migration-name");
        let connection = Connection::open(&temp.path).expect("fixture database should open");
        create_migration_ledger(&connection, "not-the-canonical-migration");
        create_v1_metadata_table(&connection);
        mark_sentrdel_application(&connection);
        connection
            .pragma_update(None, "user_version", migrations::LATEST_SCHEMA_VERSION)
            .expect("fixture user_version should update");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
        drop(connection);

        let error = match Store::open(&temp.path) {
            Ok(_) => panic!("wrong migration identity must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::MigrationIntegrity { version: 1, .. }
        ));

        let connection = Connection::open(&temp.path).expect("rejected fixture should reopen");
        assert_eq!(journal_mode(&connection).to_ascii_lowercase(), "delete");
    }
}
