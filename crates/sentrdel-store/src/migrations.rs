mod asel_schema;
pub(crate) mod evidence_store;
mod state_schema;
pub(crate) mod state_store;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{StoreError, StoreResult};

/// SQLite application_id spelling `SNTD` in big-endian ASCII.
pub(crate) const SENTRDEL_APPLICATION_ID: i64 = 0x534E_5444;

const CREATE_LEDGER_SQL: &str = r#"
    CREATE TABLE sentrdel_schema_migrations (
        version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
        name    TEXT NOT NULL UNIQUE
    ) STRICT;
"#;

const EVIDENCE_TABLE_SQL: &str = r#"
    CREATE TABLE sentrdel_evidence_objects (
        evidence_id   TEXT PRIMARY KEY NOT NULL
            CHECK (
                length(evidence_id) = 71
                AND substr(evidence_id, 1, 7) = 'sha256:'
                AND substr(evidence_id, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0)
    ) STRICT
"#;

const EVIDENCE_REINSERT_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_evidence_immutable_reinsert
    BEFORE INSERT ON sentrdel_evidence_objects
    WHEN EXISTS (
        SELECT 1 FROM sentrdel_evidence_objects
        WHERE evidence_id = NEW.evidence_id
    )
    BEGIN
        SELECT RAISE(IGNORE);
    END
"#;

const EVIDENCE_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_evidence_immutable_update
    BEFORE UPDATE ON sentrdel_evidence_objects
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel Evidence objects are immutable');
    END
"#;

const EVIDENCE_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_evidence_immutable_delete
    BEFORE DELETE ON sentrdel_evidence_objects
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel Evidence objects are immutable');
    END
"#;

struct Migration {
    version: i64,
    name: &'static str,
    apply: fn(&Connection) -> StoreResult<()>,
    validate: fn(&Connection) -> StoreResult<()>,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "bootstrap_store_metadata",
        apply: apply_v1_schema,
        validate: validate_v1_schema,
    },
    Migration {
        version: 2,
        name: "immutable_evidence_objects",
        apply: apply_v2_schema,
        validate: validate_v2_schema,
    },
    Migration {
        version: 3,
        name: "reconciled_state_persistence",
        apply: state_schema::apply_v3_schema,
        validate: state_schema::validate_v3_schema,
    },
    Migration {
        version: 4,
        name: "asel_append_only_store",
        apply: asel_schema::apply_v4_schema,
        validate: asel_schema::validate_v4_schema,
    },
];

pub(crate) const LATEST_SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].version;

/// Validate ownership, schema metadata, and every already-applied migration
/// without mutating the database.
///
/// This must run before connection configuration that can persist state (most
/// importantly `journal_mode=WAL`) so unrelated, unsupported, inconsistent, or
/// spoofed databases are rejected without Sentrdel changing them first.
pub(crate) fn preflight(connection: &Connection) -> StoreResult<()> {
    let pragma_version = user_version(connection)?;
    let app_id = application_id(connection)?;
    reject_future_version(pragma_version)?;

    if migration_ledger_exists(connection)? {
        validate_ledger_schema(connection)?;
        let ledger_version = migration_ledger_version(connection)?;
        reject_future_version(ledger_version)?;

        if ledger_version == 0 {
            return Err(StoreError::MigrationIntegrity {
                version: 0,
                detail: "migration ledger exists but contains no applied migration",
            });
        }
        if app_id != SENTRDEL_APPLICATION_ID {
            return Err(StoreError::MigrationIntegrity {
                version: ledger_version,
                detail: "migration ledger exists without the canonical Sentrdel application_id",
            });
        }
        if pragma_version != ledger_version {
            return Err(StoreError::InconsistentSchemaVersion {
                pragma: pragma_version,
                ledger: ledger_version,
            });
        }
        validate_applied_migrations(connection, ledger_version)?;
        return Ok(());
    }

    if pragma_version != 0 {
        return Err(StoreError::InconsistentSchemaVersion {
            pragma: pragma_version,
            ledger: 0,
        });
    }

    let user_objects = user_schema_object_count(connection)?;
    if app_id != 0 || user_objects != 0 {
        return Err(StoreError::UnrecognizedDatabase {
            application_id: app_id,
            user_object_count: user_objects,
        });
    }

    Ok(())
}

pub(crate) fn migrate(connection: &mut Connection) -> StoreResult<()> {
    // Defense in depth: callers should preflight before any persistent
    // connection configuration, but migration itself also refuses bad state.
    preflight(connection)?;

    let ledger_version = if migration_ledger_exists(connection)? {
        validate_ledger_schema(connection)?;
        migration_ledger_version(connection)?
    } else {
        apply_bootstrap_migration(connection)?;
        1
    };

    let pragma_version = user_version(connection)?;
    if pragma_version != ledger_version {
        return Err(StoreError::InconsistentSchemaVersion {
            pragma: pragma_version,
            ledger: ledger_version,
        });
    }

    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version > ledger_version)
    {
        apply_migration(connection, migration)?;
    }

    let final_version = user_version(connection)?;
    let final_ledger_version = migration_ledger_version(connection)?;

    if final_version != LATEST_SCHEMA_VERSION || final_ledger_version != LATEST_SCHEMA_VERSION {
        return Err(StoreError::InconsistentSchemaVersion {
            pragma: final_version,
            ledger: final_ledger_version,
        });
    }

    validate_applied_migrations(connection, final_ledger_version)?;
    Ok(())
}

fn apply_v1_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        PRAGMA application_id = 1397642308;
        CREATE TABLE sentrdel_store_metadata (
            key   TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        ) STRICT;
        "#,
    )?;
    Ok(())
}

fn apply_v2_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(EVIDENCE_TABLE_SQL)?;
    connection.execute_batch(EVIDENCE_REINSERT_TRIGGER_SQL)?;
    connection.execute_batch(EVIDENCE_UPDATE_TRIGGER_SQL)?;
    connection.execute_batch(EVIDENCE_DELETE_TRIGGER_SQL)?;
    Ok(())
}

fn apply_bootstrap_migration(connection: &mut Connection) -> StoreResult<()> {
    let migration = &MIGRATIONS[0];
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(CREATE_LEDGER_SQL)?;
    (migration.apply)(&transaction)?;
    transaction.execute(
        "INSERT INTO sentrdel_schema_migrations(version, name) VALUES (?1, ?2)",
        params![migration.version, migration.name],
    )?;
    transaction.pragma_update(None, "user_version", migration.version)?;
    transaction.commit()?;
    Ok(())
}

fn apply_migration(connection: &mut Connection, migration: &Migration) -> StoreResult<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    (migration.apply)(&transaction)?;
    transaction.execute(
        "INSERT INTO sentrdel_schema_migrations(version, name) VALUES (?1, ?2)",
        params![migration.version, migration.name],
    )?;
    transaction.pragma_update(None, "user_version", migration.version)?;
    transaction.commit()?;
    Ok(())
}

fn reject_future_version(found: i64) -> StoreResult<()> {
    if found > LATEST_SCHEMA_VERSION {
        return Err(StoreError::FutureSchemaVersion {
            found,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    Ok(())
}

fn application_id(connection: &Connection) -> StoreResult<i64> {
    Ok(connection.pragma_query_value(None, "application_id", |row| row.get(0))?)
}

fn user_schema_object_count(connection: &Connection) -> StoreResult<i64> {
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?)
}

fn migration_ledger_exists(connection: &Connection) -> StoreResult<bool> {
    let exists: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'sentrdel_schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

fn migration_ledger_version(connection: &Connection) -> StoreResult<i64> {
    Ok(connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM sentrdel_schema_migrations",
        [],
        |row| row.get(0),
    )?)
}

fn validate_ledger_schema(connection: &Connection) -> StoreResult<()> {
    let column_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('sentrdel_schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    let matching_columns: i64 = connection.query_row(
        r#"
        SELECT COUNT(*)
        FROM pragma_table_info('sentrdel_schema_migrations')
        WHERE (name = 'version' AND type = 'INTEGER' AND "notnull" = 1 AND pk = 1)
           OR (name = 'name' AND type = 'TEXT' AND "notnull" = 1 AND pk = 0)
        "#,
        [],
        |row| row.get(0),
    )?;
    let strict: i64 = connection.query_row(
        r#"
        SELECT COALESCE(MAX(strict), 0)
        FROM pragma_table_list('sentrdel_schema_migrations')
        WHERE schema = 'main' AND name = 'sentrdel_schema_migrations' AND type = 'table'
        "#,
        [],
        |row| row.get(0),
    )?;

    if column_count != 2 || matching_columns != 2 || strict != 1 {
        return Err(StoreError::MigrationIntegrity {
            version: 0,
            detail: "migration ledger schema does not match the Sentrdel bootstrap schema",
        });
    }

    Ok(())
}

fn validate_applied_migrations(connection: &Connection, ledger_version: i64) -> StoreResult<()> {
    let ledger_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sentrdel_schema_migrations",
        [],
        |row| row.get(0),
    )?;
    if ledger_count != ledger_version {
        return Err(StoreError::MigrationIntegrity {
            version: ledger_version,
            detail: "migration ledger is not a contiguous 1-based sequence",
        });
    }

    for migration in MIGRATIONS
        .iter()
        .filter(|migration| migration.version <= ledger_version)
    {
        let recorded_name: Option<String> = connection
            .query_row(
                "SELECT name FROM sentrdel_schema_migrations WHERE version = ?1",
                params![migration.version],
                |row| row.get(0),
            )
            .optional()?;

        if recorded_name.as_deref() != Some(migration.name) {
            return Err(StoreError::MigrationIntegrity {
                version: migration.version,
                detail: "migration ledger name does not match the canonical migration",
            });
        }

        (migration.validate)(connection)?;
    }

    Ok(())
}

fn validate_v1_schema(connection: &Connection) -> StoreResult<()> {
    if application_id(connection)? != SENTRDEL_APPLICATION_ID {
        return Err(StoreError::MigrationIntegrity {
            version: 1,
            detail: "Sentrdel application_id is missing or incorrect",
        });
    }

    let column_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('sentrdel_store_metadata')",
        [],
        |row| row.get(0),
    )?;
    let matching_columns: i64 = connection.query_row(
        r#"
        SELECT COUNT(*)
        FROM pragma_table_info('sentrdel_store_metadata')
        WHERE (name = 'key' AND type = 'TEXT' AND "notnull" = 1 AND pk = 1)
           OR (name = 'value' AND type = 'TEXT' AND "notnull" = 1 AND pk = 0)
        "#,
        [],
        |row| row.get(0),
    )?;
    let strict: i64 = connection.query_row(
        r#"
        SELECT COALESCE(MAX(strict), 0)
        FROM pragma_table_list('sentrdel_store_metadata')
        WHERE schema = 'main' AND name = 'sentrdel_store_metadata' AND type = 'table'
        "#,
        [],
        |row| row.get(0),
    )?;

    if column_count != 2 || matching_columns != 2 || strict != 1 {
        return Err(StoreError::MigrationIntegrity {
            version: 1,
            detail: "schema objects required by migration v1 are missing or malformed",
        });
    }

    Ok(())
}

fn validate_v2_schema(connection: &Connection) -> StoreResult<()> {
    let column_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('sentrdel_evidence_objects')",
        [],
        |row| row.get(0),
    )?;
    let matching_columns: i64 = connection.query_row(
        r#"
        SELECT COUNT(*)
        FROM pragma_table_info('sentrdel_evidence_objects')
        WHERE (name = 'evidence_id' AND type = 'TEXT' AND "notnull" = 1 AND pk = 1)
           OR (name = 'canonical_json' AND type = 'BLOB' AND "notnull" = 1 AND pk = 0)
        "#,
        [],
        |row| row.get(0),
    )?;
    let strict: i64 = connection.query_row(
        r#"
        SELECT COALESCE(MAX(strict), 0)
        FROM pragma_table_list('sentrdel_evidence_objects')
        WHERE schema = 'main' AND name = 'sentrdel_evidence_objects' AND type = 'table'
        "#,
        [],
        |row| row.get(0),
    )?;

    let table_sql_matches = schema_sql_matches(
        connection,
        "table",
        "sentrdel_evidence_objects",
        EVIDENCE_TABLE_SQL,
    )?;
    let reinsert_trigger_matches = schema_sql_matches(
        connection,
        "trigger",
        "sentrdel_evidence_immutable_reinsert",
        EVIDENCE_REINSERT_TRIGGER_SQL,
    )?;
    let update_trigger_matches = schema_sql_matches(
        connection,
        "trigger",
        "sentrdel_evidence_immutable_update",
        EVIDENCE_UPDATE_TRIGGER_SQL,
    )?;
    let delete_trigger_matches = schema_sql_matches(
        connection,
        "trigger",
        "sentrdel_evidence_immutable_delete",
        EVIDENCE_DELETE_TRIGGER_SQL,
    )?;

    if column_count != 2
        || matching_columns != 2
        || strict != 1
        || !table_sql_matches
        || !reinsert_trigger_matches
        || !update_trigger_matches
        || !delete_trigger_matches
    {
        return Err(StoreError::MigrationIntegrity {
            version: 2,
            detail: "immutable Evidence storage schema does not match migration v2",
        });
    }

    Ok(())
}

fn schema_sql_matches(
    connection: &Connection,
    object_type: &str,
    name: &str,
    expected: &str,
) -> StoreResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;

    Ok(actual
        .as_deref()
        .map(normalize_schema_sql)
        .is_some_and(|actual| actual == normalize_schema_sql(expected)))
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.trim()
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

pub(crate) fn user_version(connection: &Connection) -> StoreResult<i64> {
    Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::{
        EVIDENCE_UPDATE_TRIGGER_SQL, LATEST_SCHEMA_VERSION, MIGRATIONS, SENTRDEL_APPLICATION_ID,
        normalize_schema_sql, preflight,
    };
    use crate::StoreError;

    #[test]
    fn migration_plan_is_contiguous_and_latest_is_derived() {
        for (index, migration) in MIGRATIONS.iter().enumerate() {
            assert_eq!(migration.version, index as i64 + 1);
        }
        assert_eq!(
            LATEST_SCHEMA_VERSION,
            MIGRATIONS
                .last()
                .expect("migration plan is non-empty")
                .version
        );
    }

    #[test]
    fn conditional_spoofed_update_trigger_is_rejected() {
        let connection = Connection::open_in_memory().expect("fixture database");
        connection
            .execute_batch(
                r#"
                PRAGMA application_id = 1397642308;
                PRAGMA user_version = 2;
                CREATE TABLE sentrdel_schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
                    name TEXT NOT NULL UNIQUE
                ) STRICT;
                INSERT INTO sentrdel_schema_migrations(version, name) VALUES
                    (1, 'bootstrap_store_metadata'),
                    (2, 'immutable_evidence_objects');
                CREATE TABLE sentrdel_store_metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT;
                CREATE TABLE sentrdel_evidence_objects (
                    evidence_id TEXT PRIMARY KEY NOT NULL
                        CHECK (
                            length(evidence_id) = 71
                            AND substr(evidence_id, 1, 7) = 'sha256:'
                            AND substr(evidence_id, 8) NOT GLOB '*[^0-9a-f]*'
                        ),
                    canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0)
                ) STRICT;
                CREATE TRIGGER sentrdel_evidence_immutable_reinsert
                BEFORE INSERT ON sentrdel_evidence_objects
                WHEN EXISTS (
                    SELECT 1 FROM sentrdel_evidence_objects
                    WHERE evidence_id = NEW.evidence_id
                )
                BEGIN
                    SELECT RAISE(IGNORE);
                END;
                CREATE TRIGGER sentrdel_evidence_immutable_update
                BEFORE UPDATE ON sentrdel_evidence_objects
                WHEN 0
                BEGIN
                    SELECT RAISE(ABORT, 'Sentrdel Evidence objects are immutable');
                END;
                CREATE TRIGGER sentrdel_evidence_immutable_delete
                BEFORE DELETE ON sentrdel_evidence_objects
                BEGIN
                    SELECT RAISE(ABORT, 'Sentrdel Evidence objects are immutable');
                END;
                "#,
            )
            .expect("spoofed fixture");

        assert_eq!(SENTRDEL_APPLICATION_ID, 0x534E_5444);
        assert_ne!(
            normalize_schema_sql(EVIDENCE_UPDATE_TRIGGER_SQL),
            normalize_schema_sql(
                r#"
                CREATE TRIGGER sentrdel_evidence_immutable_update
                BEFORE UPDATE ON sentrdel_evidence_objects
                WHEN 0
                BEGIN
                    SELECT RAISE(ABORT, 'Sentrdel Evidence objects are immutable');
                END
                "#
            )
        );
        assert!(matches!(
            preflight(&connection),
            Err(StoreError::MigrationIntegrity { version: 2, .. })
        ));
    }
}
