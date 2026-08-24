use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::{StoreError, StoreResult};

pub(crate) const LATEST_SCHEMA_VERSION: i64 = 1;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
    validate: fn(&Connection) -> StoreResult<()>,
}

const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "bootstrap_store_metadata",
    sql: r#"
        CREATE TABLE sentrdel_store_metadata (
            key   TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        ) STRICT;
    "#,
    validate: validate_v1_schema,
}];

/// Validate schema metadata and every already-applied migration without mutating
/// the database.
///
/// This must run before connection configuration that can persist state (most
/// importantly `journal_mode=WAL`) so unsupported, inconsistent, or spoofed
/// databases are rejected without Sentrdel changing them first.
pub(crate) fn preflight(connection: &Connection) -> StoreResult<()> {
    let pragma_version = user_version(connection)?;
    reject_future_version(pragma_version)?;

    if migration_ledger_exists(connection)? {
        validate_ledger_schema(connection)?;
        let ledger_version = migration_ledger_version(connection)?;
        reject_future_version(ledger_version)?;
        if pragma_version != ledger_version {
            return Err(StoreError::InconsistentSchemaVersion {
                pragma: pragma_version,
                ledger: ledger_version,
            });
        }
        validate_applied_migrations(connection, ledger_version)?;
    } else if pragma_version != 0 {
        return Err(StoreError::InconsistentSchemaVersion {
            pragma: pragma_version,
            ledger: 0,
        });
    }

    Ok(())
}

pub(crate) fn migrate(connection: &mut Connection) -> StoreResult<()> {
    // Defense in depth: callers should preflight before any persistent
    // connection configuration, but migration itself also refuses bad state.
    preflight(connection)?;

    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sentrdel_schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
            name    TEXT NOT NULL UNIQUE
        ) STRICT;
        "#,
    )?;
    validate_ledger_schema(connection)?;

    let ledger_version = migration_ledger_version(connection)?;
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
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO sentrdel_schema_migrations(version, name) VALUES (?1, ?2)",
            params![migration.version, migration.name],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        transaction.commit()?;
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

fn reject_future_version(found: i64) -> StoreResult<()> {
    if found > LATEST_SCHEMA_VERSION {
        return Err(StoreError::FutureSchemaVersion {
            found,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    Ok(())
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

pub(crate) fn user_version(connection: &Connection) -> StoreResult<i64> {
    Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
}
