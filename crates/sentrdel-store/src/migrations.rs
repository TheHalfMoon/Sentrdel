use rusqlite::{Connection, TransactionBehavior, params};

use crate::{StoreError, StoreResult};

pub(crate) const LATEST_SCHEMA_VERSION: i64 = 1;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
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
}];

pub(crate) fn migrate(connection: &mut Connection) -> StoreResult<()> {
    let pragma_version = user_version(connection)?;
    if pragma_version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::FutureSchemaVersion {
            found: pragma_version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sentrdel_schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL CHECK (version > 0),
            name    TEXT NOT NULL UNIQUE
        ) STRICT;
        "#,
    )?;

    let ledger_version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM sentrdel_schema_migrations",
        [],
        |row| row.get(0),
    )?;

    if ledger_version > LATEST_SCHEMA_VERSION {
        return Err(StoreError::FutureSchemaVersion {
            found: ledger_version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

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
    let final_ledger_version: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM sentrdel_schema_migrations",
        [],
        |row| row.get(0),
    )?;

    if final_version != LATEST_SCHEMA_VERSION || final_ledger_version != LATEST_SCHEMA_VERSION {
        return Err(StoreError::InconsistentSchemaVersion {
            pragma: final_version,
            ledger: final_ledger_version,
        });
    }

    Ok(())
}

pub(crate) fn user_version(connection: &Connection) -> StoreResult<i64> {
    Ok(connection.pragma_query_value(None, "user_version", |row| row.get(0))?)
}
