use rusqlite::Connection;

use crate::{StoreError, StoreResult};

use super::schema_sql_matches;

pub(super) const ASEL_EVENTS_TABLE_SQL: &str = r#"
    CREATE TABLE sentrdel_asel_events (
        session_id          TEXT NOT NULL CHECK (length(trim(session_id)) > 0),
        sequence            INTEGER NOT NULL CHECK (sequence >= 0),
        event_hash          TEXT NOT NULL UNIQUE
            CHECK (
                length(event_hash) = 71
                AND substr(event_hash, 1, 7) = 'sha256:'
                AND substr(event_hash, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        previous_event_hash TEXT
            CHECK (
                previous_event_hash IS NULL
                OR (
                    length(previous_event_hash) = 71
                    AND substr(previous_event_hash, 1, 7) = 'sha256:'
                    AND substr(previous_event_hash, 8) NOT GLOB '*[^0-9a-f]*'
                )
            ),
        canonical_json      BLOB NOT NULL CHECK (length(canonical_json) > 0),
        PRIMARY KEY (session_id, sequence),
        CHECK (
            (sequence = 0 AND previous_event_hash IS NULL)
            OR (sequence > 0 AND previous_event_hash IS NOT NULL)
        )
    ) STRICT
"#;

pub(super) const ASEL_APPEND_GUARD_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_asel_append_guard
    BEFORE INSERT ON sentrdel_asel_events
    WHEN
        (NEW.sequence = 0 AND EXISTS (
            SELECT 1 FROM sentrdel_asel_events
            WHERE session_id = NEW.session_id
        ))
        OR
        (NEW.sequence > 0 AND NOT EXISTS (
            SELECT 1 FROM sentrdel_asel_events
            WHERE session_id = NEW.session_id
              AND sequence = NEW.sequence - 1
              AND event_hash = NEW.previous_event_hash
        ))
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel ASEL events must append to the exact session head');
    END
"#;

pub(super) const ASEL_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_asel_immutable_update
    BEFORE UPDATE ON sentrdel_asel_events
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel ASEL events are immutable');
    END
"#;

pub(super) const ASEL_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_asel_immutable_delete
    BEFORE DELETE ON sentrdel_asel_events
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel ASEL events are immutable');
    END
"#;

pub(super) fn apply_v4_schema(connection: &Connection) -> StoreResult<()> {
    for sql in [
        ASEL_EVENTS_TABLE_SQL,
        ASEL_APPEND_GUARD_TRIGGER_SQL,
        ASEL_UPDATE_TRIGGER_SQL,
        ASEL_DELETE_TRIGGER_SQL,
    ] {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(super) fn validate_v4_schema(connection: &Connection) -> StoreResult<()> {
    let required = [
        ("table", "sentrdel_asel_events", ASEL_EVENTS_TABLE_SQL),
        (
            "trigger",
            "sentrdel_asel_append_guard",
            ASEL_APPEND_GUARD_TRIGGER_SQL,
        ),
        (
            "trigger",
            "sentrdel_asel_immutable_update",
            ASEL_UPDATE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "sentrdel_asel_immutable_delete",
            ASEL_DELETE_TRIGGER_SQL,
        ),
    ];

    for (object_type, name, expected) in required {
        if !schema_sql_matches(connection, object_type, name, expected)? {
            return Err(StoreError::MigrationIntegrity {
                version: 4,
                detail: "T020 ASEL append-only schema does not match migration v4",
            });
        }
    }

    Ok(())
}
