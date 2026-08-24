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

#[cfg(test)]
mod tests {
    use rusqlite::{Connection, params};

    use super::apply_v4_schema;

    fn hash(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    #[test]
    fn sqlite_triggers_enforce_append_order_and_immutability() {
        let connection = Connection::open_in_memory().expect("fixture database");
        apply_v4_schema(&connection).expect("v4 schema should apply");

        let root_hash = hash('a');
        let second_hash = hash('b');
        let gap_hash = hash('c');

        connection
            .execute(
                "INSERT INTO sentrdel_asel_events(session_id, sequence, event_hash, previous_event_hash, canonical_json) VALUES (?1, 0, ?2, NULL, ?3)",
                params!["session-trigger", root_hash, b"{}".as_slice()],
            )
            .expect("first root should append");

        assert!(
            connection
                .execute(
                    "INSERT INTO sentrdel_asel_events(session_id, sequence, event_hash, previous_event_hash, canonical_json) VALUES (?1, 0, ?2, NULL, ?3)",
                    params!["session-trigger", hash('d'), b"{}".as_slice()],
                )
                .is_err(),
            "second root must be rejected"
        );

        assert!(
            connection
                .execute(
                    "INSERT INTO sentrdel_asel_events(session_id, sequence, event_hash, previous_event_hash, canonical_json) VALUES (?1, 2, ?2, ?3, ?4)",
                    params!["session-trigger", gap_hash, root_hash, b"{}".as_slice()],
                )
                .is_err(),
            "sequence gap must be rejected"
        );

        connection
            .execute(
                "INSERT INTO sentrdel_asel_events(session_id, sequence, event_hash, previous_event_hash, canonical_json) VALUES (?1, 1, ?2, ?3, ?4)",
                params!["session-trigger", second_hash, root_hash, b"{}".as_slice()],
            )
            .expect("exact successor should append");

        assert!(
            connection
                .execute(
                    "UPDATE sentrdel_asel_events SET canonical_json = ?1 WHERE session_id = ?2 AND sequence = 1",
                    params![b"{\"mutated\":true}".as_slice(), "session-trigger"],
                )
                .is_err(),
            "ASEL rows must be immutable"
        );
        assert!(
            connection
                .execute(
                    "DELETE FROM sentrdel_asel_events WHERE session_id = ?1 AND sequence = 1",
                    params!["session-trigger"],
                )
                .is_err(),
            "ASEL rows must not be deletable"
        );
    }
}
