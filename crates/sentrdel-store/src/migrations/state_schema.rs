use rusqlite::Connection;

use crate::{StoreError, StoreResult};

use super::schema_sql_matches;

pub(super) const FINDING_PROJECTION_TABLE_SQL: &str = r#"
    CREATE TABLE sentrdel_finding_projection (
        finding_id     TEXT PRIMARY KEY NOT NULL
            CHECK (
                length(finding_id) = 71
                AND substr(finding_id, 1, 7) = 'sha256:'
                AND substr(finding_id, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        revision       INTEGER NOT NULL CHECK (revision > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0)
    ) STRICT
"#;

pub(super) const FINDING_HISTORY_TABLE_SQL: &str = r#"
    CREATE TABLE sentrdel_finding_history (
        finding_id     TEXT NOT NULL
            CHECK (
                length(finding_id) = 71
                AND substr(finding_id, 1, 7) = 'sha256:'
                AND substr(finding_id, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        revision       INTEGER NOT NULL CHECK (revision > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0),
        PRIMARY KEY (finding_id, revision),
        FOREIGN KEY (finding_id) REFERENCES sentrdel_finding_projection(finding_id)
    ) STRICT
"#;

pub(super) const FINDING_HISTORY_REINSERT_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_finding_history_immutable_reinsert
    BEFORE INSERT ON sentrdel_finding_history
    WHEN EXISTS (
        SELECT 1 FROM sentrdel_finding_history
        WHERE finding_id = NEW.finding_id AND revision = NEW.revision
    )
    BEGIN
        SELECT RAISE(IGNORE);
    END
"#;

pub(super) const FINDING_HISTORY_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_finding_history_immutable_update
    BEFORE UPDATE ON sentrdel_finding_history
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel Finding history is immutable');
    END
"#;

pub(super) const FINDING_HISTORY_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_finding_history_immutable_delete
    BEFORE DELETE ON sentrdel_finding_history
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel Finding history is immutable');
    END
"#;

pub(super) const STATE_OBJECTS_TABLE_SQL: &str = r#"
    CREATE TABLE sentrdel_state_objects (
        object_kind    TEXT NOT NULL
            CHECK (object_kind IN ('coverage', 'engine_run', 'engine_manifest', 'security_pack_manifest')),
        object_key     TEXT NOT NULL CHECK (length(object_key) > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0),
        PRIMARY KEY (object_kind, object_key)
    ) STRICT
"#;

pub(super) const STATE_OBJECTS_REINSERT_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_state_objects_immutable_reinsert
    BEFORE INSERT ON sentrdel_state_objects
    WHEN EXISTS (
        SELECT 1 FROM sentrdel_state_objects
        WHERE object_kind = NEW.object_kind AND object_key = NEW.object_key
    )
    BEGIN
        SELECT RAISE(IGNORE);
    END
"#;

pub(super) const STATE_OBJECTS_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_state_objects_immutable_update
    BEFORE UPDATE ON sentrdel_state_objects
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel immutable state objects cannot be updated');
    END
"#;

pub(super) const STATE_OBJECTS_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_state_objects_immutable_delete
    BEFORE DELETE ON sentrdel_state_objects
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel immutable state objects cannot be deleted');
    END
"#;

pub(super) const PROJECT_PROFILES_TABLE_SQL: &str = r#"
    CREATE TABLE sentrdel_project_profiles (
        repository_id  TEXT PRIMARY KEY NOT NULL CHECK (length(repository_id) > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0)
    ) STRICT
"#;

pub(super) fn apply_v3_schema(connection: &Connection) -> StoreResult<()> {
    for sql in [
        FINDING_PROJECTION_TABLE_SQL,
        FINDING_HISTORY_TABLE_SQL,
        FINDING_HISTORY_REINSERT_TRIGGER_SQL,
        FINDING_HISTORY_UPDATE_TRIGGER_SQL,
        FINDING_HISTORY_DELETE_TRIGGER_SQL,
        STATE_OBJECTS_TABLE_SQL,
        STATE_OBJECTS_REINSERT_TRIGGER_SQL,
        STATE_OBJECTS_UPDATE_TRIGGER_SQL,
        STATE_OBJECTS_DELETE_TRIGGER_SQL,
        PROJECT_PROFILES_TABLE_SQL,
    ] {
        connection.execute_batch(sql)?;
    }
    Ok(())
}

pub(super) fn validate_v3_schema(connection: &Connection) -> StoreResult<()> {
    let required = [
        (
            "table",
            "sentrdel_finding_projection",
            FINDING_PROJECTION_TABLE_SQL,
        ),
        (
            "table",
            "sentrdel_finding_history",
            FINDING_HISTORY_TABLE_SQL,
        ),
        (
            "trigger",
            "sentrdel_finding_history_immutable_reinsert",
            FINDING_HISTORY_REINSERT_TRIGGER_SQL,
        ),
        (
            "trigger",
            "sentrdel_finding_history_immutable_update",
            FINDING_HISTORY_UPDATE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "sentrdel_finding_history_immutable_delete",
            FINDING_HISTORY_DELETE_TRIGGER_SQL,
        ),
        ("table", "sentrdel_state_objects", STATE_OBJECTS_TABLE_SQL),
        (
            "trigger",
            "sentrdel_state_objects_immutable_reinsert",
            STATE_OBJECTS_REINSERT_TRIGGER_SQL,
        ),
        (
            "trigger",
            "sentrdel_state_objects_immutable_update",
            STATE_OBJECTS_UPDATE_TRIGGER_SQL,
        ),
        (
            "trigger",
            "sentrdel_state_objects_immutable_delete",
            STATE_OBJECTS_DELETE_TRIGGER_SQL,
        ),
        (
            "table",
            "sentrdel_project_profiles",
            PROJECT_PROFILES_TABLE_SQL,
        ),
    ];

    for (object_type, name, expected) in required {
        if !schema_sql_matches(connection, object_type, name, expected)? {
            return Err(StoreError::MigrationIntegrity {
                version: 3,
                detail: "T018 state persistence schema does not match migration v3",
            });
        }
    }

    Ok(())
}
