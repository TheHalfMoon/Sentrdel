use rusqlite::Connection;

use crate::{StoreError, StoreResult};

use super::schema_sql_matches;

const GRAPH_NODE_PROJECTION_SQL: &str = r#"
    CREATE TABLE sentrdel_graph_node_projection (
        node_id TEXT PRIMARY KEY NOT NULL
            CHECK (
                length(node_id) = 71
                AND substr(node_id, 1, 7) = 'sha256:'
                AND substr(node_id, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        revision INTEGER NOT NULL CHECK (revision > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0)
    ) STRICT
"#;

const GRAPH_NODE_HISTORY_SQL: &str = r#"
    CREATE TABLE sentrdel_graph_node_history (
        node_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0),
        PRIMARY KEY (node_id, revision),
        FOREIGN KEY (node_id)
            REFERENCES sentrdel_graph_node_projection(node_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT
"#;

const GRAPH_EDGE_PROJECTION_SQL: &str = r#"
    CREATE TABLE sentrdel_graph_edge_projection (
        edge_id TEXT PRIMARY KEY NOT NULL
            CHECK (
                length(edge_id) = 71
                AND substr(edge_id, 1, 7) = 'sha256:'
                AND substr(edge_id, 8) NOT GLOB '*[^0-9a-f]*'
            ),
        source_node_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision > 0),
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0),
        FOREIGN KEY (source_node_id)
            REFERENCES sentrdel_graph_node_projection(node_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (target_node_id)
            REFERENCES sentrdel_graph_node_projection(node_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT
"#;

const GRAPH_EDGE_HISTORY_SQL: &str = r#"
    CREATE TABLE sentrdel_graph_edge_history (
        edge_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision > 0),
        source_node_id TEXT NOT NULL,
        target_node_id TEXT NOT NULL,
        canonical_json BLOB NOT NULL CHECK (length(canonical_json) > 0),
        PRIMARY KEY (edge_id, revision),
        FOREIGN KEY (edge_id)
            REFERENCES sentrdel_graph_edge_projection(edge_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (source_node_id)
            REFERENCES sentrdel_graph_node_projection(node_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        FOREIGN KEY (target_node_id)
            REFERENCES sentrdel_graph_node_projection(node_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT
    ) STRICT
"#;

const GRAPH_NODE_HISTORY_INSERT_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_graph_node_history_projection_guard
    BEFORE INSERT ON sentrdel_graph_node_history
    WHEN NOT EXISTS (
        SELECT 1
        FROM sentrdel_graph_node_projection
        WHERE node_id = NEW.node_id
          AND revision = NEW.revision
          AND canonical_json = NEW.canonical_json
    )
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel graph node history must match the current projection revision');
    END
"#;

const GRAPH_NODE_HISTORY_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_graph_node_history_immutable_update
    BEFORE UPDATE ON sentrdel_graph_node_history
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel graph node history is immutable');
    END
"#;

const GRAPH_NODE_HISTORY_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_graph_node_history_immutable_delete
    BEFORE DELETE ON sentrdel_graph_node_history
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel graph node history is immutable');
    END
"#;

const GRAPH_EDGE_HISTORY_INSERT_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_graph_edge_history_projection_guard
    BEFORE INSERT ON sentrdel_graph_edge_history
    WHEN NOT EXISTS (
        SELECT 1
        FROM sentrdel_graph_edge_projection
        WHERE edge_id = NEW.edge_id
          AND revision = NEW.revision
          AND source_node_id = NEW.source_node_id
          AND target_node_id = NEW.target_node_id
          AND canonical_json = NEW.canonical_json
    )
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel graph edge history must match the current projection revision');
    END
"#;

const GRAPH_EDGE_HISTORY_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_graph_edge_history_immutable_update
    BEFORE UPDATE ON sentrdel_graph_edge_history
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel graph edge history is immutable');
    END
"#;

const GRAPH_EDGE_HISTORY_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER sentrdel_graph_edge_history_immutable_delete
    BEFORE DELETE ON sentrdel_graph_edge_history
    BEGIN
        SELECT RAISE(ABORT, 'Sentrdel graph edge history is immutable');
    END
"#;

pub(super) fn apply_v5_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(GRAPH_NODE_PROJECTION_SQL)?;
    connection.execute_batch(GRAPH_NODE_HISTORY_SQL)?;
    connection.execute_batch(GRAPH_EDGE_PROJECTION_SQL)?;
    connection.execute_batch(GRAPH_EDGE_HISTORY_SQL)?;
    connection.execute_batch(GRAPH_NODE_HISTORY_INSERT_TRIGGER_SQL)?;
    connection.execute_batch(GRAPH_NODE_HISTORY_UPDATE_TRIGGER_SQL)?;
    connection.execute_batch(GRAPH_NODE_HISTORY_DELETE_TRIGGER_SQL)?;
    connection.execute_batch(GRAPH_EDGE_HISTORY_INSERT_TRIGGER_SQL)?;
    connection.execute_batch(GRAPH_EDGE_HISTORY_UPDATE_TRIGGER_SQL)?;
    connection.execute_batch(GRAPH_EDGE_HISTORY_DELETE_TRIGGER_SQL)?;
    Ok(())
}

pub(super) fn validate_v5_schema(connection: &Connection) -> StoreResult<()> {
    let tables = [
        ("sentrdel_graph_node_projection", GRAPH_NODE_PROJECTION_SQL),
        ("sentrdel_graph_node_history", GRAPH_NODE_HISTORY_SQL),
        ("sentrdel_graph_edge_projection", GRAPH_EDGE_PROJECTION_SQL),
        ("sentrdel_graph_edge_history", GRAPH_EDGE_HISTORY_SQL),
    ];
    for (name, expected) in tables {
        let strict: i64 = connection.query_row(
            "SELECT COALESCE(MAX(strict), 0) FROM pragma_table_list(?1) WHERE schema = 'main' AND name = ?1 AND type = 'table'",
            [name],
            |row| row.get(0),
        )?;
        if strict != 1 || !schema_sql_matches(connection, "table", name, expected)? {
            return Err(StoreError::MigrationIntegrity {
                version: 5,
                detail: "graph persistence table schema does not match migration v5",
            });
        }
    }

    let triggers = [
        (
            "sentrdel_graph_node_history_projection_guard",
            GRAPH_NODE_HISTORY_INSERT_TRIGGER_SQL,
        ),
        (
            "sentrdel_graph_node_history_immutable_update",
            GRAPH_NODE_HISTORY_UPDATE_TRIGGER_SQL,
        ),
        (
            "sentrdel_graph_node_history_immutable_delete",
            GRAPH_NODE_HISTORY_DELETE_TRIGGER_SQL,
        ),
        (
            "sentrdel_graph_edge_history_projection_guard",
            GRAPH_EDGE_HISTORY_INSERT_TRIGGER_SQL,
        ),
        (
            "sentrdel_graph_edge_history_immutable_update",
            GRAPH_EDGE_HISTORY_UPDATE_TRIGGER_SQL,
        ),
        (
            "sentrdel_graph_edge_history_immutable_delete",
            GRAPH_EDGE_HISTORY_DELETE_TRIGGER_SQL,
        ),
    ];
    for (name, expected) in triggers {
        if !schema_sql_matches(connection, "trigger", name, expected)? {
            return Err(StoreError::MigrationIntegrity {
                version: 5,
                detail: "graph persistence history trigger does not match migration v5",
            });
        }
    }

    Ok(())
}
