use std::{error::Error, fmt};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sentrdel_schema::{
    canonical::{CanonicalError, canonical_json_bytes},
    graph::{GraphContractError, GraphEdge, GraphNode},
};

use crate::{PersistentSink, RedactionError, Store};

pub type GraphStoreResult<T> = Result<T, GraphStoreError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphWriteOutcome {
    Inserted { revision: i64 },
    Unchanged { revision: i64 },
    Revised { revision: i64 },
}

impl GraphWriteOutcome {
    pub fn revision(self) -> i64 {
        match self {
            Self::Inserted { revision }
            | Self::Unchanged { revision }
            | Self::Revised { revision } => revision,
        }
    }
}

#[derive(Debug)]
pub enum GraphStoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Canonical(CanonicalError),
    GraphContract(GraphContractError),
    Redaction(RedactionError),
    MissingEndpointNode {
        edge_id: String,
        node_id: String,
    },
    IdentityCollision {
        object_kind: &'static str,
        object_id: String,
    },
    RevisionOverflow {
        object_kind: &'static str,
        object_id: String,
    },
    CorruptStoredObject {
        object_kind: &'static str,
        object_id: String,
        detail: &'static str,
    },
}

impl fmt::Display for GraphStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite graph-store error: {error}"),
            Self::Json(error) => write!(formatter, "stored graph JSON is invalid: {error}"),
            Self::Canonical(error) => write!(formatter, "graph canonicalization failed: {error}"),
            Self::GraphContract(error) => {
                write!(formatter, "graph contract validation failed: {error}")
            }
            Self::Redaction(error) => {
                write!(formatter, "graph persistence redaction failed: {error}")
            }
            Self::MissingEndpointNode { edge_id, node_id } => write!(
                formatter,
                "refusing graph edge {edge_id} because endpoint node {node_id} is not persisted"
            ),
            Self::IdentityCollision {
                object_kind,
                object_id,
            } => write!(
                formatter,
                "stored {object_kind} {object_id} has a different semantic identity for the same stable id"
            ),
            Self::RevisionOverflow {
                object_kind,
                object_id,
            } => write!(
                formatter,
                "stored {object_kind} {object_id} exhausted the revision counter"
            ),
            Self::CorruptStoredObject {
                object_kind,
                object_id,
                detail,
            } => write!(
                formatter,
                "stored {object_kind} {object_id} failed integrity validation: {detail}"
            ),
        }
    }
}

impl Error for GraphStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::GraphContract(error) => Some(error),
            Self::Redaction(error) => Some(error),
            Self::MissingEndpointNode { .. }
            | Self::IdentityCollision { .. }
            | Self::RevisionOverflow { .. }
            | Self::CorruptStoredObject { .. } => None,
        }
    }
}

impl From<rusqlite::Error> for GraphStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for GraphStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<CanonicalError> for GraphStoreError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<GraphContractError> for GraphStoreError {
    fn from(error: GraphContractError) -> Self {
        Self::GraphContract(error)
    }
}

impl From<RedactionError> for GraphStoreError {
    fn from(error: RedactionError) -> Self {
        Self::Redaction(error)
    }
}

impl Store {
    /// Persist the current graph-node projection and append immutable history.
    /// Stable identity excludes mutable metadata, so byte-identical replay is
    /// idempotent while metadata/provenance changes advance the revision.
    pub fn put_graph_node(&mut self, node: &GraphNode) -> GraphStoreResult<GraphWriteOutcome> {
        node.validate()?;
        let canonical = canonical_json_bytes(node)?;
        self.require_persistable(PersistentSink::Sqlite, &canonical)?;
        let node_id = node.node_id.as_str().to_owned();

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT revision, canonical_json FROM sentrdel_graph_node_projection WHERE node_id = ?1",
                params![node_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match existing {
            None => {
                transaction.execute(
                    "INSERT INTO sentrdel_graph_node_projection(node_id, revision, canonical_json) VALUES (?1, 1, ?2)",
                    params![node_id, canonical],
                )?;
                transaction.execute(
                    "INSERT INTO sentrdel_graph_node_history(node_id, revision, canonical_json) VALUES (?1, 1, ?2)",
                    params![node_id, canonical],
                )?;
                transaction.commit()?;
                Ok(GraphWriteOutcome::Inserted { revision: 1 })
            }
            Some((revision, stored)) => {
                let stored_node =
                    validate_node_projection(&transaction, &node_id, revision, &stored)?;
                if stored_node.node_kind != node.node_kind
                    || stored_node.semantic_key != node.semantic_key
                {
                    return Err(GraphStoreError::IdentityCollision {
                        object_kind: "graph node",
                        object_id: node_id,
                    });
                }
                if stored == canonical {
                    return Ok(GraphWriteOutcome::Unchanged { revision });
                }

                let next_revision =
                    revision
                        .checked_add(1)
                        .ok_or_else(|| GraphStoreError::RevisionOverflow {
                            object_kind: "graph node",
                            object_id: node_id.clone(),
                        })?;
                transaction.execute(
                    "UPDATE sentrdel_graph_node_projection SET revision = ?2, canonical_json = ?3 WHERE node_id = ?1 AND revision = ?4",
                    params![node_id, next_revision, canonical, revision],
                )?;
                transaction.execute(
                    "INSERT INTO sentrdel_graph_node_history(node_id, revision, canonical_json) VALUES (?1, ?2, ?3)",
                    params![node_id, next_revision, canonical],
                )?;
                transaction.commit()?;
                Ok(GraphWriteOutcome::Revised {
                    revision: next_revision,
                })
            }
        }
    }

    pub fn get_graph_node(&self, node_id: &str) -> GraphStoreResult<Option<GraphNode>> {
        let stored: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT revision, canonical_json FROM sentrdel_graph_node_projection WHERE node_id = ?1",
                params![node_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        stored
            .map(|(revision, canonical)| {
                validate_node_projection(&self.connection, node_id, revision, &canonical)
            })
            .transpose()
    }

    pub fn list_graph_nodes(&self) -> GraphStoreResult<Vec<GraphNode>> {
        let mut statement = self.connection.prepare(
            "SELECT node_id, revision, canonical_json FROM sentrdel_graph_node_projection ORDER BY node_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;

        let mut nodes = Vec::new();
        for row in rows {
            let (node_id, revision, canonical) = row?;
            nodes.push(validate_node_projection(
                &self.connection,
                &node_id,
                revision,
                &canonical,
            )?);
        }
        Ok(nodes)
    }

    /// Persist an edge only when both endpoint node projections already exist.
    pub fn put_graph_edge(&mut self, edge: &GraphEdge) -> GraphStoreResult<GraphWriteOutcome> {
        edge.validate()?;
        let canonical = canonical_json_bytes(edge)?;
        self.require_persistable(PersistentSink::Sqlite, &canonical)?;
        let edge_id = edge.edge_id.as_str().to_owned();
        let source = edge.source.as_str().to_owned();
        let target = edge.target.as_str().to_owned();

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for node_id in [&source, &target] {
            let exists: i64 = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM sentrdel_graph_node_projection WHERE node_id = ?1)",
                params![node_id],
                |row| row.get(0),
            )?;
            if exists != 1 {
                return Err(GraphStoreError::MissingEndpointNode {
                    edge_id,
                    node_id: node_id.clone(),
                });
            }
        }

        let existing: Option<(String, String, i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT source_node_id, target_node_id, revision, canonical_json FROM sentrdel_graph_edge_projection WHERE edge_id = ?1",
                params![edge_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;

        match existing {
            None => {
                transaction.execute(
                    "INSERT INTO sentrdel_graph_edge_projection(edge_id, source_node_id, target_node_id, revision, canonical_json) VALUES (?1, ?2, ?3, 1, ?4)",
                    params![edge_id, source, target, canonical],
                )?;
                transaction.execute(
                    "INSERT INTO sentrdel_graph_edge_history(edge_id, revision, source_node_id, target_node_id, canonical_json) VALUES (?1, 1, ?2, ?3, ?4)",
                    params![edge_id, source, target, canonical],
                )?;
                transaction.commit()?;
                Ok(GraphWriteOutcome::Inserted { revision: 1 })
            }
            Some((stored_source, stored_target, revision, stored)) => {
                let stored_edge = validate_edge_projection(
                    &transaction,
                    &edge_id,
                    &stored_source,
                    &stored_target,
                    revision,
                    &stored,
                )?;
                if stored_edge.source != edge.source
                    || stored_edge.target != edge.target
                    || stored_edge.relation != edge.relation
                {
                    return Err(GraphStoreError::IdentityCollision {
                        object_kind: "graph edge",
                        object_id: edge_id,
                    });
                }
                if stored == canonical {
                    return Ok(GraphWriteOutcome::Unchanged { revision });
                }

                let next_revision =
                    revision
                        .checked_add(1)
                        .ok_or_else(|| GraphStoreError::RevisionOverflow {
                            object_kind: "graph edge",
                            object_id: edge_id.clone(),
                        })?;
                transaction.execute(
                    "UPDATE sentrdel_graph_edge_projection SET revision = ?2, canonical_json = ?3 WHERE edge_id = ?1 AND revision = ?4",
                    params![edge_id, next_revision, canonical, revision],
                )?;
                transaction.execute(
                    "INSERT INTO sentrdel_graph_edge_history(edge_id, revision, source_node_id, target_node_id, canonical_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![edge_id, next_revision, source, target, canonical],
                )?;
                transaction.commit()?;
                Ok(GraphWriteOutcome::Revised {
                    revision: next_revision,
                })
            }
        }
    }

    pub fn get_graph_edge(&self, edge_id: &str) -> GraphStoreResult<Option<GraphEdge>> {
        let stored: Option<(String, String, i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT source_node_id, target_node_id, revision, canonical_json FROM sentrdel_graph_edge_projection WHERE edge_id = ?1",
                params![edge_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        stored
            .map(|(source, target, revision, canonical)| {
                validate_edge_projection(
                    &self.connection,
                    edge_id,
                    &source,
                    &target,
                    revision,
                    &canonical,
                )
            })
            .transpose()
    }

    pub fn list_graph_edges(&self) -> GraphStoreResult<Vec<GraphEdge>> {
        let mut statement = self.connection.prepare(
            "SELECT edge_id, source_node_id, target_node_id, revision, canonical_json FROM sentrdel_graph_edge_projection ORDER BY edge_id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;

        let mut edges = Vec::new();
        for row in rows {
            let (edge_id, source, target, revision, canonical) = row?;
            edges.push(validate_edge_projection(
                &self.connection,
                &edge_id,
                &source,
                &target,
                revision,
                &canonical,
            )?);
        }
        Ok(edges)
    }
}

fn validate_node_projection(
    connection: &Connection,
    node_id: &str,
    revision: i64,
    stored: &[u8],
) -> GraphStoreResult<GraphNode> {
    let node: GraphNode = serde_json::from_slice(stored)?;
    if node.node_id.as_str() != node_id {
        return Err(corrupt(
            "graph node",
            node_id,
            "row key does not match node id",
        ));
    }
    node.validate()?;
    if canonical_json_bytes(&node)? != stored {
        return Err(corrupt(
            "graph node",
            node_id,
            "stored bytes are not canonical JSON",
        ));
    }
    validate_latest_history(
        connection,
        "sentrdel_graph_node_history",
        "node_id",
        node_id,
        revision,
        stored,
        "graph node",
    )?;
    Ok(node)
}

fn validate_edge_projection(
    connection: &Connection,
    edge_id: &str,
    source: &str,
    target: &str,
    revision: i64,
    stored: &[u8],
) -> GraphStoreResult<GraphEdge> {
    let edge: GraphEdge = serde_json::from_slice(stored)?;
    if edge.edge_id.as_str() != edge_id {
        return Err(corrupt(
            "graph edge",
            edge_id,
            "row key does not match edge id",
        ));
    }
    if edge.source.as_str() != source || edge.target.as_str() != target {
        return Err(corrupt(
            "graph edge",
            edge_id,
            "stored endpoint columns do not match canonical edge JSON",
        ));
    }
    edge.validate()?;
    if canonical_json_bytes(&edge)? != stored {
        return Err(corrupt(
            "graph edge",
            edge_id,
            "stored bytes are not canonical JSON",
        ));
    }
    validate_latest_history(
        connection,
        "sentrdel_graph_edge_history",
        "edge_id",
        edge_id,
        revision,
        stored,
        "graph edge",
    )?;
    Ok(edge)
}

fn validate_latest_history(
    connection: &Connection,
    table: &str,
    id_column: &str,
    object_id: &str,
    revision: i64,
    projection: &[u8],
    object_kind: &'static str,
) -> GraphStoreResult<()> {
    let sql =
        format!("SELECT canonical_json FROM {table} WHERE {id_column} = ?1 AND revision = ?2");
    let historical: Option<Vec<u8>> = connection
        .query_row(&sql, params![object_id, revision], |row| row.get(0))
        .optional()?;
    if historical.as_deref() != Some(projection) {
        return Err(corrupt(
            object_kind,
            object_id,
            "current projection does not match its immutable history revision",
        ));
    }
    Ok(())
}

fn corrupt(object_kind: &'static str, object_id: &str, detail: &'static str) -> GraphStoreError {
    GraphStoreError::CorruptStoredObject {
        object_kind,
        object_id: object_id.to_owned(),
        detail,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use rusqlite::params;
    use sentrdel_schema::graph::{
        GraphConfidenceBasis, GraphConfidenceSource, GraphEdge, GraphNode, GraphNodeKind,
        GraphProvenanceId, GraphRelation,
    };
    use serde_json::json;

    use super::{GraphStoreError, GraphWriteOutcome};
    use crate::Store;

    static NEXT_TEMP_DB: AtomicU64 = AtomicU64::new(0);

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEMP_DB.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "sentrdel-graph-{label}-{}-{sequence}.sqlite3",
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

    fn provenance(value: &str) -> GraphProvenanceId {
        GraphProvenanceId::new(value).expect("fixture provenance")
    }

    fn node(key: &str, marker: &str) -> GraphNode {
        GraphNode::new(
            GraphNodeKind::File,
            key,
            BTreeMap::from([("marker".to_owned(), json!(marker))]),
            vec![provenance("evidence:fixture")],
        )
        .expect("fixture node")
    }

    fn edge(source: &GraphNode, target: &GraphNode, marker: &str) -> GraphEdge {
        GraphEdge::new(
            source.node_id.clone(),
            target.node_id.clone(),
            GraphRelation::Refs,
            GraphConfidenceSource::new(
                "fixture-producer",
                Some("1.0.0".to_owned()),
                GraphConfidenceBasis::Extracted,
            )
            .expect("fixture confidence"),
            vec![provenance("evidence:fixture")],
            BTreeMap::from([("marker".to_owned(), json!(marker))]),
        )
        .expect("fixture edge")
    }

    #[test]
    fn node_replay_is_idempotent_and_metadata_change_creates_history() {
        let temp = TempDb::new("node-revisions");
        let mut store = Store::open(&temp.path).expect("store");
        let first = node("src/lib.rs", "one");
        let revised = node("src/lib.rs", "two");
        assert_eq!(first.node_id, revised.node_id);

        assert_eq!(
            store.put_graph_node(&first).expect("insert"),
            GraphWriteOutcome::Inserted { revision: 1 }
        );
        assert_eq!(
            store.put_graph_node(&first).expect("replay"),
            GraphWriteOutcome::Unchanged { revision: 1 }
        );
        assert_eq!(
            store.put_graph_node(&revised).expect("revision"),
            GraphWriteOutcome::Revised { revision: 2 }
        );
        assert_eq!(
            store
                .get_graph_node(revised.node_id.as_str())
                .expect("get")
                .expect("node"),
            revised
        );

        let history_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sentrdel_graph_node_history WHERE node_id = ?1",
                params![first.node_id.as_str()],
                |row| row.get(0),
            )
            .expect("history count");
        assert_eq!(history_count, 2);
    }

    #[test]
    fn edge_fails_closed_without_nodes_then_revises_metadata() {
        let temp = TempDb::new("edge-revisions");
        let mut store = Store::open(&temp.path).expect("store");
        let source = node("src/a.rs", "a");
        let target = node("src/b.rs", "b");
        let first = edge(&source, &target, "one");
        let revised = edge(&source, &target, "two");

        assert!(matches!(
            store.put_graph_edge(&first),
            Err(GraphStoreError::MissingEndpointNode { .. })
        ));
        store.put_graph_node(&source).expect("source");
        store.put_graph_node(&target).expect("target");
        assert_eq!(
            store.put_graph_edge(&first).expect("insert"),
            GraphWriteOutcome::Inserted { revision: 1 }
        );
        assert_eq!(
            store.put_graph_edge(&revised).expect("revision"),
            GraphWriteOutcome::Revised { revision: 2 }
        );
        assert_eq!(
            store
                .get_graph_edge(revised.edge_id.as_str())
                .expect("get")
                .expect("edge"),
            revised
        );
    }

    #[test]
    fn list_order_is_stable_by_canonical_id() {
        let temp = TempDb::new("ordering");
        let mut store = Store::open(&temp.path).expect("store");
        let a = node("src/a.rs", "a");
        let b = node("src/b.rs", "b");
        store.put_graph_node(&b).expect("b");
        store.put_graph_node(&a).expect("a");

        let listed = store.list_graph_nodes().expect("list");
        let ids = listed
            .iter()
            .map(|value| value.node_id.as_str())
            .collect::<Vec<_>>();
        let mut expected = vec![a.node_id.as_str(), b.node_id.as_str()];
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    #[test]
    fn registered_secret_is_rejected_before_graph_persistence() {
        let temp = TempDb::new("redaction");
        let mut store = Store::open(&temp.path).expect("store");
        store
            .register_discovered_secret("fixture-super-secret")
            .expect("secret registration");
        let secret_node = node("src/secret.rs", "fixture-super-secret");

        assert!(matches!(
            store.put_graph_node(&secret_node),
            Err(GraphStoreError::Redaction(_))
        ));
        assert!(store.list_graph_nodes().expect("list").is_empty());
    }

    #[test]
    fn read_detects_projection_history_divergence() {
        let temp = TempDb::new("corruption");
        let mut store = Store::open(&temp.path).expect("store");
        let value = node("src/lib.rs", "one");
        store.put_graph_node(&value).expect("insert");

        store
            .connection
            .execute(
                "UPDATE sentrdel_graph_node_projection SET canonical_json = ?2 WHERE node_id = ?1",
                params![value.node_id.as_str(), b"{}".as_slice()],
            )
            .expect("corrupt projection");

        assert!(store.get_graph_node(value.node_id.as_str()).is_err());
    }

    #[test]
    fn history_rows_are_immutable() {
        let temp = TempDb::new("immutable-history");
        let mut store = Store::open(&temp.path).expect("store");
        let value = node("src/lib.rs", "one");
        store.put_graph_node(&value).expect("insert");

        let result = store.connection.execute(
            "UPDATE sentrdel_graph_node_history SET canonical_json = canonical_json WHERE node_id = ?1 AND revision = 1",
            params![value.node_id.as_str()],
        );
        assert!(result.is_err());
    }
}
