//! Bounded graph context for reconciled Findings.
//!
//! This module reports stable graph identity, before/after symbol presence, and
//! bounded reverse reachability only. Reachability is context, not runtime
//! causality, exploitability, or proof that a changed symbol caused a Finding.

use sentrdel_graph::{
    GraphContractError, GraphNodeId, GraphNodeKind, GraphProjection, GraphProjectionError,
    GraphRelation, ReverseReachabilityHit, stable_node_id,
};
use sentrdel_schema::finding::Finding;
use std::collections::BTreeSet;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolGraphState {
    Added,
    Removed,
    Modified,
    Unchanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphSnapshotSide {
    Before,
    After,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingSymbolContext {
    pub semantic_key: String,
    pub node_id: GraphNodeId,
    pub state: SymbolGraphState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingReachabilityContext {
    pub seed_node_id: GraphNodeId,
    pub snapshot: GraphSnapshotSide,
    pub hits: Vec<ReverseReachabilityHit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingGraphContext {
    pub finding_id: String,
    pub symbols: Vec<FindingSymbolContext>,
    pub reachability: Vec<FindingReachabilityContext>,
    pub unresolved_symbol_subjects: Vec<String>,
}

#[derive(Debug)]
pub enum FindingGraphContextError {
    GraphContract(GraphContractError),
    Projection(GraphProjectionError),
}

impl fmt::Display for FindingGraphContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GraphContract(error) => {
                write!(formatter, "cannot derive stable symbol identity: {error}")
            }
            Self::Projection(error) => write!(formatter, "cannot derive bounded graph context: {error}"),
        }
    }
}

impl std::error::Error for FindingGraphContextError {}

impl From<GraphContractError> for FindingGraphContextError {
    fn from(value: GraphContractError) -> Self {
        Self::GraphContract(value)
    }
}

impl From<GraphProjectionError> for FindingGraphContextError {
    fn from(value: GraphProjectionError) -> Self {
        Self::Projection(value)
    }
}

/// Attach bounded before/after graph context to one canonical Finding.
///
/// Symbol subjects use the existing `symbol:<semantic-key>` convention from
/// `Finding::draft().affected_subjects`. Stable node identity determines whether
/// a symbol was added, removed, modified, or unchanged. Reverse reachability is
/// queried independently on each snapshot and retains graph witness edges.
/// Nothing in this function upgrades Evidence epistemic authority or asserts
/// that a reachable node is security-impacted at runtime.
pub fn build_finding_graph_context(
    finding: &Finding,
    before: &GraphProjection,
    after: &GraphProjection,
    max_depth: usize,
    allowed_relations: &BTreeSet<GraphRelation>,
) -> Result<FindingGraphContext, FindingGraphContextError> {
    let semantic_keys: BTreeSet<_> = finding
        .draft()
        .affected_subjects
        .iter()
        .filter_map(|subject| subject.strip_prefix("symbol:"))
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect();

    let mut symbols = Vec::new();
    let mut reachability = Vec::new();
    let mut unresolved_symbol_subjects = Vec::new();

    for semantic_key in semantic_keys {
        let node_id = stable_node_id(GraphNodeKind::Symbol, &semantic_key)?;
        let before_node = before.node(&node_id);
        let after_node = after.node(&node_id);

        let state = match (before_node, after_node) {
            (None, None) => {
                unresolved_symbol_subjects.push(semantic_key);
                continue;
            }
            (None, Some(_)) => SymbolGraphState::Added,
            (Some(_), None) => SymbolGraphState::Removed,
            (Some(left), Some(right)) if left != right => SymbolGraphState::Modified,
            (Some(_), Some(_)) => SymbolGraphState::Unchanged,
        };

        if before_node.is_some() {
            reachability.push(FindingReachabilityContext {
                seed_node_id: node_id.clone(),
                snapshot: GraphSnapshotSide::Before,
                hits: before.reverse_reachability(&node_id, max_depth, allowed_relations)?,
            });
        }
        if after_node.is_some() {
            reachability.push(FindingReachabilityContext {
                seed_node_id: node_id.clone(),
                snapshot: GraphSnapshotSide::After,
                hits: after.reverse_reachability(&node_id, max_depth, allowed_relations)?,
            });
        }

        symbols.push(FindingSymbolContext {
            semantic_key,
            node_id,
            state,
        });
    }

    symbols.sort_by(|left, right| left.semantic_key.cmp(&right.semantic_key));
    reachability.sort_by(|left, right| {
        left.seed_node_id
            .cmp(&right.seed_node_id)
            .then_with(|| snapshot_rank(left.snapshot).cmp(&snapshot_rank(right.snapshot)))
    });
    unresolved_symbol_subjects.sort();

    Ok(FindingGraphContext {
        finding_id: finding.finding_id().to_owned(),
        symbols,
        reachability,
        unresolved_symbol_subjects,
    })
}

const fn snapshot_rank(side: GraphSnapshotSide) -> u8 {
    match side {
        GraphSnapshotSide::Before => 0,
        GraphSnapshotSide::After => 1,
    }
}
