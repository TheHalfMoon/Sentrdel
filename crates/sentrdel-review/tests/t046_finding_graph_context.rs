use sentrdel_graph::{
    GraphConfidenceBasis, GraphConfidenceSource, GraphEdge, GraphNode, GraphNodeKind,
    GraphProjection, GraphProvenanceId, GraphRelation,
};
use sentrdel_review::context::{GraphSnapshotSide, SymbolGraphState, build_finding_graph_context};
use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::finding::{
    EpistemicState, Finding, ReconciledFindingDraft, ReconcilerAuthority, Severity,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn provenance() -> GraphProvenanceId {
    GraphProvenanceId::new("evidence:t046").unwrap()
}

fn symbol(key: &str, revision: &str) -> GraphNode {
    let mut attributes = BTreeMap::new();
    attributes.insert("revision".to_owned(), Value::String(revision.to_owned()));
    GraphNode::new(GraphNodeKind::Symbol, key, attributes, vec![provenance()]).unwrap()
}

fn calls(source: &GraphNode, target: &GraphNode) -> GraphEdge {
    GraphEdge::new(
        source.node_id.clone(),
        target.node_id.clone(),
        GraphRelation::Calls,
        GraphConfidenceSource::new(
            "fixture",
            Some("1".to_owned()),
            GraphConfidenceBasis::Extracted,
        )
        .unwrap(),
        vec![provenance()],
        BTreeMap::new(),
    )
    .unwrap()
}

fn finding(subjects: Vec<&str>) -> Finding {
    let reconciler = ReconcilerAuthority::from_runtime("reconciler", "sha256:t046").unwrap();
    Finding::new_reconciled(
        ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint: "sha256:t046-finding".to_owned(),
            title: "Fixture finding".to_owned(),
            impact_statement: "Fixture impact".to_owned(),
            category: "fixture".to_owned(),
            severity: Severity::High,
            epistemic_state: EpistemicState::Detected,
            evidence_ids: vec!["sha256:evidence".to_owned()],
            contradiction_ids: Vec::new(),
            primary_location: Some("src/service.rs".to_owned()),
            affected_subjects: subjects.into_iter().map(str::to_owned).collect(),
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: None,
            updated_at: "2026-08-28T19:00:00Z".to_owned(),
        },
        &reconciler,
    )
    .unwrap()
}

#[test]
fn modified_symbol_keeps_before_and_after_reachability_without_causality_claims() {
    let service_before = symbol("crate::service", "before");
    let service_after = symbol("crate::service", "after");
    let api_before = symbol("crate::api", "same");
    let api_after = symbol("crate::api", "same");
    let worker_after = symbol("crate::worker", "new");

    let before = GraphProjection::from_records(
        vec![api_before.clone(), service_before.clone()],
        vec![calls(&api_before, &service_before)],
    )
    .unwrap();
    let after = GraphProjection::from_records(
        vec![
            worker_after.clone(),
            service_after.clone(),
            api_after.clone(),
        ],
        vec![
            calls(&worker_after, &service_after),
            calls(&api_after, &service_after),
        ],
    )
    .unwrap();

    let context = build_finding_graph_context(
        &finding(vec!["symbol:crate::service"]),
        &before,
        &after,
        2,
        &BTreeSet::from([GraphRelation::Calls]),
    )
    .unwrap();

    assert_eq!(context.symbols.len(), 1);
    assert_eq!(context.symbols[0].semantic_key, "crate::service");
    assert_eq!(context.symbols[0].state, SymbolGraphState::Modified);
    assert!(context.unresolved_symbol_subjects.is_empty());
    assert_eq!(context.reachability.len(), 2);

    let before_context = context
        .reachability
        .iter()
        .find(|value| value.snapshot == GraphSnapshotSide::Before)
        .unwrap();
    assert_eq!(before_context.hits.len(), 1);
    assert_eq!(before_context.hits[0].node_id, api_before.node_id);

    let after_context = context
        .reachability
        .iter()
        .find(|value| value.snapshot == GraphSnapshotSide::After)
        .unwrap();
    assert_eq!(after_context.hits.len(), 2);
    let after_ids: BTreeSet<_> = after_context
        .hits
        .iter()
        .map(|hit| hit.node_id.clone())
        .collect();
    assert_eq!(
        after_ids,
        BTreeSet::from([api_after.node_id, worker_after.node_id])
    );
}

#[test]
fn added_and_unresolved_symbols_preserve_only_observable_snapshot_state() {
    let added = symbol("crate::added", "new");
    let caller = symbol("crate::caller", "same");
    let before =
        GraphProjection::from_records(Vec::<GraphNode>::new(), Vec::<GraphEdge>::new()).unwrap();
    let after = GraphProjection::from_records(
        vec![added.clone(), caller.clone()],
        vec![calls(&caller, &added)],
    )
    .unwrap();

    let context = build_finding_graph_context(
        &finding(vec!["symbol:crate::missing", "symbol:crate::added"]),
        &before,
        &after,
        1,
        &BTreeSet::from([GraphRelation::Calls]),
    )
    .unwrap();

    assert_eq!(context.symbols.len(), 1);
    assert_eq!(context.symbols[0].state, SymbolGraphState::Added);
    assert_eq!(context.reachability.len(), 1);
    assert_eq!(context.reachability[0].snapshot, GraphSnapshotSide::After);
    assert_eq!(context.reachability[0].hits[0].node_id, caller.node_id);
    assert_eq!(context.unresolved_symbol_subjects, vec!["crate::missing"]);
}
