# Research: Security Invariant Regression Core

**Date:** 2026-09-08  
**Scope:** Repository-grounded S1 planning research only. No new source/dependency/runtime adoption is authorized by this document.

## Research question

What is the smallest trustworthy comparison core that can answer: **what security property did this candidate weaken relative to an exact trusted base, and what evidence or missing coverage limits that conclusion?**

## Canonical substrate findings

### Existing graph projection/diff is sufficient substrate

`crates/sentrdel-graph/src/projection.rs` already provides:

- validated in-memory projection from canonical graph records;
- deterministic stable-ID ordering through ordered maps/sets;
- duplicate identity and missing-endpoint fail-closed behavior;
- bounded reverse reachability;
- stable-ID graph diff with added/removed/modified nodes and edges;
- preservation of mutable metadata/provenance/confidence changes as modifications rather than false remove/add pairs.

Decision: S1 reuses this substrate. It does not add a second graph runtime, universal CPG, or fuzzy graph identity layer. Graph diff remains context below invariant/coverage semantics.

### R3 already owns the invariant semantics S1 needs to compare

`crates/sentrdel-review/src/business_logic/model.rs` already defines bounded stable semantic IDs, resource/provenance caps, cross-layer paths, invariant definitions, and the four evaluation states:

- `Satisfied`;
- `Violated`;
- `Unknown`;
- `NotApplicable`.

R3 also distinguishes built-in and tightening-only project declarations and carries supporting/contradicting observation IDs, coverage reasons, and source provenance.

Decision: S1 compares these semantics rather than duplicating evaluator logic or inventing a severity scale.

### Canonical Coverage already represents loss modes explicitly

`crates/sentrdel-schema/src/coverage.rs` distinguishes:

- `Covered`;
- `Partial`;
- `Unsupported`;
- `Unavailable`;
- `Failed`;
- `TimedOut`;
- `SkippedByPolicy`.

Decision: S1 preserves this vocabulary and introduces comparison semantics over it. Any state other than sufficiently applicable `Covered` remains a gap when the comparison requires proof.

### Existing SentrdelBench is the evaluator

R3 already promoted invariant fixtures through SentrdelBench with deterministic replay, clean-case false-positive controls, declared known-miss/recall expectations, provenance/coverage assertions, authority canaries, protected-holdout separation, and latency/resource qualification.

Decision: S1 extends the existing benchmark plane with frozen **revision-pair** fixtures. It does not create a second evaluator or allow candidate-generation logic to control its own ground truth.

## Pairwise semantics research decisions

### Why not use a generic diff-aware finding list?

A list diff cannot distinguish:

- a fixed issue from a vanished producer;
- a new violation from newly gained coverage;
- a moved semantic object from a deleted-and-added pair;
- a real security-property weakening from source churn;
- a disappearing project invariant from genuine mitigation.

Decision: comparison is over explicit invariant state + Coverage + semantic identity + provenance, with graph diff as bounded context.

### Why not infer `REINTRODUCED`?

Reintroduction requires at least three temporal facts: present/violated, later absent/mitigated, then present/violated again. A base/candidate pair carries only two states.

Decision: pairwise S1 does not emit `REINTRODUCED`. A later temporal-history spec may add it with exact historical evidence.

### Why not make `MOVED` a regression class?

Movement concerns continuity/location, not security state. Exact stable identity can remain unchanged while source provenance moves.

Decision: movement is metadata. Security disposition is separately determined.

### Why not fuzzy-match renames?

Fuzzy matching can incorrectly join distinct auth paths, resources, routes, or invariants and create false causal/security conclusions. Graph similarity is especially dangerous because similar neighborhoods are common in repeated application patterns.

Decision: exact stable identity or a future deterministic continuity witness only. Unmatched ambiguity stays visible.

### What does coverage loss mean?

Coverage loss is any candidate degradation that removes the evidence needed to maintain a supported comparison: a formerly covered capability becomes partial/unsupported/unavailable/failed/timed out/skipped, a required producer disappears, a dynamic construct becomes unresolved, or a resource cap prevents the required observation.

Decision: coverage loss is a first-class security disposition and cannot be hidden by an empty candidate issue list.

## Source qualification boundary

The canonical source ledger already records:

- `petgraph 0.8.3` as qualified for bounded in-memory graph projection through PGQ-001;
- selected Graphify graph-diff/affected/blast-radius concepts as qualified for selective native Rust port through GQ-001, while donor runtime remains excluded;
- R3's qualified TypeScript grammar and existing dependency closure.

The 2026-09-08 source-study records are research/provenance. They do not authorize source copying, dependency/model/data/container adoption, external-engine execution, network access, provider credentials, or target execution.

Decision: S1 planning adds no dependency and copies no donor code. If implementation later proves a missing capability, exact source/dependency qualification precedes adoption.

## Rejected alternatives

### Rebuild graph comparison in a new package

Rejected. Existing `sentrdel-graph` already owns stable graph projection/diff. A duplicate runtime would create identity and authority drift.

### Compare only Findings

Rejected. Findings are reconciled outputs and can disappear when coverage changes. S1 must see invariant/Coverage/evidence state to distinguish mitigation from lost visibility.

### Treat an absent candidate result as fixed

Rejected. Absence is meaningful only if candidate scope and coverage prove the object/property is absent or satisfied.

### Use model/LLM judgment for rename or regression classification

Rejected. Model output is below FACT/VERIFIED/Finding authority and would make deterministic replay impossible.

### Execute the target to resolve uncertainty

Rejected for S1. Runtime verification belongs to later bounded verification authority (S5/R6) and cannot be smuggled into the static regression core.

### Add public CLI/JSON output now

Rejected. S2 is deliberately the local developer contract slice. S1 should first freeze trustworthy comparison semantics without coupling them to presentation or exit-code policy.

## Research conclusion

The repository already contains the primitives required for a conservative S1: exact canonical identities, R3 invariant evaluations, explicit Coverage, bounded provenance, stable graph projection/diff, and SentrdelBench. The design problem is not acquiring another engine; it is freezing pairwise security semantics that preserve uncertainty and authority. No new dependency or public schema is justified by current evidence.
