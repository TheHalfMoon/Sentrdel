# Clarification Closeout: Security Invariant Regression Core

**Date:** 2026-09-08  
**Status:** CLOSED_FOR_PLANNING

## Frozen decisions

1. **S1 is pairwise and deterministic.** It compares exactly one trusted-base snapshot with one candidate snapshot. Multi-revision temporal history is not part of S1.
2. **Exact revision identity precedes comparison.** Branch names, PR numbers, display labels, timestamps, or forge assertions do not establish immutable base/candidate identity.
3. **S1 is not a forge feature.** Forge discovery/delivery is S3. S1 requires no network or forge credential.
4. **S1 does not own public UX.** S2 freezes `sentrdel review`, `explain`, machine-readable output, and exit-code behavior. S1 may expose only the minimal internal Rust contract required for deterministic comparison and tests.
5. **Existing R3 invariant states remain authoritative.** S1 compares `SATISFIED`, `VIOLATED`, `UNKNOWN`, and `NOT_APPLICABLE`; it does not create a second invariant evaluator or severity lattice.
6. **Pairwise disposition is conservative.** The frozen planning vocabulary is `REGRESSION`, `IMPROVEMENT`, `UNCHANGED`, `UNKNOWN`, `COVERAGE_LOST`, and `COVERAGE_GAINED`, with exact before/after state and reason preserved.
7. **`REINTRODUCED` is deferred.** Two snapshots cannot prove that a condition existed, disappeared, and later returned. S1 must not manufacture historical claims.
8. **`MOVED` is continuity metadata, not a verdict.** Exact stable identity may survive a source move. A move by itself is neither a regression nor an improvement.
9. **No fuzzy identity.** Lexical similarity, edit distance, line movement, graph similarity, model output, or confidence scores are not identity proof.
10. **Stable-ID conflicts fail closed.** One stable identity cannot silently represent incompatible invariant kind/scope/requirements between snapshots.
11. **Coverage is part of the comparison, not an afterthought.** `SATISFIED -> UNKNOWN`, producer disappearance, unsupported/dynamic semantics, failures, timeouts, skipped analysis, and cap exhaustion cannot become clean results.
12. **Missing candidate evidence cannot prove mitigation.** `VIOLATED -> UNKNOWN` is never an improvement. `VIOLATED -> SATISFIED` requires sufficient compatible candidate coverage/evidence.
13. **Coverage gain is not retroactive causality.** `UNKNOWN -> SATISFIED` or `UNKNOWN -> VIOLATED` may record gained visibility while preserving the candidate state; it does not rewrite what the base could not prove.
14. **Base absence must be proven, not assumed.** Added/removed semantic objects can support strong conclusions only where the corresponding snapshot scope and coverage establish true absence.
15. **Project invariant deletion stays visible.** Removing a valid tightening-only invariant cannot be called mitigation merely because the candidate no longer evaluates it.
16. **Graph diff is context only.** Existing `GraphProjection::diff` is reused; add/remove/modify records do not prove causality, rename identity, or security state by themselves.
17. **Provenance is bilateral.** Base and candidate provenance/evidence references remain separately addressable; candidate records never overwrite base history.
18. **Finding authority is unchanged.** S1 comparison records cannot create canonical Findings or upgrade epistemic authority; the existing reconciler remains sole Finding authority.
19. **No new dependency is assumed.** Existing graph, R3, Coverage, canonical identity, and SentrdelBench substrate is sufficient for planning. Any implementation-time dependency requires exact qualification first.
20. **No donor/runtime adoption from research.** The 2026-09-08 source study is planning/provenance only unless the canonical source ledger grants exact stronger authority.

## Resolved ambiguities

### Is `SATISFIED -> UNKNOWN` a vulnerability?

Not by itself. S1 may not claim `VIOLATED` without evidence. It is nevertheless a security-regression signal because the candidate lost a previously provable property. If candidate coverage degraded, classify it `COVERAGE_LOST`; otherwise preserve `UNKNOWN`.

### Is `VIOLATED -> UNKNOWN` an improvement?

No. The candidate has not proven the property safe. Coverage loss or uncertainty remains explicit.

### Is an unchanged `VIOLATED` state a new regression?

No. Pairwise S1 records it as `UNCHANGED` when snapshots are compatible and coverage is sufficient. S2 may later present that state as pre-existing without changing semantics.

### Can S1 call a newly observed candidate violation `NEW`?

Only a later presentation layer may use that term when S1 proves the necessary base absence/state and compatible coverage. S1 keeps the exact pairwise disposition and reason rather than overloading one label with causal assumptions.

### Can a renamed route be matched by graph neighborhood similarity?

No. Similarity may be research/debug context only. Canonical matching requires exact stable identity or a separately frozen deterministic continuity witness.

### Does deleting a vulnerable path prove mitigation?

Only if candidate semantics and coverage deterministically prove the relevant path/object is absent and the invariant requirement itself was not merely deleted or made unsupported. Otherwise the result is unknown or coverage loss.

### Does a GraphDiff modified node prove a security regression?

No. It proves only a bounded record difference for one stable identity. Invariant and coverage comparison determine the security disposition.

### Does S1 need a new JSON schema?

No planning evidence currently justifies one. The core can be implemented behind an internal Rust contract and benchmark fixtures. S2 owns the public versioned regression output. Any earlier schema need requires a minimal separately justified change.

## Planning gate

No unresolved clarification blocks design/task planning. Product implementation remains blocked until the complete S1 planning slice is internally consistent, exact-head qualified, independently reviewed, guarded-merged into protected `main`, post-merge CI and live repository-governance are proven, and the separate S1-T001 planning/readiness closeout plus status canonicalization are themselves canonical and post-merge proven.
