# Implementation Plan: Security Invariant Regression Core

**Branch:** `spec/004-security-invariant-regression`  
**Date:** 2026-09-08  
**Spec:** `specs/004-security-invariant-regression/spec.md`  
**Depends on:** completed R1 and R3; canonical planning baseline `44749137ca5a2071c8b4347fd99c85424e625d22`

## Summary

Build S1 as a bounded deterministic Rust comparison core over two explicit semantic snapshots: a trusted base and a candidate. Reuse canonical R3 invariant evaluations, Coverage, Evidence/provenance references, and the existing `sentrdel-graph` stable-ID projection/diff. Produce internal security-regression records that preserve before/after state and uncertainty without directly creating Findings or widening policy/epistemic authority.

S1 has no forge/network/provider/credential/target-execution/model requirement. S2 owns the public local CLI/protocol contract; S3 owns forge delivery.

## Technical Context

**Language/Version:** Rust 1.98.0 exact trusted-core pin unless separately amended.  
**Existing substrate:** `sentrdel-schema`, `sentrdel-review`, `sentrdel-graph`, canonical Coverage/Evidence/reconciler, R3 business-logic invariants, SentrdelBench.  
**Dependencies:** no new dependency planned. Any implementation-time addition requires exact qualification before use.  
**Primary inputs:** validated local base/candidate revision identities and bounded semantic snapshots.  
**Network:** none.  
**Forge API:** none.  
**Provider credentials:** none.  
**Target execution:** none.  
**LLM/model/external engine:** none.  
**Persistence/public schema:** no new public schema assumed; internal deterministic comparison records first.  
**Quality:** exact-head CI, deterministic pair replay, clean-case FP and known-ground-truth miss/recall gates, coverage/provenance/authority correctness, resource/latency qualification, cross-platform no-authority canaries.

## Constitution Check

| Principle | S1 gate | Result |
|---|---|---|
| Rust Trusted Core | Revision validation, matching, comparison, ordering and authority checks remain Rust-owned | PASS |
| Evidence Before Verdict | Missing/failed/unsupported evidence becomes coverage loss/unknown, never a clean verdict | PASS |
| Vendor-Neutral, Local-First | No forge/provider/model/cloud account is required | PASS |
| Honest/Monotonic Guardrails | Uncertainty cannot be weakened into improvement; comparison does not override policy | PASS |
| Safe Verification | S1 performs no target/runtime/provider execution | PASS |
| Full-Stack Through Packs | S1 compares canonical invariant/coverage semantics without creating shallow detector breadth | PASS |
| Reuse Mature Infrastructure | Reuse R3, `sentrdel-graph`, canonical schema and SentrdelBench | PASS |
| FP/Latency Quality | Frozen clean/regression pairs and resource gates precede promotion | PASS |
| Sentrdel Secures Itself | Inputs are bounded; identities validated; no ambient credentials/network/target execution | PASS |
| Spec Kit Governance | Dedicated S1 spec/design/contracts/readiness/tasks precede implementation | PASS |

**Gate result:** PASS. No constitutional exception is requested.

## Architecture

```text
validated TRUSTED_BASE identity      validated CANDIDATE identity
              |                                   |
              v                                   v
     bounded semantic snapshot             bounded semantic snapshot
       | invariants/evaluations              | invariants/evaluations
       | Coverage                            | Coverage
       | Evidence/provenance                 | Evidence/provenance
       | bounded SSG projection              | bounded SSG projection
       +-------------------+-----------------+
                           |
                           v
              exact compatibility validation
                           |
             stable invariant/object matching
                           |
          +----------------+----------------+
          |                                 |
          v                                 v
  R3 state/Coverage comparison      existing GraphProjection::diff
          |                                 |
          +----------------+----------------+
                           v
            deterministic regression records
           (internal S1 authority only)
                           |
                    SentrdelBench S1
                           |
                     S2 later consumes
```

## Trust Boundaries

1. **Trusted-base identity boundary:** a mutable ref name is not enough; comparison consumes exact validated immutable identity.
2. **Candidate identity boundary:** candidate identity is distinct from trust; being compared does not grant authority.
3. **Snapshot compatibility boundary:** incompatible producer/config/schema semantics cannot be coerced into a verdict.
4. **Stable identity boundary:** exact semantic identity is authoritative for matching; fuzzy similarity is not.
5. **Invariant-definition boundary:** stable ID reuse with incompatible kind/scope/requirements fails closed.
6. **Coverage boundary:** missing capability cannot become clean or mitigation.
7. **Graph boundary:** graph diff/reachability is context, not causality or epistemic authority.
8. **Provenance boundary:** base and candidate evidence chains remain separate and immutable in the pair result.
9. **Finding boundary:** S1 does not directly mint canonical Findings.
10. **Benchmark boundary:** candidate logic cannot control qualification ground truth/holdouts.
11. **Source/dependency boundary:** research references do not authorize runtime/dependency adoption.

## Planned Components

Implementation module names are planning targets, not public API commitments.

### `crates/sentrdel-review/src/regression/`

- `mod.rs` — bounded internal orchestration.
- `model.rs` — revision pair, semantic snapshot references, match/continuity state, pairwise disposition, deterministic result identity, limits.
- `revision.rs` — exact local revision/snapshot identity validation without forge/network discovery.
- `match.rs` — keyed invariant/semantic-object matching and definition compatibility validation.
- `coverage.rs` — stable Coverage pair comparison and coverage-loss/gain semantics.
- `invariant.rs` — R3 evaluation-state transition matrix.
- `graph.rs` — adapter around existing `GraphProjection::diff`; no new graph runtime.
- `compare.rs` — deterministic pair comparison and ordering.

Actual placement may be consolidated if a smaller module surface is clearer. Public API expansion is not assumed.

## Data-flow Strategy

### RevisionPair

A pair binds:

- comparison contract version;
- exact trusted-base revision identity;
- exact candidate revision identity;
- deterministic pair ID.

Role order is fixed. A reversed pair is a different comparison.

### SemanticSnapshot

A snapshot minimally carries or references:

- exact revision identity;
- compatible snapshot/producer/config identity;
- invariant definitions;
- invariant evaluations;
- applicable Coverage;
- bounded supporting Evidence/provenance identity;
- bounded graph projection/digest required for context.

The snapshot is not a new universal persisted schema by default; implementation should prefer internal typed composition of existing canonical records.

### InvariantMatch

Matching uses exact stable identity plus compatible definition semantics. It records:

- pair presence (`MATCHED`, `BASE_ONLY`, `CANDIDATE_ONLY`);
- continuity basis (`EXACT_STABLE_ID`, optional separately proven deterministic move/continuity witness, or `UNMATCHED`);
- definition compatibility;
- before/after evaluation and coverage references.

Fuzzy matching is excluded.

### SecurityRegressionRecord

Internal record fields should include:

- deterministic regression ID;
- revision-pair ID;
- invariant ID or explicitly unmatched side identities;
- pair presence/continuity;
- base state and candidate state where present;
- `REGRESSION | IMPROVEMENT | UNCHANGED | UNKNOWN | COVERAGE_LOST | COVERAGE_GAINED`;
- machine-stable reason code;
- before/after Coverage summaries;
- bounded before/after Evidence/provenance references;
- bounded graph-diff context where relevant;
- diagnostics/cap state.

This record is not a Finding and does not independently gain FACT/VERIFIED authority.

## Pairwise Comparison Matrix

The implementation contract must encode explicit rules, including:

| Base | Candidate | Minimum disposition when compatible/sufficient |
|---|---|---|
| `SATISFIED` | `VIOLATED` | `REGRESSION` |
| `VIOLATED` | `SATISFIED` | `IMPROVEMENT` |
| `SATISFIED` | `SATISFIED` | `UNCHANGED` unless coverage degraded materially |
| `VIOLATED` | `VIOLATED` | `UNCHANGED` unless coverage degraded materially |
| `SATISFIED` | `UNKNOWN` | `COVERAGE_LOST` when visibility degraded; otherwise `UNKNOWN` |
| `VIOLATED` | `UNKNOWN` | never improvement; `COVERAGE_LOST` or `UNKNOWN` |
| `UNKNOWN` | supported state | `COVERAGE_GAINED` when visibility improved; candidate state preserved |
| any | incompatible snapshot/definition | `UNKNOWN` / comparison unavailable |

`NOT_APPLICABLE`, added/removed definitions, and semantic-object absence require explicit presence/coverage rules rather than a generic enum ordering.

## Added/Removed/Renamed/Moved Strategy

- **Moved source, same stable ID:** match; preserve old/new provenance; movement is metadata.
- **Modified metadata, same stable ID:** match; GraphDiff may provide context; no verdict solely from metadata.
- **Rename changing stable ID:** no match unless a deterministic canonical continuity witness is separately available; otherwise base-only/candidate-only and uncertainty remain visible.
- **Candidate-added object/invariant:** strong `REGRESSION`/`IMPROVEMENT` semantics require base coverage proving absence; otherwise preserve unknown/coverage state.
- **Candidate-removed vulnerable path:** improvement requires candidate coverage proving semantic absence and continued invariant authority; producer/config/invariant disappearance cannot masquerade as a fix.
- **Candidate-removed project invariant:** record requirement removal visibly; do not call it mitigation merely because evaluation vanished.

## Coverage Strategy

Coverage records are paired by stable comparison key derived from existing capability/scope/producer/provider-dimension identity. The comparator preserves the exact existing Coverage states rather than collapsing all gaps into one boolean.

A security-relevant candidate downgrade from usable supported coverage to a gap becomes `COVERAGE_LOST`. A gain from a base gap to supported coverage becomes `COVERAGE_GAINED`, while the newly observable candidate invariant state remains explicit.

If producer/config compatibility cannot be established, the comparison is unknown rather than silently normalizing across different analysis capabilities.

## Resource Strategy

Prefer ordered keyed maps/sets and linearithmic stable-ID matching. Do not perform unbounded all-pairs fuzzy matching.

Implementation must freeze hard caps for:

- snapshot invariant/evaluation records;
- Coverage records;
- graph nodes/edges consumed for context;
- pair results;
- evidence/provenance refs per result;
- diagnostics;
- total comparison bytes/work.

Exact values should be chosen from existing R3/graph/review ceilings and measured SentrdelBench behavior. Cap exhaustion is observable coverage/diagnostic state, never silent truncation.

## Evaluation Strategy

Freeze revision-pair fixture metadata before product comparison breadth. Required pair families:

- identical clean replay;
- safe semantic change;
- `SATISFIED -> VIOLATED`;
- `VIOLATED -> SATISFIED`;
- `SATISFIED -> UNKNOWN`;
- `VIOLATED -> UNKNOWN`;
- `UNKNOWN -> supported state`;
- producer disappearance/failure/timeout/unsupported;
- move-only exact identity;
- graph-metadata-only modification;
- ambiguous rename/unmatched remove/add;
- added/removed semantic object with complete and incomplete counterpart coverage;
- project invariant removal;
- stable-ID/definition conflict;
- hostile/instruction-shaped metadata;
- probabilistic/external authority canaries;
- input-order replay;
- resource-cap exhaustion.

Promotion gates reuse SentrdelBench active clean-case FP policy, zero known misses for declared supported regression ground truth, deterministic replay, provenance/Coverage correctness, authority boundaries, protected holdout policy, and measured resource/latency constraints.

## Implementation Phases

### Phase A — Canonical planning gate

Canonicalize this complete planning slice, then independently record/qualify planning evidence and implementation-readiness status before any product code task.

### Phase B — Pair contracts and frozen ground truth

Freeze revision-pair/snapshot compatibility, internal regression model, exact transition matrix, fixture pairs and benchmark metadata before implementation breadth.

### Phase C — Identity/snapshot comparison substrate

Implement exact revision validation, stable keyed invariant/object matching, definition compatibility, provenance preservation, Coverage pairing and bounded GraphDiff context.

### Phase D — Regression semantics

Implement deterministic invariant-state, Coverage, added/removed/move/rename, reason-code, ordering, and cap semantics with positive/negative/adversarial tests.

### Phase E — Internal integration and evaluation

Integrate the internal comparator with existing R3 semantic outputs and SentrdelBench without freezing S2 public UX. Qualify clean FP, known misses, replay, authority, resource/latency, dependency/source governance, and cross-platform behavior.

### Phase F — Converge and close

Run final Spec Kit analysis, implementation closeout, exact-head CI/review, guarded merge, protected-main post-merge CI and live governance, then canonically close the S1 task ledger. Only then may S2 planning become the dependency-ordered frontier.

## Complexity / Exceptions

No constitutional exception is requested. No new dependency, public schema, forge/network credential, provider connection, target execution, model/LLM, or external engine is planned for S1.
