# Spec Kit Consistency Analysis: S1 Security Invariant Regression Core

**Date:** 2026-09-08  
**Scope:** Initial planning consistency analysis before canonical planning qualification.  
**Status:** CONSISTENT_PENDING_CANONICAL_PLANNING_GATE

## Canonical basis

- planning baseline `main@44749137ca5a2071c8b4347fd99c85424e625d22`;
- `.specify/memory/constitution.md` version `1.0.1`;
- `AGENTS.md`;
- active `specs/000-sentrdel-roadmap/roadmap.md` and post-R3 execution blueprint;
- completed R1 Evidence/Coverage/reconciler/policy/kernel authority;
- completed R3 Business-Logic Substrate + Invariants;
- existing canonical Coverage schema;
- existing `sentrdel-graph` stable-ID projection/diff;
- existing SentrdelBench evaluation contracts;
- canonical source-qualification ledger and 2026-09-08 research/provenance boundaries;
- S1 `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, contracts, readiness checklist and task ledger in this candidate.

## Result

The initial S1 planning slice is internally consistent with the Constitution, completed R1/R3 authority, current roadmap priority, existing graph/Coverage/invariant substrate and source/dependency governance.

No product implementation is authorized by this analysis. The initial planning candidate must first complete exact-head applicable CI, substantive independent exact-range review, zero unresolved conversations, guarded expected-head merge, protected-main post-merge required/Cross-platform CI and live repository-governance proof. Planning evidence and readiness/status closeout then require their own non-circular qualification before S1-T002 may begin.

## Consistency checks

| Topic | Result | Planning conclusion |
|---|---|---|
| Rust trusted core | CONSISTENT | Pair validation/matching/comparison remains Rust-owned |
| Evidence Before Verdict | CONSISTENT | Coverage loss/unknown cannot become clean or mitigation |
| Reconciler-only Finding authority | CONSISTENT | S1 output is comparison context, not direct Finding authority |
| Local-first/vendor-neutral | CONSISTENT | No forge/network/provider/model requirement |
| Safe verification boundary | CONSISTENT | No target/provider/runtime execution in S1 |
| Existing graph reuse | CONSISTENT | `GraphProjection::diff` reused; no second graph runtime |
| R3 invariant reuse | CONSISTENT | Existing four evaluation states remain authoritative |
| Stable identity | CONSISTENT | Exact stable identity + definition compatibility; no fuzzy matching |
| Coverage semantics | CONSISTENT | Existing exact Coverage states preserved and compared |
| Added/removed/moved/renamed handling | CONSISTENT | Presence/continuity is separate from security disposition |
| Pairwise history boundary | CONSISTENT | `REINTRODUCED` deferred because two snapshots cannot prove it |
| Public interface sequencing | CONSISTENT | S2 owns CLI/protocol; S3 owns forge |
| Dependency/source governance | CONSISTENT | No new dependency/source/runtime is authorized |
| Evaluation | CONSISTENT | SentrdelBench reused; frozen pair ground truth precedes breadth |
| Resource behavior | CONSISTENT | Hard caps required; no unbounded fuzzy all-pairs matching |

## High-risk semantic checks

### False mitigation from disappearing output

Mitigated in planning. Candidate producer disappearance, `VIOLATED -> UNKNOWN`, unsupported/dynamic semantics, failed/timed-out/skipped required analysis and cap exhaustion cannot be classified as improvement.

### False regression from source churn

Mitigated in planning. Exact stable identity is primary. Source moves and mutable graph metadata remain context. Fuzzy lexical/graph matching is forbidden.

### Stable-ID reuse hiding changed semantics

Mitigated in planning. Invariant kind/scope/requirements are normalized into a compatible definition identity; incompatible reuse fails closed.

### Project invariant deletion hiding a weakened requirement

Mitigated in planning. Base-only valid project invariants remain visible. Candidate absence is not mitigation and requires project-invariant Coverage to distinguish deletion from analysis loss.

### Coverage gain retroactively rewriting history

Mitigated in planning. `UNKNOWN -> supported state` may be coverage gain, but S1 preserves that the base could not establish the prior state and does not invent causal regression/improvement.

### Graph metadata becoming verdict authority

Mitigated in planning. Graph diff is bounded context only and cannot establish causality, identity, Finding authority or epistemic upgrade.

### Premature public UX coupling

Mitigated in planning. S1 freezes internal semantic correctness only. Public CLI/JSON/exit codes and forge behavior remain S2/S3.

## Deferred non-claims

The following are intentionally outside S1 and are not planning defects:

- public local regression CLI/JSON/exit-code contract;
- GitHub/GitLab/forge checks/comments/annotations/credentials;
- IDE/agent delivery;
- multi-revision history and `REINTRODUCED`;
- fuzzy rename matching;
- new invariant/provider/scanner breadth;
- live provider posture or credentials;
- target/runtime execution, verification or exploitability proof;
- autonomous exploitation/remediation;
- new FACT/VERIFIED/Finding/policy authority;
- donor/model/data/container/runtime adoption from research.

## Initial verdict

**CONSISTENT_PENDING_CANONICAL_PLANNING_GATE**

No evidence-backed specification contradiction requires repair before the candidate enters exact-head planning qualification. S1 product implementation remains blocked by S1-T001 and the two intentionally unchecked canonical readiness gates.
