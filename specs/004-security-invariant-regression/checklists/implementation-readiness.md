# Implementation Readiness Checklist — S1 Security Invariant Regression Core

**Date:** 2026-09-08  
**Gate:** Product implementation MUST NOT start until every blocking item is checked and the complete planning slice plus S1-T001 planning closeout/status canonicalization are canonical on protected `main`.

## Scope and authority

- [x] S1 is a bounded pairwise trusted-base/candidate comparison core distinct from S2 local UX, S3 forge delivery, S4 conformance expansion, and S5 bounded verification.
- [x] Base mode is local, offline, deterministic, and Rust-owned.
- [x] Forge/network/provider credentials, hosted-provider connections, target execution, LLM/model use, and external-engine execution are excluded.
- [x] R1 Evidence/Coverage/reconciler/policy/kernel authority remains canonical.
- [x] R3 invariant definitions/evaluation states are reused rather than duplicated.
- [x] Comparison records do not directly create Findings or FACT/VERIFIED authority.
- [x] Existing `sentrdel-graph` is reused; no second graph runtime or universal CPG is introduced.

## Specification quality

- [x] Trusted-base and candidate identities are explicit and role-ordered.
- [x] Snapshot compatibility and producer/config identity are explicit.
- [x] Stable invariant matching and definition-conflict behavior are explicit.
- [x] Regression/improvement/unchanged/unknown semantics are explicit.
- [x] Coverage loss/gain is first-class and cannot become clean by missing output.
- [x] Added/removed/renamed/moved semantic object behavior is explicit.
- [x] Pairwise S1 does not overclaim temporal `REINTRODUCED` state.
- [x] Provenance preservation and graph-diff authority limits are explicit.
- [x] Public CLI/protocol/forge concerns are correctly deferred to S2/S3.
- [x] Success criteria include clean FP, known misses, determinism, provenance/Coverage, authority and resource gates.

## Research quality

- [x] Existing `GraphProjection::diff` stable-ID behavior is documented as reusable substrate.
- [x] Existing R3 stable IDs, invariant definitions/evaluations and limits are documented.
- [x] Existing canonical Coverage states are documented.
- [x] Existing SentrdelBench promotion discipline is reused.
- [x] Source-qualification ledger boundaries are recorded; no 2026-09-08 research artifact is treated as runtime adoption authority.
- [x] Rejected alternatives include Finding-list diff, fuzzy rename matching, model-based judgment, target execution, duplicate graph runtime and premature public schema design.

## Design quality

- [x] Constitution Check is PASS with no exception.
- [x] RevisionPair, SemanticSnapshot, definition identity, pair presence, continuity, Coverage pair and regression record concepts are separated.
- [x] Stable keyed matching precedes any interpretation.
- [x] Base/candidate provenance remains bilateral.
- [x] Exact state matrix preserves UNKNOWN and Coverage semantics.
- [x] `NOT_APPLICABLE` is not incorrectly globally ordered.
- [x] Project invariant deletion cannot masquerade as mitigation.
- [x] Graph diff is context below security judgment.
- [x] Resource caps and fail-visible exhaustion are mandatory.
- [x] No new public schema or dependency is assumed necessary without implementation evidence.

## Contract quality

- [x] Allowed/forbidden revision identity inputs/actions are explicit.
- [x] Mutable refs/forge metadata are insufficient identity proof.
- [x] Snapshot compatibility failures fail visible.
- [x] Stable-ID/definition conflicts fail closed.
- [x] Fuzzy lexical/graph/model identity proof is forbidden.
- [x] Coverage degradation cannot become improvement.
- [x] Producer disappearance remains visible.
- [x] Pairwise historical overclaim is forbidden.
- [x] Comparison output authority remains below reconciler/Finding authority.
- [x] Public interface authority remains S2/S3.

## Evaluation and self-security

- [x] Frozen regression-pair ground truth precedes implementation breadth.
- [x] Clean/no-change and move-only false-positive controls are required.
- [x] Known-ground-truth supported regressions require zero misses for promotion.
- [x] Coverage-loss, producer-disappearance and unknown pairs are qualification cases.
- [x] Deterministic replay includes ordering and internal serialized records.
- [x] Authority canaries cover graph confidence, external/model output and hostile repository metadata.
- [x] Resource/latency qualification and cap-failure behavior are required.
- [x] Protected-holdout policy remains external to candidate-generation logic where applicable.
- [x] New dependency/source adoption requires exact qualification before use.

## Taskability

- [x] Work is decomposed into planning, frozen contracts/ground truth, snapshot/identity substrate, comparison semantics, internal integration/evaluation and closeout.
- [x] Every security-boundary implementation can carry positive/negative/adversarial tests in the same task.
- [x] No task requires S2/S3 public/forge authority.
- [x] Final closeout can use exact-head CI, independent review, guarded expected-head merge, protected-main post-merge CI and live repository-governance proof.

## Canonical gates

- [ ] Initial S1 planning PR is exact-head qualified, independently review-clean, guarded-merged, and post-merge required/Cross-platform CI plus live repository-governance proof are complete on exact protected `main`.
- [ ] S1-T001 planning/readiness closeout is separately exact-head qualified, independently review-clean, guarded-merged, and post-merge governance is proven; only then may the task ledger/roadmap mark S1 implementation-ready through a separately qualified status-canonicalization change.

These two gates are intentionally unchecked in the initial planning candidate. No planning document may self-prove its own GitHub qualification.
