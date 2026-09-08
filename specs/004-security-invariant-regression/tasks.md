# Tasks: Security Invariant Regression Core

**Input:** Constitution, roadmap, completed R1/R3 contracts, S1 `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, `contracts/revision-pair-contract.md`, `contracts/security-regression-contract.md`, and `checklists/implementation-readiness.md`.  
**Status:** IMPLEMENTATION_READY — S1-T001 planning/readiness evidence is proven; product implementation may begin only after this status-canonicalization change completes its own protected-main qualification and governance proof.

## Format

`- [ ] S1-T### [P?] Description`

`[P]` means safely parallel only after all stated prerequisites are canonical.

---

## Phase 0 — Canonical planning gate

- [x] **S1-T001** Canonicalize the complete S1 Spec Kit planning slice on protected `main`: exact-head applicable CI, substantive independent exact-range review, zero unresolved conversations, guarded expected-head merge, post-merge required and Cross-platform CI, live repository-governance proof, then separately canonicalize planning-gate evidence, planning-closeout evidence, final implementation-readiness gates, roadmap implementation-ready status and this task checkbox without allowing a status document to self-prove its own qualification. **Blocks every product implementation task below until this status-canonicalization change is itself canonical and post-merge proven.**

**Checkpoint:** S1 planning/readiness evidence is complete and roadmap status may be `implementation-ready`. No S1 product code is written until this status-canonicalization change itself completes exact-head qualification, guarded expected-head merge, protected-main required/Cross-platform CI, live repository-governance proof, and temporary evidence cleanup.

---

## Phase 1 — Frozen pair contracts and ground truth

- [x] **S1-T002** Freeze the internal revision-pair/snapshot contract: exact trusted-base/candidate role identity, deterministic pair ID, snapshot contract/producer/config compatibility and fixture-only synthetic identity; no forge/network discovery.
- [x] **S1-T003** [P] Create frozen synthetic before/after fixture pairs for identical clean replay, safe semantic change, proven regression, proven improvement, unknown, coverage loss/gain, producer disappearance, move-only continuity, ambiguous rename/unmatched, added/removed objects, project invariant removal, definition conflict, graph-metadata-only change, hostile metadata and resource caps.
- [x] **S1-T004** [P] Extend SentrdelBench metadata for S1 pair ground truth, clean-case false-positive controls, declared supported regression/miss expectations, Coverage/provenance assertions, authority assertions and protected-holdout eligibility before comparison implementation breadth.
- [x] **S1-T005** Freeze the bounded internal regression model and deterministic reason-code/state matrix from `data-model.md`; preserve before/after state, presence, continuity, Coverage and bilateral provenance; no public schema widening unless separately justified.
- [x] **S1-T006** Freeze authority fixtures proving comparison records cannot directly create Findings, mint FACT/VERIFIED authority, override policy/kernel/reconciler decisions, turn graph/model/external confidence into authority, or turn missing output into PASS.

**Checkpoint:** exact pair semantics and immutable evaluation ground truth are canonical before comparison implementation.

---

## Phase 2 — Revision, snapshot, and identity substrate

- [x] **S1-T007** Implement bounded exact local revision identity validation and RevisionPair construction, including commit/tree binding where available, role ordering, fixture-only identity namespace, malformed/mismatched identity rejection and no forge/network/target-execution path.
- [x] **S1-T008** Implement bounded SemanticSnapshot composition/validation over existing canonical R3 invariant/evaluation, Coverage, Evidence/provenance and graph records; validate producer/config/schema compatibility before comparison.
- [ ] **S1-T009** Implement stable keyed invariant matching with normalized definition digest/compatibility; same stable ID with incompatible kind/scope/requirements fails closed as definition conflict.
- [ ] **S1-T010** Implement exact semantic-object continuity handling using existing stable IDs and the current `sentrdel-graph` projection/diff only as context; no fuzzy lexical/graph/model rename identity.
- [ ] **S1-T011** Implement bilateral bounded Evidence/provenance preservation and deterministic normalization so candidate records cannot overwrite base history.
- [ ] **S1-T012** Implement stable Coverage pairing by capability/scope/producer/provider-dimension identity with explicit compatibility diagnostics and full existing Coverage-state preservation.
- [ ] **S1-T013** Add positive/negative/adversarial substrate tests for mutable-ref drift, mismatched snapshot revision, duplicate/conflicting stable IDs, incompatible producer/config, move-only provenance, rename ambiguity, hostile metadata, input-order changes and cap exhaustion.

**Checkpoint:** S1 can safely establish which exact semantic records are comparable before producing any security disposition.

---

## Phase 3 — Security regression comparison semantics

- [ ] **S1-T014** Implement the frozen R3 invariant evaluation-state transition matrix for `REGRESSION`, `IMPROVEMENT`, `UNCHANGED`, `UNKNOWN`, `COVERAGE_LOST` and `COVERAGE_GAINED`; preserve exact before/after states and reason codes.
- [ ] **S1-T015** Implement first-class candidate Coverage regression/gain detection; producer disappearance, failure, timeout, unsupported/dynamic semantics, skipped required capability and cap exhaustion cannot become clean or mitigation.
- [ ] **S1-T016** Implement added/removed invariant and semantic-object semantics, including project-invariant requirement removal and proof requirements for candidate-added/base-only objects; absence without sufficient counterpart Coverage remains unknown.
- [ ] **S1-T017** Implement move/rename behavior: exact-ID movement remains continuity metadata, same-ID semantic definition conflict fails closed, and unmatched rename-like pairs remain explicit without heuristic joining.
- [ ] **S1-T018** Implement deterministic regression IDs, stable result/reason/Coverage/provenance/diagnostic ordering and bounded work accounting using keyed structures rather than fuzzy all-pairs matching.
- [ ] **S1-T019** Add state-matrix and authority tests covering every supported before/after state family, `NOT_APPLICABLE` scope cases, Coverage degradation/gain, no historical `REINTRODUCED`, no false `MOVED` verdict and no missing-evidence improvement.

**Checkpoint:** pairwise security semantics are deterministic, coverage-aware and authority-correct before any developer-facing integration.

---

## Phase 4 — Internal integration without S2/S3 authority

- [ ] **S1-T020** Integrate the internal regression comparator with existing R3 semantic outputs through the smallest Rust-owned boundary; do not freeze S2 CLI/JSON/exit codes or S3 forge behavior.
- [ ] **S1-T021** Integrate bounded existing `GraphProjection::diff` context for matched comparison records where useful, preserving that graph changes do not independently establish causality, identity or verdict authority.
- [ ] **S1-T022** Add deterministic internal pair rendering/serialization only as required for tests and SentrdelBench; if a public schema/API becomes necessary, stop that expansion until a minimal separately justified contract change is qualified.
- [ ] **S1-T023** Add end-to-end in-process fixture-pair tests proving tenant-binding, required-role, protected-property, elevated-client, coverage-loss and move/rename semantics over existing R3 outputs without network/provider/target execution.

---

## Phase 5 — Evaluation, self-security, and canonical closeout

- [ ] **S1-T024** Promote the frozen supported S1 regression-pair set through SentrdelBench: active clean-case FP threshold, zero known-ground-truth misses for declared supported regressions, Coverage/provenance correctness, deterministic replay, authority assertions and protected-holdout rules where applicable.
- [ ] **S1-T025** Add S1 latency/memory/work qualification with exact machine metadata and hard snapshot/pair/graph/evidence/provenance/diagnostic caps; cap exhaustion must fail visible and existing review ceilings cannot be weakened without spec amendment.
- [ ] **S1-T026** Run final dependency/source governance: prove unchanged qualified dependency/source closure if no dependency was added, or complete exact source/version/license/build/privileged-surface qualification before any newly required dependency/source enters.
- [ ] **S1-T027** Run Linux/macOS/Windows qualification for the supported S1 pair corpus plus adversarial no-network/no-target-execution/no-credential/no-LLM/no-external-engine/Finding-authority/coverage-loss canaries.
- [ ] **S1-T028** Update architecture/threat-model documentation only for behavior actually implemented in S1; preserve explicit S2/S3/S5 and runtime/provider/network non-claims.
- [ ] **S1-T029** Run final S1 Spec Kit consistency analysis against Constitution, roadmap, R1/R3 authority, S1 spec/clarification/research/plan/data-model/contracts/readiness/tasks and implemented behavior; repair only evidence-backed drift.
- [ ] **S1-T030** Run S1 implementation closeout: exact workspace/tests/lints/benchmarks, pair-ground-truth metrics, coverage/provenance/authority/resource/dependency/cross-platform evidence, exact-head review/merge proof and live protected-main governance; record exact results without broadening claims.
- [ ] **S1-T031** Canonicalize S1 closeout and mark all S1 tasks complete only after exact-head applicable CI, clean independent review, zero unresolved conversations, guarded expected-head merge, post-merge required/Cross-platform CI, live repository-governance proof, temporary evidence cleanup and confirmation that no S1 task remains open.

---

## Dependencies

```text
S1-T001 canonical planning/readiness
        |
        v
S1-T002..T006 contracts + frozen pair ground truth + authority fixtures
        |
        v
S1-T007..T013 revision/snapshot/identity/Coverage substrate
        |
        v
S1-T014..T019 pairwise regression semantics
        |
        v
S1-T020..T023 internal integration + E2E pairs
        |
        v
S1-T024..T031 evaluation/hardening/closeout
        |
        v
S2 planning becomes eligible only after S1 CLOSED_CANONICAL
```

## Implementation discipline

- One task or tightly coupled atomic task group per implementation PR unless canonical dependencies make a combined change safer.
- Every security-boundary change carries positive/negative/adversarial tests in the same PR.
- Every new commit invalidates earlier exact-head CI/review qualification for merge eligibility.
- No dependency/source/runtime enters before exact qualification.
- No fuzzy matcher, external/model confidence, graph similarity, or source movement may create identity authority.
- Missing/failed/unsupported candidate analysis cannot become clean or mitigation.
- Pairwise S1 cannot claim multi-revision temporal history.
- Existing reconciler remains the sole canonical Finding authority.
- S2/S3 public/forge behavior remains unauthorized until their own successor specs.
