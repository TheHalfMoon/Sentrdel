# Feature Specification: Security Invariant Regression Core

**Feature Branch:** `spec/004-security-invariant-regression`  
**Created:** 2026-09-08  
**Status:** SPECIFIED  
**Roadmap:** R5 / S1 in `specs/000-sentrdel-roadmap/roadmap.md`  
**Depends on:** completed R1 Evidence + Guard Foundation and completed R3 Business-Logic Substrate + Invariants; planning baseline `44749137ca5a2071c8b4347fd99c85424e625d22`

## Overview

S1 adds Sentrdel's first bounded trusted-base versus candidate **Security Invariant Regression Core**. It compares two explicitly identified, locally derived semantic snapshots and reports what security-relevant invariant, coverage, graph, or evidence state changed without treating source-line change, graph similarity, missing analysis, model output, external producer confidence, or a disappearing result as proof of security improvement.

S1 is a deterministic Rust-owned comparison layer over existing Sentrdel contracts. It reuses R3 invariant evaluations (`SATISFIED`, `VIOLATED`, `UNKNOWN`, `NOT_APPLICABLE`), canonical Coverage, bounded provenance, and the existing `sentrdel-graph` stable-ID projection/diff. It does not create a second graph runtime, a universal CPG, or a second Finding authority.

S1 is local-only. It requires no forge API, network service, provider credential, target build/install/test execution, provider interrogation, LLM, external model, or external scanner. S2 owns the public local CLI/protocol contract; S3 owns GitHub/forge delivery. S1 therefore does not assume a new public schema or CLI surface.

## User Story 1 — Detect a proven security-property regression (P1)

A candidate changes a supported security path so an invariant that was proven `SATISFIED` at the trusted base is proven `VIOLATED` in the candidate. S1 returns one deterministic regression record bound to the exact base/candidate identities, invariant identity, before/after states, evidence/provenance, and applicable coverage.

**Independent test:** Frozen before/after fixture pairs for tenant binding, required role, protected properties, and elevated-client context produce stable regression identities and byte-stable semantic ordering without target execution or network access.

## User Story 2 — Make coverage loss a first-class security outcome (P1)

A candidate removes or obscures analysis capability so a property previously supported by complete-enough evidence becomes `UNKNOWN`, `PARTIAL`, `UNSUPPORTED`, `UNAVAILABLE`, `FAILED`, `TIMED_OUT`, or otherwise unprovable. S1 reports coverage loss or uncertainty rather than mitigation or a clean result.

**Independent test:** Producer disappearance, dynamic semantics, unsupported adapters, cap exhaustion, failed analysis, and missing candidate evidence never become `IMPROVEMENT` or an implicit clean comparison.

## User Story 3 — Preserve semantic identity across benign movement (P1)

A supported semantic object moves to another source location while its canonical stable semantic identity and definition remain unchanged. S1 matches the object by exact stable identity, preserves before/after provenance, and does not emit a regression solely because location changed.

**Independent test:** Equivalent move-only fixture pairs remain semantically unchanged; graph metadata/provenance changes surface as comparison context without becoming a verdict.

## User Story 4 — Fail visible on ambiguous rename or identity drift (P1)

A route, resource, path, invariant, or related semantic object is renamed or structurally changed so exact identity continuity cannot be proven. S1 does not use lexical similarity, graph similarity, or line movement as identity proof. The comparison remains unmatched/unknown unless a deterministic Sentrdel-owned continuity witness exists.

**Independent test:** Similar-looking renamed objects, stable-ID collisions with changed definitions, and ambiguous remove/add pairs do not silently collapse into one matched object.

## User Story 5 — Distinguish improvement from missing evidence (P1)

A base violation disappears in the candidate. S1 reports an improvement only when the candidate state is affirmatively supported and required candidate coverage is sufficient. If the violation disappears because the producer vanished, the adapter became unsupported, the invariant definition disappeared, or evidence is incomplete, the result is coverage loss or unknown.

**Independent test:** `VIOLATED -> SATISFIED` with compatible complete coverage is an improvement; `VIOLATED -> UNKNOWN` or producer disappearance is never an improvement.

## Functional Requirements

### Revision-pair identity and trust

- **FR-001** S1 MUST compare two explicit revision roles: `TRUSTED_BASE` and `CANDIDATE`. Role order is security-significant and MUST NOT be inferred from lexical ref ordering.
- **FR-002** Production revision identity MUST bind to exact immutable repository identities sufficient to prevent branch-name drift, including exact commit/tree identity where available. A branch name, PR number, display label, timestamp, or forge claim alone is insufficient.
- **FR-003** Synthetic fixture identities MAY be used only in test/benchmark mode and MUST NOT establish a trusted production base.
- **FR-004** A deterministic, domain-separated revision-pair identity MUST bind the comparison-contract version plus exact base and candidate identities.
- **FR-005** S1 MUST NOT call forge APIs or network remotes to discover or validate comparison identity. Base/candidate selection UX belongs to S2/S3; S1 consumes already validated local identities/snapshots.

### Snapshot compatibility

- **FR-006** Each semantic snapshot MUST bind its revision identity, invariant definitions/evaluations, applicable Coverage, bounded Evidence/provenance references, and the bounded SSG projection or deterministic graph identity needed by the comparison.
- **FR-007** Comparison MUST validate snapshot contract version and the producer/version/configuration dimensions that materially affect semantic comparability. Incompatible or insufficiently described snapshots fail visible as `UNKNOWN`/comparison-unavailable; they do not produce a regression or improvement verdict.
- **FR-008** Snapshot input collections MUST be deterministically normalized and bounded before comparison.

### Invariant and semantic identity matching

- **FR-009** Invariants MUST match primarily by exact canonical stable invariant identity and compatible definition semantics. Kind, scope, requirement, and source/authority semantics MUST NOT silently change under one identity.
- **FR-010** Reuse of one stable invariant ID for incompatible before/after definitions MUST fail closed as an identity/contract conflict rather than being compared as one invariant.
- **FR-011** Semantic objects MUST match by exact Sentrdel-owned stable identity where available. Lexical similarity, source proximity, graph-neighborhood similarity, edit distance, confidence score, or model judgment MUST NOT establish canonical identity.
- **FR-012** A source move with unchanged stable semantic identity MAY be recorded as continuity metadata with before/after provenance. `MOVED` is not itself a security verdict.
- **FR-013** Rename continuity MAY be recognized only when an existing or separately frozen deterministic Sentrdel-owned identity witness proves continuity. Base S1 MUST NOT add heuristic/fuzzy rename authority merely to reduce remove/add pairs.
- **FR-014** Added, removed, renamed, moved, and unmatched semantic objects MUST remain explicitly distinguishable in comparison records.

### Security delta semantics

- **FR-015** S1 MUST freeze an internal pairwise disposition vocabulary containing at least `REGRESSION`, `IMPROVEMENT`, `UNCHANGED`, `UNKNOWN`, `COVERAGE_LOST`, and `COVERAGE_GAINED`.
- **FR-016** Every disposition MUST preserve the exact before/after invariant state, presence/continuity state, coverage comparison, and reason. The disposition MUST NOT erase underlying uncertainty.
- **FR-017** `SATISFIED -> VIOLATED` with compatible sufficient coverage is a `REGRESSION`.
- **FR-018** `VIOLATED -> SATISFIED` is an `IMPROVEMENT` only when candidate coverage/evidence is sufficient to affirm the candidate state.
- **FR-019** `SATISFIED -> UNKNOWN` is a security-regression signal. When caused by degraded candidate coverage it MUST be `COVERAGE_LOST`; otherwise it is `UNKNOWN`. It MUST NOT be treated as `UNCHANGED` or clean.
- **FR-020** `VIOLATED -> UNKNOWN` MUST NOT be an improvement. Coverage degradation remains `COVERAGE_LOST`; otherwise the result is `UNKNOWN`.
- **FR-021** `UNKNOWN -> SATISFIED` or `UNKNOWN -> VIOLATED` MAY be `COVERAGE_GAINED` when the candidate gains sufficient supported analysis. The newly observed candidate state remains explicit, but pairwise S1 MUST NOT invent causal improvement/regression history that the base could not establish.
- **FR-022** Same supported state with compatible sufficient coverage is `UNCHANGED`; a same enum value with materially degraded coverage is not automatically unchanged.
- **FR-023** Pairwise S1 MUST NOT claim `REINTRODUCED` because proving reintroduction requires history beyond two snapshots. Historical/temporal classification requires a later separately frozen contract.
- **FR-024** Presentation terms such as `NEW`, `PRE_EXISTING`, `WORSENED`, or `MITIGATED` MAY be derived later only where the frozen pairwise semantics prove them. S1 does not invent severity ordering between R3 invariant states.

### Coverage-aware comparison

- **FR-025** S1 MUST compare applicable Coverage by stable capability/scope/producer/dimension identity and preserve `COVERED`, `PARTIAL`, `UNSUPPORTED`, `UNAVAILABLE`, `FAILED`, `TIMED_OUT`, and `SKIPPED_BY_POLICY` semantics.
- **FR-026** Candidate degradation from sufficient supported coverage to a gap is `COVERAGE_LOST` when it affects the security comparison. Missing producer output, missing evidence, failure, timeout, unsupported/dynamic semantics, or cap exhaustion MUST NOT become proof that a base issue was mitigated.
- **FR-027** Candidate gain from a base gap to sufficient supported coverage MAY be `COVERAGE_GAINED`; the candidate invariant state remains explicit.
- **FR-028** An empty candidate Finding/Evidence/evaluation set MUST NOT erase coverage loss or become a clean comparison.
- **FR-029** External/probabilistic producer disappearance MUST remain visible as coverage/uncertainty and cannot become a clean result.

### Graph, R3, evidence, and provenance integration

- **FR-030** S1 MUST reuse existing `sentrdel-graph` stable-ID projection/diff primitives where semantically valid and MUST NOT introduce a second graph runtime or universal CPG.
- **FR-031** `GraphProjection::diff` add/remove/modify output is comparison context, not proof of causality, invariant identity, security regression, or rename continuity.
- **FR-032** S1 MUST reuse R3 invariant definition/evaluation semantics rather than duplicating a second invariant evaluator for pairwise comparison.
- **FR-033** Before/after provenance and bounded evidence references MUST be preserved separately. Candidate provenance MUST NOT overwrite or retroactively rewrite base provenance.
- **FR-034** Comparison authority MUST be no stronger than the evidence/coverage/evaluation authority it consumes. Graph confidence, external severity/confidence, model output, benchmark score, or source reputation cannot upgrade Sentrdel epistemic authority.
- **FR-035** S1 comparison records MUST NOT directly create canonical Findings or override policy/kernel/reconciler decisions. Existing reconciler-only Finding authority remains unchanged.

### Added/removed definitions and semantic objects

- **FR-036** Removal of a valid base project-declared security invariant MUST remain visible and MUST NOT be interpreted as mitigation merely because the candidate no longer evaluates it. Whether the removal is a regression requires the frozen definition/coverage contract and must remain below Finding authority.
- **FR-037** Addition of a candidate invariant or semantic object MUST preserve absence/coverage truth for the base. Base absence can support a strong pairwise conclusion only when base scope/coverage proves that absence rather than failing to observe it.
- **FR-038** Removal of a violated semantic path MAY support improvement only when candidate absence is deterministically proven under compatible sufficient coverage; otherwise it remains unknown/coverage loss.

### Determinism and resource behavior

- **FR-039** Equivalent normalized revision-pair inputs MUST produce deterministic pair identity, matching, disposition, reason ordering, provenance ordering, diagnostics, and internal serialized test records.
- **FR-040** S1 MUST impose hard caps on snapshot records, invariant pairs, graph nodes/edges considered, evidence/provenance references per result, diagnostics, and total comparison work. Exact caps are frozen during implementation against existing limits and benchmark evidence, not guessed by planning.
- **FR-041** Resource-cap exhaustion MUST fail visible through comparison/coverage diagnostics and MUST NOT truncate into a clean verdict.
- **FR-042** Comparison MUST avoid quadratic fuzzy all-pairs identity searches. Stable keyed matching is the default algorithmic contract.

### Evaluation and promotion

- **FR-043** Frozen regression-pair fixtures MUST precede release-gating implementation breadth.
- **FR-044** The declared supported S1 fixture set MUST include clean/no-semantic-change, proven regression, proven improvement, unknown, coverage loss, coverage gain, producer disappearance, move-only continuity, ambiguous rename/unmatched, added/removed object, graph-metadata-only, definition conflict, adversarial authority, and resource-cap cases.
- **FR-045** S1 MUST reuse SentrdelBench rather than create a second evaluator. Release promotion requires the active clean-case false-positive policy, zero known misses for the frozen supported regression ground truth, deterministic replay, coverage/provenance correctness, authority correctness, resource/latency qualification, and protected-holdout rules applicable to the candidate.
- **FR-046** Detection/recall improvement cannot qualify a candidate that introduces hidden coverage loss, authority widening, nondeterminism, resource-bound failure, or false conversion of uncertainty into a verdict.

### Interface and dependency boundaries

- **FR-047** S1 does not require a new public CLI command, exit code, machine-readable public schema, or forge surface. S2 owns the local developer contract and S3 owns forge delivery.
- **FR-048** If implementation evidence proves an internal/public contract gap, any schema/API change MUST be minimal, separately justified, versioned/compatible where applicable, and cannot silently preempt S2 authority.
- **FR-049** No new dependency is pre-authorized. Any new crate, donor code, model, data, binary, container, external engine, or service requires exact repository qualification before use.
- **FR-050** S1 MUST require no network, provider credential, forge credential, target execution, LLM, model, external scanner, or donor runtime.

## Success Criteria

- **SC-001** Frozen supported regression pairs have zero known-ground-truth misses and pass the active SentrdelBench clean-case false-positive gate.
- **SC-002** Equivalent pair inputs replay deterministically, including stable identities and ordering.
- **SC-003** Every supported regression/improvement record preserves exact base/candidate identity, invariant identity, before/after state, applicable coverage, and bounded provenance/evidence chain.
- **SC-004** Every candidate coverage degradation remains visible and no missing/failed/unsupported producer can create an improvement or clean verdict.
- **SC-005** Move-only and metadata-only fixture pairs do not produce false security regressions; ambiguous rename pairs remain fail-visible.
- **SC-006** Adversarial fixtures prove graph confidence, external/model output, repository instructions, and malformed identity input cannot create Finding/policy/FACT/VERIFIED authority.
- **SC-007** S1 remains within frozen memory/time/work caps on the declared qualification corpus and cap exhaustion fails visible.
- **SC-008** No forge/network/provider/credential/target-execution authority is required for S1 qualification.

## Non-Goals

- Public change-relative CLI/JSON/exit-code design; owned by S2.
- GitHub/GitLab/forge checks, comments, annotations, or credentials; owned by S3.
- IDE/agent-specific integration.
- Multi-revision temporal history or `REINTRODUCED` classification.
- Heuristic/fuzzy rename matching or graph-similarity identity proof.
- New invariant families, provider-pack breadth, scanner imports, or model-based security judgment.
- Runtime verification, fix validation, exploitability proof, live-provider posture, or credentialed verification.
- Autonomous exploitation or remediation.
- Universal CPG construction or a second graph engine.
- Direct Finding, policy, kernel, FACT, or VERIFIED authority.
- Treating missing evidence, disappearing producers, empty outputs, or higher confidence scores as proof of security.

## Source and research boundary

The 2026-09-08 source-study artifacts remain research/provenance only unless the canonical source-qualification ledger grants stronger exact authority. Existing qualified `petgraph` and selectively qualified Graphify concepts are already represented through the canonical `sentrdel-graph` substrate; S1 planning authorizes no new donor copy, port, dependency, runtime, model, data, binary, container, network service, or external-engine execution.
