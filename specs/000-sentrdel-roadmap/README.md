# Sentrdel Roadmap Navigation and Authority Index

**Purpose:** make the roadmap corpus easy to follow without confusing strategic planning with implementation authority.

This file is navigation only. It does not override the Constitution, protected-main truth, an active Spec Kit, or the canonical task ledger.

---

## 1. Authority order

When documents disagree, use this order:

```text
Constitution
  > protected-main live repository/GitHub truth
  > active Spec Kit spec/contracts/plan/tasks
  > canonical roadmap
  > active Implementation Master Plan
  > active supporting planning supplements
  > research/source assessments
  > historical/superseded plans
```

Implementation authority always comes from the active Spec Kit and dependency-eligible task ledger, never from a roadmap document alone.

---

## 2. Required reading order

For any continuation that needs roadmap context, read:

1. `.specify/memory/constitution.md`
2. the currently active Spec Kit `spec.md`, contracts, `plan.md`, checklists, and `tasks.md`
3. protected-main live repository/GitHub truth
4. `specs/000-sentrdel-roadmap/roadmap.md`
5. `specs/000-sentrdel-roadmap/implementation-plan-adoption-record-2026-09-16.md`
6. `specs/000-sentrdel-roadmap/implementation-master-plan-2026-09-16.md`
7. `specs/000-sentrdel-roadmap/developer-adoption-and-trust-plan-2026-09-16.md`
8. the future-slice bootstrap relevant to the next eligible slice:
   - `specs/000-sentrdel-roadmap/s2-review-orchestration-spec-bootstrap-2026-09-16.md`
   - `specs/000-sentrdel-roadmap/s2b-developer-review-experience-spec-bootstrap-2026-09-16.md`
9. `specs/000-sentrdel-roadmap/full-project-review-and-plan-strengthening-2026-09-16.md`
10. bounded supporting supplements only when their domain is relevant:
   - `specs/000-sentrdel-roadmap/security-control-plane-expansion-2026-09-12.md`
   - `specs/000-sentrdel-roadmap/opencti-intelligence-interoperability-2026-09-16.md`
   - `specs/000-sentrdel-roadmap/source-driven-security-expansion-2026-09-08.md`
   - `specs/000-sentrdel-roadmap/strategic-amendment-2026-09-02-semantic-security-graph.md`
   - `specs/000-sentrdel-roadmap/competitive-triangulation-2026-09-02.md`
11. historical plans only for design history, not current sequencing.

Supporting source/research navigation begins at:

- `docs/third-party/SOURCE_MINING_INDEX_2026-09-16.md`
- `docs/third-party/open-code-review-source-assessment-2026-09-16.md`
- `docs/third-party/developer-review-distribution-study-2026-09-16.md`
- `docs/third-party/opencti-source-assessment-2026-09-16.md`
- `docs/third-party/cross-repository-source-mining-2026-09-16.md`

Research and permission records are not source qualification and authorize no dependency/runtime/source adoption.

---

## 3. Strategic-document lifecycle

Allowed lifecycle labels:

```text
ACTIVE_PLAN_OF_RECORD
ACTIVE_SUPPORTING_SUPPLEMENT
HISTORICAL_SUPERSEDED
RESEARCH_ONLY
REJECTED
```

Current planning status after canonical PR #332:

- `implementation-master-plan-2026-09-16.md` — **ACTIVE_PLAN_OF_RECORD** for post-S1 sequencing;
- `developer-adoption-and-trust-plan-2026-09-16.md` — **ACTIVE_SUPPORTING_SUPPLEMENT candidate** until its own PR is canonical; it strengthens developer-product/distribution/trust requirements without changing current task authority;
- `full-project-review-and-plan-strengthening-2026-09-16.md` — **ACTIVE_SUPPORTING_SUPPLEMENT**;
- `security-control-plane-expansion-2026-09-12.md` — **ACTIVE_SUPPORTING_SUPPLEMENT** for bounded verification/runtime/control-plane work;
- `opencti-intelligence-interoperability-2026-09-16.md` — **ACTIVE_SUPPORTING_SUPPLEMENT** for later intelligence/workbench/case/stream work;
- `post-r3-execution-blueprint-2026-09-02.md` — **HISTORICAL_SUPERSEDED** for sequencing;
- third-party/source studies — **RESEARCH_ONLY** unless separately promoted through source qualification;
- PR #331 — **superseded, not rejected**, closed without merge.

The immutable adoption evidence for the Implementation Master Plan is recorded in `implementation-plan-adoption-record-2026-09-16.md`.

---

## 4. Current implementation boundary

Protected-main planning baseline after PR #332:

```text
main = 52b33b11eef3bde42c2d3da127a2a94a86cd51f8
active Spec Kit = specs/004-security-invariant-regression
S1-T001..S1-T011 = canonical
active dependency frontier = S1-T012
```

Post-merge proof for PR #332 is complete across Self Security, Bootstrap CI, Schema Lock Qualification, and Cross-platform CI.

The exact current frontier is always controlled by live protected-main truth plus `specs/004-security-invariant-regression/tasks.md`.

S2 and all later work remain unauthorized until their predecessor gates are canonical and their own Spec Kit lifecycle establishes implementation authority.

---

## 5. Product North Star

The security architecture remains evidence-first and authority-strict, but the developer product objective is now explicit:

> **Sentrdel should become the security reviewer every developer installs and every team can trust.**

Short product promise:

> **Security review for every change.**

Recommended category:

> **Agentic Software Security Review**

This does not mean "all cybersecurity." Sentrdel's strongest product category is the trusted security-review and judgment layer for human- and AI-generated software change.

The desired developer experience is:

```text
fast enough to run on every change
quiet enough to leave enabled
clear enough for every developer
deep enough for security engineers
explainable enough to challenge
deterministic enough to reproduce
independent enough to review AI-written code
provable enough to earn trust
```

The detailed product contract is `developer-adoption-and-trust-plan-2026-09-16.md`.

---

## 6. Core strategic thesis

Sentrdel owns the parts of software security review that require stable authority, provenance, completeness, and judgment:

- canonical Evidence and Coverage contracts;
- exact changed-surface and review-run completeness truth;
- semantic identities and provenance;
- deterministic ReviewPlan and reuse identities;
- security invariants and trusted-base/candidate regression;
- explicit coverage regression;
- reconciler-only Finding authority;
- policy/guard separation from review completeness;
- bounded verification evidence upgrades;
- proof-artifact and retest semantics;
- local/forge/IDE/agent semantic equivalence through one protocol;
- conformance and benchmark contracts.

Sentrdel should normally reuse or import mature infrastructure for commodity breadth where qualification and bounded protocols are stronger than rebuilding:

- generic SAST;
- SCA/SBOM;
- vulnerability/advisory data;
- secret scanning;
- IaC/cloud/container scanning;
- DAST/runtime engines;
- runtime telemetry;
- CTI feeds/standards;
- parsing/indexing primitives;
- optional probabilistic classifiers.

External output remains untrusted evidence/context until Sentrdel-owned contracts reconcile it.

---

## 7. Non-negotiable trust separations

Future product UX must preserve:

```text
Evidence != Finding
Coverage != review completeness
review completeness != policy decision
policy ALLOW != secure
zero findings != clean when mandatory work is incomplete
model output != Finding authority
agent remediation != verified remediation
forge publication success != canonical run success
runtime observation != repository fact
sandbox success != verification authorization
source permission != source qualification
research inclusion != dependency admission
```

Developer simplicity is achieved by strict internal contracts, not by hiding uncertainty.

---

## 8. Post-S1 bounded sequence

The active Implementation Master Plan controls sequencing:

1. **S2A — Review Orchestration Contract**
2. **S2B — Developer Security Review Experience / Local Security Regression Developer Contract**
3. **S3 — Forge Delivery, with GitHub as the reference external developer experience**
4. **S4 — Review + Regression Conformance, including cross-surface product conformance**
5. **S5 — Bounded Verification**
6. **S6A — Standards-First External Evidence Import**
7. **S6B — External Producer Adapters**
8. later provider/framework, action-guard, intelligence, runtime, optional control-plane, and controlled-learning tracks

S6A research/specification may become eligible after S2A/S4 foundations in parallel with S5, but must not delay or weaken S5.

No numbered item becomes executable merely because this roadmap names it.

---

## 9. Developer-product rollout sequence

The developer adoption supplement adds a delivery sequence without changing the core dependency authority:

```text
D0 local CLI + stable machine protocol
 -> D1 GitHub reference experience
 -> D2 coding-agent remediation handoff
 -> D3 IDE reference integration
 -> D4 GitLab/additional forge adapters
 -> D5 optional organization/control-plane experience
```

Rules:

- one canonical security brain serves every surface;
- local usage does not require a hosted account/cloud model;
- agent/IDE/forge adapters cannot create stronger judgment;
- canonical blocking/incomplete results remain visible even when inline comments are intentionally bounded;
- GitHub must become excellent before broad forge proliferation;
- broader distribution waits for semantic/product conformance rather than duplicating implementation logic.

---

## 10. First successor Spec Kits

### S2A

Use:

`specs/000-sentrdel-roadmap/s2-review-orchestration-spec-bootstrap-2026-09-16.md`

It seeds exact inventory, deterministic planning, review-unit/risk-profile contracts, completeness, reuse, persistence boundaries, adversarial fixtures, and dependency-ordered future tasks.

### S2B

Use:

`specs/000-sentrdel-roadmap/s2b-developer-review-experience-spec-bootstrap-2026-09-16.md`

It seeds:

- developer outcome projection;
- terminal information architecture;
- stable machine protocol;
- exit codes;
- review/preview/explain behavior;
- zero-config setup and `doctor`/`init` semantics;
- redaction/truncation;
- remediation packets for humans/agents;
- progress/telemetry separation;
- golden UX/adversarial fixtures;
- product performance baselines;
- onboarding proof;
- a dependency-ordered S2B task DAG.

Neither bootstrap reserves a numeric Spec Kit ID or grants implementation authority.

---

## 11. Product-quality gates

Security correctness remains first. Product quality becomes a release property because noisy or unusable security tools are disabled in real workflows.

Hard trust gates include zero tolerance for:

```text
false READY while mandatory review is incomplete
canonical blocking result hidden from machine/summary output
invalid reuse accepted
advisory/model suppression of canonical Finding
stale candidate result published as current
guessed canonical inline location
cross-surface canonical semantic divergence
agent remediation marked verified without proof
```

Measured product metrics include:

- cold/warm latency;
- time to first actionable result;
- time to terminal completeness;
- setup -> first successful review;
- memory/work counters;
- annotation accuracy;
- duplicate/superseded publication rate;
- comment volume;
- explain usage;
- remediation rerun behavior;
- repeat repository review activity.

Adoption metrics can guide product design but never rewrite security judgment.

---

## 12. Proof-of-category journeys

Before broad platform expansion, Sentrdel should prove:

1. a supported real security regression;
2. a complete clean change;
3. zero findings with incomplete mandatory work that remains visibly incomplete;
4. coverage regression where previously provable semantics become unsupported/ambiguous;
5. safe warm rerun with exact reuse invalidation;
6. moved forge head without stale publication;
7. advisory/model disagreement without authority leakage;
8. human or coding-agent remediation followed by independent re-review;
9. local-to-GitHub semantic equivalence;
10. later, separately authorized bounded verification linked to proof artifacts.

The first major developer-product win is a trusted local + GitHub loop, not scanner count or hosted-dashboard breadth.

---

## 13. Defensibility filter

Before approving a major future capability, ask:

1. Does it improve deterministic judgment, review truth, evidence provenance, coverage truth, verification, remediation/retest, or developer trust?
2. Can a mature external tool provide raw capability behind a bounded import/producer contract?
3. Does it create new credential/network/process/native/model/target-mutation authority?
4. Can failure/timeout/unsupported/incomplete state remain explicit?
5. Does it improve proof-of-category or protected conformance?
6. Can it remain optional so the local core stays small and useful?
7. Does it preserve one canonical security brain across local/forge/IDE/agent surfaces?
8. Is its implementation packet dependency-eligible under the active Spec Kit?

If the answer is mostly no, defer it.

---

## 14. Planning reconciliation status

The canonical planning line is now:

```text
PR #332 merged -> main@52b33b11eef3bde42c2d3da127a2a94a86cd51f8
Implementation Master Plan = ACTIVE_PLAN_OF_RECORD
PR #331 = closed, superseded historical research
```

This developer-first planning PR starts from that exact protected-main baseline and changes roadmap/research documentation only. It does not modify `specs/004-security-invariant-regression/tasks.md`, Rust product code, workflows, dependencies, generated schemas, or current S1 authority.

The next implementation action remains the dependency-eligible active S1 task from live truth. At this navigation update that task is **S1-T012**.

After S1 closes canonically, create/activate S2A from the S2A bootstrap. Only after S2A is canonical should S2B use the Developer Review Experience bootstrap. GitHub/IDE/agent implementation must not jump ahead of those gates.