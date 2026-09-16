# Sentrdel Full Project Review and Plan Strengthening — 2026-09-16

**Status:** `STRATEGIC_REVIEW / PLAN-OF-RECORD CANDIDATE / NO IMPLEMENTATION AUTHORITY`  
**Review base:** protected `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3` plus live open-PR truth at review time  
**Active implementation authority:** `specs/004-security-invariant-regression/` only  
**Primary new external study:** `alibaba/open-code-review@a694be568d9b9a935b2ba11a867d5a91d7ffd833`  
**Related source assessment:** `docs/third-party/open-code-review-source-assessment-2026-09-16.md`  
**Also reconciles:** the useful planning content of draft PR #331 into the broader PR #332 planning line  
**Purpose:** Review Sentrdel as a complete product/architecture/governance program, identify the highest-leverage gaps, simplify the roadmap, and strengthen the path from trusted security judgment to a developer product that is useful on every meaningful change.

## 1. Executive conclusion

Sentrdel's **security architecture is stronger than its product orchestration architecture**.

The repository already has an unusually coherent trust model:

- Evidence is separate from verdict;
- Coverage is explicit and missing analysis does not become clean;
- the reconciler is the sole canonical Finding authority;
- model output is lower-authority;
- repository content is data, not instruction;
- target repositories are not executed during ordinary review;
- dependency/source admission is exact and governance-heavy;
- R3 is deliberately narrow rather than pretending universal semantic certainty;
- S1 correctly makes trusted-base/candidate security-property regression the next product moat.

Those principles should **not** be redesigned.

The most important improvement is to build a Rust-owned **Review Orchestration and Delivery Plane** around that judgment kernel before expanding into a large control plane.

The target product should answer, in one review experience:

> **What changed? What security property changed? What did Sentrdel actually inspect? What did it fail or refuse to inspect? What evidence supports the conclusion? What is canonical versus advisory? What was published to the developer? Can this exact work be reused safely on the next push?**

That is the missing bridge between Sentrdel's excellent security semantics and becoming the everyday security layer for AI-assisted development.

## 2. Review scope

This review covered the current repository architecture and governance, including:

- Constitution and `AGENTS.md`;
- root product README and explicit non-claims;
- Rust workspace/crate boundaries;
- R1 CLI/review/coverage contracts;
- R2 Supabase static posture direction;
- R3 business-logic/invariant substrate;
- current security threat model;
- active S1 Spec 004 and task ordering;
- post-R3 execution blueprint;
- current roadmap and source-driven/security-control-plane/OpenCTI planning;
- source/dependency qualification discipline;
- live open PRs #330, #331 and #332;
- founder-owned source-mining results from Golam, Kodac, Ascout, Signthos, Himsat, Diffcipline, SpecGrain and HarnessMind;
- OpenCTI strategy;
- OpenCodeReview's review-selection, grouping, session-manifest, resume, delegation, rule-routing and forge-delivery patterns.

This is a strategic/product/architecture review, not a claim that every source line has received a vulnerability audit.

## 3. What is already excellent

### 3.1 The trust model is the project's strongest asset

Sentrdel consistently separates:

```text
content availability
!= instruction authority
!= epistemic authority
!= Finding authority
!= policy authority
!= verification authority
```

This is more important than adding another scanner or model. It should remain the foundation of every future feature.

### 3.2 Coverage loss as a first-class security result is highly defensible

The S1 design correctly recognizes that:

```text
previously provable property
  -> producer disappears / analysis becomes dynamic / cap exhausts
  -> COVERAGE_LOST or UNKNOWN
  -> never implicit mitigation / clean
```

This is a genuine differentiator and should be visible in the product UX, benchmark corpus and forge status contract.

### 3.3 S1 is correctly bounded

The current S1 spec should not be widened by this review. It correctly excludes:

- forge APIs;
- model requirements;
- external scanners;
- target execution;
- fuzzy identity;
- new Finding authority;
- public CLI/schema redesign.

Finish the exact S1 sequence first.

### 3.4 The dependency/source qualification discipline is unusually strong

Exact pins, build/proc-macro/native surface review, authority ceilings and explicit source qualification are already part of the repository culture. This becomes essential when Sentrdel later imports scanners, sandboxes, telemetry collectors, packs and intelligence sources.

### 3.5 The project has resisted the universal-CPG trap

The bounded SSG is the right direction. Sentrdel should use graph/dataflow/indexing tools where they improve evidence and invariant leverage, not make a universal graph runtime the product.

### 3.6 Rust-first/local-first remains the right base

The current workspace separates schema, store, graph, engine, policy, guard, review, verify and CLI responsibilities. The reserved `sentrdel-verify` crate remains execution-disabled rather than pretending verification exists. That is good architecture discipline.

## 4. Main weaknesses and risks

### 4.1 Security judgment is ahead of review-run truth

The existing CLI envelope tells the consumer about decision, Findings, Coverage and diagnostics. It does not yet provide a canonical answer to:

- what exact changed items were selected;
- what was intentionally excluded;
- what was deferred because of size/budget;
- which review work completed/reused/failed;
- what the run's terminal completeness state is;
- whether prior work was safely reused;
- whether publication to a forge was complete.

This is distinct from producer `CoverageRecord` and must not be forced into the same contract.

### 4.2 `ALLOW` can be misread as “secure” unless S2 separates policy from completeness

The frozen R1 CLI decision vocabulary is valid for its contract, and Coverage gaps are separately rendered. However, future change-relative review UX must make it impossible for a consumer to interpret:

```text
Decision: ALLOW
+ partial/unsupported review coverage
```

as “this change is secure”.

S2 should explicitly separate at least:

- **policy/guard decision** — `ALLOW / ASK / DENY / UNDECIDABLE`;
- **review completeness** — whether required review work completed;
- **security regression disposition** — what S1 proved about base vs candidate;
- **publication status** — whether the result was successfully delivered.

No single green field should flatten all four.

### 4.3 S2 is currently too small for the role it must play

The post-R3 blueprint describes S2 mostly as CLI/JSON/exit-code design. It should instead own the complete local **Review Orchestration Contract** that S3, IDEs and agents consume.

Without that, GitHub integration will be forced to invent scope, rerun, annotation and completeness semantics that should be vendor-neutral and local first.

### 4.4 S3 needs more than “GitHub Checks + annotations”

A safe and excellent forge product needs:

- exact range identity;
- fork-safe trusted-base checkout;
- PR head treated as data, not workflow authority;
- explicit minimal token permissions;
- deterministic rerun/checkpoint behavior;
- comment/annotation idempotency;
- exact source-span binding;
- summary fallback when exact line provenance is unavailable;
- publication failure accounting;
- no PR comment/body instruction authority;
- no mutable binary/action versions.

### 4.5 Planning has become fragmented

The repository now has several strategic supplements and overlapping open roadmap PRs. This is a natural consequence of deep research, but it creates a governance risk: future agents may select a stale planning document and implement against it.

The repository needs one navigation/convergence rule:

```text
Constitution
  > active Spec Kit
  > canonical roadmap
  > latest explicitly adopted strategic review / Plan of Record
  > older strategic supplements
  > research assessments
```

Draft PR #331 and PR #332 should not remain competing roadmap futures. The useful #331 content should be reconciled into #332, then #331 should be closed as superseded after the convergence record is complete.

### 4.6 The roadmap is too sequential in one place and too expansive in another

The current preferred sequence places bounded verification before external evidence import. Verification should remain high priority, but the **standards-only part** of external evidence import does not logically depend on dynamic verification.

A narrow S6A profile for SARIF/CycloneDX/SPDX/OSV can become spec/research eligible after the developer contract + conformance foundation without delaying S5.

This gives Sentrdel breadth through mature producers while keeping S1-S5 focused.

### 4.7 The product needs a clearer steel thread

Before building OpenCTI-style workbenches, portfolio views or runtime control planes, Sentrdel should prove one excellent end-to-end developer experience:

```text
exact base/head
  -> deterministic change inventory
  -> ReviewPlan
  -> Evidence/Coverage
  -> S1 regression
  -> canonical Findings where applicable
  -> local review output
  -> GitHub Check + exact annotations
  -> explicit partial/unreviewed state
  -> safe rerun on the next push
```

If this feels excellent, the rest of the control plane has a trustworthy foundation.

## 5. Target architecture refinement

Add one explicit plane between change acquisition and canonical judgment delivery.

```text
                         CHANGE / REVISION INPUT
                                  |
                                  v
┌────────────────────────────────────────────────────────────────────────────┐
│                    REVIEW ORCHESTRATION PLANE                             │
│ exact change inventory · ReviewPlan · run manifest · review units         │
│ completeness · budget · reuse proof · advisory context · publication IDs  │
└───────────────────────────────┬────────────────────────────────────────────┘
                                |
                                v
┌────────────────────────────────────────────────────────────────────────────┐
│                     TRUSTED JUDGMENT CORE                                 │
│ Evidence · Coverage · SSG · Invariants · Regression · Reconciler · Policy │
└───────────────┬─────────────────────────────┬──────────────────────────────┘
                |                             |
                v                             v
     OPTIONAL ADVISORY PLANE          VERIFICATION / IMPORT / RUNTIME
     host-agent ReviewPacket          separately authorized producers
     model hypotheses/explanation     explicit authority ceilings
                |                             |
                └──────────────┬──────────────┘
                               v
┌────────────────────────────────────────────────────────────────────────────┐
│                         DELIVERY PLANE                                    │
│ CLI · JSON/protocol · GitHub/GitLab · IDE · agent · optional workbench    │
│ exact projection · publication lifecycle · no new judgment authority      │
└────────────────────────────────────────────────────────────────────────────┘
```

The Review Orchestration Plane does **not** create canonical Findings. It owns truth about what the review process attempted and completed.

## 6. Contracts to freeze before S3 becomes implementation-ready

### 6.1 `ChangeReviewManifest`

Minimum semantics:

- schema version;
- run ID and optional parent run;
- repository identity;
- exact base/head/revision-pair identity;
- input/change-inventory digest;
- Sentrdel binary/version/digest where available;
- producer/profile/rule/pack/config identities;
- selected item set;
- completed/reused/failed/deferred/waived item sets;
- run failure if any;
- terminal state;
- resource/work counters;
- elapsed time;
- publication references.

### 6.2 `ReviewItem`

Minimum semantics:

- stable logical item identity;
- old/new canonical path where applicable;
- change kind;
- content/diff fingerprint;
- artifact/content class;
- selection disposition and reason;
- mandatory/optional security-review status;
- applicable producer/profile identities;
- execution outcome;
- Coverage references.

### 6.3 `ReviewPlan`

One deterministic plan produced before expensive execution:

- exact selected surface;
- mandatory analysis profiles;
- optional escalation profiles;
- expected producers;
- review-unit partition;
- work/resource budget;
- explicit unsupported/deferred items;
- explanation for every selection/routing decision.

`preview` and real execution consume the same plan identity.

### 6.4 `ReviewUnit`

A bounded set of semantically related review items with deterministic provenance. Sentrdel-owned relationships decide authoritative grouping. Optional model grouping can propose advisory context only.

### 6.5 `ReviewReuseProof`

Safe prior-work reuse bound to exact revisions/content/config/producers/authority. Drift fails closed to redispatch.

### 6.6 `ModelContextManifest`

Records exactly what lower-authority model/host-agent reasoning received:

- context item IDs and digests;
- redaction/truncation facts;
- source type;
- instruction-authority class (`UNTRUSTED_DATA` for repository/PR content);
- provider/model/template/tool identities;
- applicable advisory capability ceiling.

Secret plaintext and forbidden credential content remain outside model context by default.

### 6.7 `AdvisoryReviewComment`

Separate from canonical Finding:

- advisory ID;
- producer/model/host-agent identity;
- source context manifest;
- candidate category/severity;
- candidate source span;
- confidence if useful;
- reflection/filter state;
- relationship to canonical records if any;
- explicit epistemic ceiling.

### 6.8 `ReviewPublicationRecord`

Tracks CLI/forge/IDE delivery without becoming truth authority.

## 7. Expanded gap register

OpenCodeReview assessment defines G53-G69. This full review adds the following project-level gaps.

### G70 — Policy decision and review completeness can be confused in presentation

**Correction:** S2 must expose separate typed fields for policy decision, run completeness, regression disposition and publication state. `ALLOW` never means “secure”.

### G71 — Change inventory must cover non-reviewable artifacts explicitly

Deleted, renamed, binary, generated, oversized, unsupported and provider-ignored artifacts still belong to the exact candidate change inventory. They may be non-analyzable, but they must not disappear from scope accounting.

**Correction:** every changed artifact receives a `ReviewItem` disposition. Security-relevant skipped artifacts affect completeness/Coverage.

### G72 — Advisory-model provenance is not rich enough for future reusable reasoning

A model response should bind model/provider/version, template/rule/toolset identities, input-context digest, redaction facts, completion mode and run identity.

**Correction:** define `ModelContextManifest` + advisory producer provenance before model-generated review comments become a first-class integration surface.

### G73 — Security memory needs freshness and anti-suppression semantics before implementation

Persistent project knowledge is useful, but memory can become a hidden stale policy channel.

**Correction:** memory records bind source/revision/scope/freshness/expiry/provenance and remain context only. Memory cannot suppress Evidence, Coverage gaps, Findings, policy or verification requirements.

### G74 — Standards-first external evidence can move earlier without blocking verification

The generic Evidence/Coverage substrate is already mature enough to design a narrow standards-only import profile independently of sandboxed verification.

**Correction:** after S2 and initial S4 conformance contracts, allow **S6A research/specification** for SARIF/CycloneDX/SPDX/OSV in parallel with S5 implementation. This must not delay or weaken S5.

### G75 — Review quality needs delivery-level benchmark dimensions

Security precision alone does not prove an excellent review product.

**Correction:** add SentrdelBench metrics for:

- changed-surface selection recall;
- mandatory-item omission count (target zero);
- review completeness correctness;
- reuse/checkpoint correctness;
- inline location accuracy;
- duplicate/superseded comment rate;
- publication failure rate;
- time to first actionable canonical result;
- total cold/warm review latency;
- optional advisory token/cost budget;
- operator comprehension of `ALLOW` vs incomplete/unknown states.

### G76 — Product risk profiles are not frozen

A two-line documentation change and an auth/provider/workflow change should not consume the same review plan.

**Correction:** future S2 review profiles (`standard`, `heightened`, `critical` or later frozen names) are derived from deterministic change/security facts and operator policy. They control additional producers/budgets/advisory effort but never widen execution/network/credential authority automatically.

### G77 — Forge publication must be treated as an untrusted external effect

Posting a Check/comment can partially fail, rate-limit or bind to a moved head.

**Correction:** publication is idempotent and head-bound; partial publication never changes canonical run success. A new head invalidates stale inline placement and requires explicit supersession/republication behavior.

### G78 — Strategic documents need lifecycle state

Research documents currently accumulate indefinitely.

**Correction:** roadmap/navigation should classify each strategic artifact as one of:

- `ACTIVE_PLAN_OF_RECORD`;
- `ACTIVE_SUPPORTING_SUPPLEMENT`;
- `HISTORICAL_SUPERSEDED`;
- `RESEARCH_ONLY`;
- `REJECTED`.

Superseded plans stay auditable but cannot silently regain authority.

## 8. Roadmap sequence changes

Do **not** change S1 implementation order.

Strengthen the post-S1 sequence as follows:

### S2A — Review Orchestration Contract

Freeze:

- exact change inventory;
- `ReviewPlan`;
- `ChangeReviewManifest`;
- review completeness;
- resource/budget behavior;
- safe reuse proof;
- review-unit semantics;
- advisory context boundary.

### S2B — Local Security Regression Developer Contract

Freeze:

- human output hierarchy;
- machine-readable regression output;
- policy vs completeness vs regression separation;
- exit codes;
- explain surfaces;
- `review --preview` / scope explanation;
- optional `ReviewPacket` export.

S2A and S2B may be one Spec Kit if the final plan proves they are tightly coupled and bounded; they should still be separate conceptual gates.

### S3 — Forge Delivery

Add:

- fork-safe GitHub reference workflow;
- immutable integration/tool identity;
- exact annotations;
- publication lifecycle;
- sticky/non-destructive summary;
- safe cross-push checkpointing based on local run/reuse contracts;
- no comment/body instruction authority.

### S4 — Open Regression + Review Conformance

Extend the existing conformance plan with ReviewPlan/run-manifest/reuse/publication fixtures.

### S5 — Bounded Verification

Keep high priority. Reuse the same generic run/completeness primitives where appropriate, but keep verification authorization and proof semantics stronger and separate.

### S6A — Standards-First External Evidence Import

Research/specification may begin after S2/S4 foundations without waiting for S5 completion. Implementation remains separately gated and must not distract from the verification steel thread.

### Later control-plane work

OpenCTI-inspired workbench/cases/intelligence, runtime/portfolio, and automation remain later. Do not allow the optional control plane to outrun the quality of the local review product.

## 9. Product steel thread before broad expansion

The first public-quality post-S1 milestone should prove this exact experience:

1. user selects an exact base/head or local working-tree comparison;
2. Sentrdel prints a deterministic preview of every changed item and planned security coverage;
3. review executes without target build/install/code execution;
4. S1 shows the security-property regression/coverage delta;
5. canonical Findings remain reconciler-owned;
6. Coverage loss is visually prominent;
7. local JSON records both judgment and review completeness;
8. GitHub shows the same semantics, not a parallel implementation;
9. exact inline annotations appear only where provenance proves the source span;
10. uncertain/unanchored results move to a summary, not a guessed line;
11. the next push safely reuses only exact still-valid work and redispatches changed/invalidated units;
12. no green status is possible when mandatory review work is incomplete.

This should be treated as a product benchmark, not merely a demo.

## 10. UX direction

The default developer output should prioritize:

```text
1. Review completeness
2. Security properties changed
3. Blocking/ask policy state
4. Canonical regressions/findings
5. Coverage loss / unsupported work
6. Proof/evidence path
7. Exact affected semantic boundary
8. Verification state
9. Advisory explanation/remediation
10. Technical provenance on demand
```

This ordering makes uncertainty impossible to miss.

Suggested future local commands/surfaces, names not frozen:

```text
sentrdel review --preview
sentrdel review <base>..<head>
sentrdel review --json
sentrdel explain <regression-or-finding>
sentrdel rules explain <path>
sentrdel review export-packet
sentrdel review resume <run-id>
```

No command name in this strategic review is implementation authority.

## 11. What not to build yet

Defer until the core developer steel thread and conformance are excellent:

- large multi-tenant web control plane;
- autonomous exploitation/pentest swarms;
- generic shell tool orchestration;
- broad provider pack count for marketing;
- universal CPG;
- mandatory graph database;
- mandatory cloud/model provider;
- long-term memory with suppression authority;
- auto-fix/auto-merge authority;
- OpenCTI clone;
- custom telemetry/trajectory standards where OpenTelemetry/ATIF/in-toto/SLSA already fit.

## 12. Source reuse priorities after this review

### Product-core patterns

1. Sentrdel's existing Graphify/Tree-sitter qualifications remain primary graph/parser truth.
2. Golam authority/sandbox/capability primitives are high-value future selective-port candidates.
3. Kodac provenance/analyzer-normalization/sandbox patterns are high-value future selective-port candidates.
4. Ascout receipts/completeness are high-value review-manifest references.
5. OpenCodeReview manifest/selection/resume/delegation mechanics are high-value review-orchestration references.

### External adapters

Prefer mature standards/tools for raw evidence rather than rebuilding them.

### Development assurance

Diffcipline/SpecGrain/HarnessMind remain process references, not hidden product dependencies.

## 13. Governance convergence

PR #332 should be the planning convergence path for this review because it already contains the current security-control-plane, OpenCTI and cross-repository source studies.

Draft PR #331 contains valuable earlier thinking, especially around VerificationRun, run completeness, resumability, workbench/reporting and tool manifests. Those concepts are preserved and strengthened in #332's current blueprint plus this review. After #332 contains the complete convergence record, #331 should be closed as **superseded, not rejected**.

Any merge-order rule remains unchanged:

1. active S1 implementation work wins over planning branches;
2. if protected `main` moves, planning branches reconcile by ordinary merge/fast-forward-safe history, never rebase/force-push;
3. the reconciled exact head receives fresh CI/review;
4. planning merge never authorizes future product implementation by itself.

## 14. Success criteria for the strengthened plan

A future Sentrdel release should not claim the review product is mature until it can prove:

- zero hidden mandatory changed items in frozen review-surface fixtures;
- deterministic ReviewPlan identity and output;
- exact run completeness under success/failure/timeout/budget/cancellation cases;
- no clean/green interpretation under required incomplete work;
- safe reuse invalidation under revision/config/rule/producer drift;
- local/forge semantic equivalence;
- exact inline annotation provenance or explicit summary-only fallback;
- canonical Finding immunity from model reflection/filtering;
- repository configuration cannot suppress required security analysis;
- fork PRs cannot turn untrusted head content into workflow/credential authority;
- optional host-agent/model delegation remains lower-authority;
- no planning document below the active Plan of Record can silently override the active Spec Kit.

## 15. Final product thesis

Sentrdel should not try to be the system that **does the most security things**.

It should become the system developers trust to answer:

> **What exactly was reviewed, what security property changed, what evidence proves it, what is still unknown, what was independently verified, and can I trust this exact result for this exact change?**

That thesis is narrower than an all-purpose security platform and stronger than an AI review bot. It is the direction most consistent with the existing code, governance and defensible technical moat.
