# Sentrdel Post-R3 Execution Blueprint — 2026-09-02

**Status:** STRATEGIC_EXECUTION_BLUEPRINT  
**Planning base:** `main@f4c72f1fdf9a6d817c2349578d3cd7993aeacd8a`  
**Depends on:** canonical completion and post-merge proof of R3  
**Authority:** Roadmap planning only. This document does not authorize implementation, reorder the active R3 task ledger, or replace future Spec Kit artifacts.

## Goal

Convert the Semantic Security Graph / Security Invariant Regression strategy into a dependency-ordered sequence of future bounded specs.

The blueprint deliberately avoids a single mega-spec. Each slice must later receive its own:

`specify -> clarify -> plan/research/design -> checklist -> tasks -> analyze -> implement -> converge`

The first product objective after R3 is not broad scanner coverage. It is one excellent, deterministic, benchmarked answer to:

> **What security property did this PR weaken, and what evidence proves or limits that conclusion?**

## Entry gate

No work in this blueprint is implementation-authorized until all of the following are true:

1. R3 `tasks.md` is canonically complete;
2. R3 closeout has exact-head CI and independent review;
3. R3 is merged through expected-head protection;
4. post-merge CI succeeds on the exact canonical `main`;
5. live repository-governance proof succeeds on that exact `main`;
6. the roadmap/planning amendments are reconciled against the new canonical base and merged through their own normal qualification;
7. the first successor spec is separately created and implementation-ready.

## Slice S1 — Security Invariant Regression Core

**Roadmap home:** R5  
**Purpose:** Compare trusted-base and candidate semantic state without forge-specific UI.

### Scope

- trusted-base revision identity and validation;
- deterministic base/head SSG projection;
- stable semantic identity matching across revisions;
- invariant-state comparison;
- coverage-state comparison;
- evidence-chain comparison;
- bounded move/rename handling where provable;
- deterministic regression ordering and IDs;
- no network, forge API, target execution, provider credentials, or LLM requirement.

### Candidate result classes

The spec should evaluate and freeze the minimum useful vocabulary, likely including:

- `NEW`;
- `PRE_EXISTING`;
- `WORSENED`;
- `MITIGATED`;
- `REINTRODUCED`;
- `MOVED` only where identity evidence is sufficient;
- `UNCERTAIN`;
- `COVERAGE_LOST`;
- `COVERAGE_GAINED`.

Names are not final until the spec freezes them.

### Hard correctness rules

- A changed line is not proof of causality.
- A graph similarity score is not identity proof.
- Missing head coverage cannot become `MITIGATED`.
- A base finding disappearing because analysis became unsupported must become visible coverage loss/uncertainty.
- External producer disappearance cannot become a clean result.
- An invariant moving from `SATISFIED` to `UNKNOWN` is a security-regression signal even when no `VIOLATED` result can be proven.
- Equivalent base/head semantic inputs must replay deterministically.

### Exit gate

- frozen public regression-pair fixtures;
- safe/unsafe/unknown/coverage-loss pairs;
- deterministic replay qualification;
- resource caps;
- clean-case false-positive qualification;
- authority-correctness tests;
- no forge integration yet.

## Slice S2 — Security Regression Developer Contract

**Roadmap home:** R5  
**Depends on:** S1

### Purpose

Freeze the local UX/API contract before coupling the engine to GitHub or an IDE.

### Required surfaces

- `sentrdel review` change-relative summary;
- `sentrdel explain <regression>` evidence chain;
- machine-readable versioned regression output;
- explicit per-layer coverage state;
- base/head identity in output;
- stable exit-code contract for merge gating;
- deterministic truncation/resource-cap diagnostics.

### Default human output hierarchy

1. security property that changed;
2. regression state;
3. severity/judgment only when reconciler authority supports it;
4. evidence path;
5. affected route/resource/provider boundary;
6. missing/partial coverage;
7. verification state;
8. remediation guidance as non-authoritative assistance.

### Noise policy

The default PR/review summary should focus on changes introduced or worsened by the candidate. Pre-existing backlog remains queryable but should not drown the merge decision.

## Slice S3 — GitHub / Forge Delivery

**Roadmap home:** R5  
**Depends on:** S2

### Purpose

Deliver the same local deterministic judgment through a forge without moving judgment authority into the forge integration.

### Initial GitHub scope

- GitHub Check summary;
- bounded annotations only where exact provenance exists;
- trusted-base/head verification;
- status based on the local regression/guard contract;
- no repository comment text treated as security authority;
- no implicit inheritance of broad GitHub credentials by analysis subprocesses;
- no auto-fix merge authority.

### Design rule

GitHub, GitLab, IDE, Cursor, Claude, Codex, and other integrations must consume the same local versioned protocol. They must not fork security semantics per vendor.

### Exit gate

- equivalent local and GitHub semantic outputs for frozen fixtures;
- credential/permission minimization proof;
- instruction/context provenance tests for PR metadata/comments;
- warm/cold latency measurement;
- false-block qualification.

## Slice S4 — Open Regression Conformance

**Roadmap home:** R9  
**Depends on:** S1/S2; may begin as research earlier but release authority remains gated.

### Purpose

Turn Sentrdel's semantics into an open ecosystem contract rather than a closed implementation detail.

### Artifact families

1. **Evidence conformance**
   - valid/invalid Evidence producers;
   - authority-ceiling violations;
   - provenance completeness;
   - deterministic identities.

2. **Coverage conformance**
   - unsupported producer;
   - failed producer;
   - capped analysis;
   - missing framework adapter;
   - dynamic semantics;
   - producer disappearance between base/head.

3. **Invariant conformance**
   - `SATISFIED`;
   - `VIOLATED`;
   - `UNKNOWN`;
   - `NOT_APPLICABLE`;
   - contradictory evidence.

4. **Regression-pair conformance**
   - new violation;
   - worsened guard;
   - mitigation;
   - reintroduction;
   - coverage loss;
   - rename/move ambiguity;
   - clean/no-semantic-change.

5. **Importer conformance**
   - external severity is not canonical severity;
   - external confidence/reachability is not FACT/VERIFIED authority;
   - malformed/unbounded input fails visibly;
   - producer/version/config provenance is preserved.

6. **Verification conformance**
   - separately authorized proof;
   - contradiction;
   - timeout/resource cap;
   - unavailable verifier;
   - evidence upgrade boundaries.

### Public vs protected corpus

Public conformance artifacts may be community-facing. Release qualification must also retain protected holdouts inaccessible to candidate-generation logic.

## Slice S5 — Bounded Verification of High-Value Invariants

**Roadmap home:** R6  
**Depends on:** S1/S2 and sufficient evaluation maturity

### Initial target

Do not begin with generic autonomous pentesting.

Select a tiny number of invariant classes where bounded synthetic/local verification is practical, for example:

- tenant/object isolation on a synthetic local fixture;
- protected-property mutation regression;
- webhook signature/state-transition assertions in a future provider pack;
- fix validation for a known deterministic static finding.

### Hard authority boundary

Verification remains:

- opt-in;
- isolated;
- target-scoped;
- synthetic or explicitly authorized local data by default;
- network-policy bounded;
- resource bounded;
- reproducible;
- non-autonomous with respect to third-party/production exploitation.

`FIX_VERIFIED` requires execution evidence.

## Slice S6 — External Evidence Import Protocol

**Roadmap home:** R7  
**Depends on:** stable Evidence/Coverage contracts; does not require rebuilding external engines.

### Phase 1 candidates

Prefer open machine-readable standards first:

- SARIF;
- CycloneDX;
- SPDX;
- OSV-compatible advisory/vulnerability records.

### Phase 2 candidates

Add explicit producer adapters only when useful:

- Semgrep/Opengrep;
- Trivy/Grype/Syft;
- Gitleaks;
- Checkov/Terrascan;
- user-supplied CodeQL outputs.

### Import boundary

Each import should preserve:

- producer identity;
- producer version;
- config/rule-pack identity where available;
- input/artifact digest where available;
- source location;
- original external classification;
- import time;
- Sentrdel authority ceiling;
- validation/cap diagnostics.

The importer must never silently transform external tool confidence, severity, reachability, or exploitability wording into stronger Sentrdel epistemic authority.

## Slice S7 — Semantic Provider Expansion

**Roadmap home:** R4  
**Depends on:** R3; preferred after S1-S4 product/quality proof unless a separate spec proves a stronger priority.

### Selection rule

Choose provider/framework work by **invariant leverage**, not popularity alone.

A candidate adapter should answer:

- which new actor/auth semantics become provable?
- which guard semantics become provable?
- which resource/data-operation semantics become provable?
- which cross-layer invariant becomes possible or more precise?
- how much benchmark coverage improves?
- what new false-positive/authority risk is introduced?

### Priority examples

- common Auth/OIDC/JWT/session semantics;
- Firebase rules/Auth/storage/function boundaries;
- Stripe webhook/state-transition/idempotency semantics;
- PostgreSQL direct-access semantics;
- Vercel/Cloudflare server/runtime boundaries.

A provider pack that only adds a checklist but does not strengthen semantic judgment should usually be deferred.

## Slice S8 — Dependency/Build Action Guard

**Roadmap home:** R7 plus existing Guard architecture  
**Depends on:** stable dependency evidence and explicitly controllable execution seam

### Purpose

Protect coding-agent/CI package and build actions before execution where Sentrdel genuinely controls the seam.

### Candidate inputs

- dependency/lockfile delta;
- exact package/version;
- known vulnerability/malware intelligence;
- package age where trustworthy;
- install/build scripts;
- Rust `build.rs`;
- procedural macros;
- native-code/build dependencies;
- checksum/provenance;
- approval/policy state.

### Non-goal

Do not build a proprietary malware-analysis engine as the prerequisite. Reuse qualified intelligence and scanners behind the Evidence boundary.

## Slice S9 — Runtime Correlation

**Roadmap home:** R8  
**Depends on:** R6 and stable semantic identities

Runtime observations should attach to existing semantic identities when provenance permits:

- route;
- process;
- resource;
- provider client;
- dependency;
- invariant path.

Static and runtime evidence must remain separately labeled. Runtime observation must not retroactively rewrite repository facts.

## Slice S10 — SSG Project Posture

**Roadmap home:** R10  
**Depends on:** R2-R9

R10 should compose mature semantic domains rather than invent a new judgment model.

It should answer full-project questions such as:

- where are high-authority paths reachable from low-trust inputs?
- which security invariants depend on a single fragile guard?
- where has coverage regressed?
- which agent/build/deploy actions changed project authority?
- which static claims are independently verified or contradicted at runtime?

## Slice S11 — Open Intelligence / Controlled Learning Flywheel

**Roadmap home:** R11  
**Depends on:** R6/R9

Candidate generation may propose:

- new invariant heuristics;
- framework adapters;
- rule/pack checks;
- adversarial fixtures;
- fuzz targets;
- intelligence records;
- remediation guidance.

Promotion still requires the frozen evaluator, protected holdout, ordinary independent review, and explicit repository approval/signing. Candidate-generation logic cannot alter the authority used to judge itself.

## The first four public demos

Before broad feature expansion, Sentrdel should be able to demonstrate these four cases end-to-end.

### Demo 1 — Tenant isolation regression

A PR removes or weakens a supported tenant/ownership guard while a request-controlled tenant/resource selector still reaches the data operation.

Expected developer value:

> `WORSENED`: tenant isolation property became weaker in this PR.

### Demo 2 — Elevated provider-authority regression

A request path changes from user-scoped provider authority to service-role/elevated authority without a corresponding supported application guard.

Expected developer value:

> The regression crosses an application-to-provider trust boundary; static provider posture alone is not treated as sufficient authorization proof.

### Demo 3 — Protected-property mutation regression

An explicit safe field allowlist becomes a broad request-controlled mutation capable of including protected fields.

Expected developer value:

> The mutation security property worsened, with exact request-origin and data-operation provenance.

### Demo 4 — Coverage regression

A supported ownership/auth path is refactored into dynamic/unresolved behavior.

Expected developer value:

> `COVERAGE_LOST`: Sentrdel can no longer prove the previously supported security property. The PR is not labeled clean merely because the detector lost visibility.

Demo 4 is mandatory. It demonstrates the Evidence Before Verdict thesis more strongly than another vulnerability screenshot.

## Product scorecard for post-R3 work

Every future slice should be evaluated on at least:

- invariant-regression precision;
- supported-case recall;
- clean-PR false-positive rate;
- coverage-loss truthfulness;
- provenance completeness;
- authority correctness;
- deterministic replay;
- warm/cold latency;
- memory/resource bounds;
- explanation usefulness;
- false-block rate at enforcement seams;
- local/offline usability.

Rule count and alert count are not success metrics by themselves.

## Deferral rule

A proposed major feature should normally be deferred if all of the following are true:

1. a mature external engine already provides it well;
2. importing its results would preserve the needed security value;
3. building it would not materially improve Sentrdel invariant semantics, coverage, verification, or conformance;
4. it introduces significant new dependency, credential, network, runtime, or supply-chain authority.

## Immediate continuation

This blueprint changes no current implementation authority.

The immediate repository line remains the active canonical R3 `tasks.md`. Finish it first, prove it, then reconcile this blueprint against the resulting canonical main before authorizing the first post-R3 successor spec.
