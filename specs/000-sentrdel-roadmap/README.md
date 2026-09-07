# Sentrdel Roadmap Navigation and Authority Index

**Purpose:** Make the roadmap corpus easy to read without confusing strategic direction with implementation authority.

This file is navigation only. It does not override the Constitution, an active Spec Kit, or canonical task ordering.

## Required reading order

For any continuation that needs roadmap context, read in this order:

1. `.specify/memory/constitution.md`
2. the currently active Spec Kit `spec.md`, contracts, `plan.md`, and `tasks.md`
3. `specs/000-sentrdel-roadmap/roadmap.md`
4. `specs/000-sentrdel-roadmap/improvement-plan-2026-08-26.md`
5. `specs/000-sentrdel-roadmap/strategic-amendment-2026-09-02-semantic-security-graph.md`
6. `specs/000-sentrdel-roadmap/competitive-triangulation-2026-09-02.md`
7. `specs/000-sentrdel-roadmap/post-r3-execution-blueprint-2026-09-02.md`
8. `specs/000-sentrdel-roadmap/source-driven-security-expansion-2026-09-08.md`

Supporting exact research pins and reuse boundaries for the 2026-09-08 source study are recorded in `docs/third-party/source-candidate-assessment-2026-09-08.md`. That candidate assessment is not a source-qualification ledger entry and authorizes no source/data/dependency/runtime adoption.

If any lower document conflicts with a higher authority, the lower document must change.

## Current implementation boundary

The active implementation authority remains R3:

`specs/003-business-logic-invariants/`

At the 2026-09-08 roadmap-research planning base, R3-T032 implementation is canonical on protected `main@bf50d14ef3747b028069d148f23c1696e9e67a42`. PR #301 owns the separate R3-T032 task-ledger closeout. R3-T033 remains unauthorized until that exact closeout is itself canonical and completes its required post-merge qualification and live repository-governance proof.

The strategic documents in this directory **must not** reorder, widen, or bypass the canonical R3 task ledger.

In particular, the post-R3 blueprint and the 2026-09-08 source-driven supplement are not permission to start R5, R6, R7, R9, Agent/MCP/Skill implementation, artifact-classifier integration, external benchmark-data import, or any other successor work before R3 has canonical closeout, post-merge CI, and live repository-governance proof.

## Strategic thesis

The current roadmap refinement is intentionally narrower than "build an open-source AppSec platform clone."

The product thesis is:

> **Sentrdel is the open-source security-invariant regression and evidence judgment engine for AI-built software.**

The **Sentrdel Semantic Security Graph (SSG)** is the bounded reasoning substrate, not the product category by itself.

The core product question is:

> **What security property did this change weaken, what evidence proves it, what analysis is missing, and what stronger claim—if any—was separately verified?**

## What Sentrdel should own

Sentrdel should own the security judgment layer that is difficult to make both deterministic and open:

- canonical Evidence and Coverage contracts;
- stable semantic identities and provenance;
- bounded route / actor / auth / guard / data / provider-authority relationships;
- security invariants;
- trusted-base versus candidate invariant regression;
- explicit coverage regression;
- reconciler-only Finding authority;
- bounded verification evidence upgrades;
- conformance and benchmark contracts;
- local-first developer judgment and forge/agent delivery through stable protocols.

## What Sentrdel should normally reuse or import

Sentrdel should prefer qualified mature infrastructure for capabilities that do not materially improve its invariant/evidence moat:

- generic SAST engines;
- SCA/SBOM generation;
- vulnerability/advisory databases;
- secret scanners;
- IaC scanners;
- package intelligence;
- DAST/runtime engines;
- code indexing/parsing infrastructure;
- forge/IDE integration primitives;
- optional probabilistic artifact classifiers where they improve safe routing without becoming judgment authority.

External output remains untrusted evidence and never becomes canonical judgment merely because the upstream tool reports severity, confidence, reachability, exploitability, identity, or a high benchmark score.

## Post-R3 bounded sequence

The current preferred strategic decomposition after canonical R3 closeout remains:

1. Security Invariant Regression Core;
2. local Security Regression Developer Contract;
3. GitHub/forge delivery using the same local judgment protocol;
4. Open Regression Conformance;
5. bounded verification for selected high-value invariants;
6. External Evidence Import Protocol;
7. semantic provider/framework expansion by invariant leverage;
8. dependency/build action guard at genuinely controllable seams;
9. runtime evidence correlation;
10. mature SSG-backed project posture;
11. controlled open-intelligence/research learning flywheel.

The 2026-09-08 source-driven research adds three **planning gates without renumbering S1-S11 or creating a prerequisite between S4 and S5**:

- after Open Regression Conformance, an **Agentic Code Security Conformance** profile becomes research/conformance-eligible, but it is explicitly **non-blocking for S5** and constrains broad agent-specific detector expansion rather than bounded verification;
- before broad external-producer expansion: **Artifact Identity + Evasion-Resistant Analyzer Routing**, separating deterministic observations from probabilistic classification and making routing disagreement visible;
- after the stable external-evidence import boundary: a **static/local Agent/MCP/Skill Security Domain** whose observations can correlate through ASEL and the SSG without inheriting dynamic red-team authority.

S1-S5 therefore remain the first product path exactly as intended by the 2026-09-02 blueprint.

Each numbered item and each planning gate is roadmap decomposition only. Each requires its own future Spec Kit lifecycle and dependency/authority proof before implementation.

## 2026-09-08 source-driven refinement

The study of `Tencent/AI-Infra-Guard`, `google/magika`, `Tencent/AICGSecEval`, `Tencent/secguide`, and `Tencent/TscanCode` confirms the existing defensibility strategy and adds these directions:

1. **Do not trust file extensions for analyzer routing.** Repository paths and extensions are untrusted; deterministic content observations, optional classifier inference, disagreement diagnostics, resource caps and explicit coverage should drive conservative routing.
2. **Generalize the model-output boundary to probabilistic producers.** ML file classification, AI-assisted scanner confidence, external severity and external reachability are not Sentrdel FACT/VERIFIED authority by themselves.
3. **Make Agent/MCP/Skill security an explicit semantic domain.** Prioritize local static instruction/tool/permission/dependency/credential/action analysis and correlate it with ASEL/SSG; defer dynamic red-team execution to separately authorized verification tiers.
4. **Add repository-level agent-generated-code conformance.** Measure invariant regressions, coverage loss, evidence chains and evaluator independence, with public fixtures plus protected holdouts. This conformance work may start from S4 contracts but must not delay S5.
5. **Treat knowledge/rule sources as candidate supply-chain inputs.** Preserve exact provenance, license, freshness, transformation, qualification, promotion, retirement and revalidation state; never auto-promote external rules into trusted judgment.
6. **Keep standards-first external evidence, but support bounded generic producer adapters.** Tool-specific XML/JSON/SARIF remains untrusted input subject to parser caps, path validation, truncation diagnostics and authority ceilings.
7. **Do not chase language or scanner count before the regression moat is proven.** External breadth informs benchmarks and future adapter selection; it does not reorder S1-S5.
8. **Separate claimed model/provider identity from stronger attested identity.** Agent/model/relay provenance can improve reproducibility and later posture, but ordinary static review must not perform network model fingerprinting or treat an unverified identity as proof of compromise.

The detailed gaps, entry/exit gates, source dispositions and non-goals are in `source-driven-security-expansion-2026-09-08.md`.

## First proof-of-category demos

Before broad feature expansion, the project should prove four end-to-end cases:

1. tenant-isolation regression;
2. elevated provider-authority regression;
3. protected-property mutation regression;
4. coverage regression where a previously provable security property becomes unsupported or ambiguous.

The fourth demo is mandatory because it proves that losing visibility is not silently converted into a clean result.

After those category demos and the S1-S4 contracts are mature, the agentic-code conformance profile should add analogous repository-level AI/agent-generated cases without changing the evaluator authority or exposing protected holdouts to candidate-generation logic. That profile remains non-blocking for S5.

## Defensibility filter

Before approving a major future feature, ask:

1. Does it improve deterministic invariant judgment, evidence provenance, coverage truth, verification, conformance, or safe analyzer routing?
2. Is a mature external engine already good enough at the raw scanning/classification capability?
3. Can Sentrdel import or consume the result behind an explicit untrusted-evidence boundary instead of rebuilding the engine?
4. Does building/adopting it introduce new credential, network, process, native runtime, model artifact, execution, or supply-chain authority?
5. Would the feature make the proof-of-category demos or protected conformance materially better?
6. Can a probabilistic result or claimed identity be kept structurally incapable of becoming FACT/VERIFIED merely because of confidence, naming, or benchmark performance?

If the answer is mostly "no," defer the feature.

## Planning-PR reconciliation status

The strategic roadmap planning line was previously reconciled with canonical `main` after earlier R3 progress. The 2026-09-08 supplement is based on `main@bf50d14ef3747b028069d148f23c1696e9e67a42`, where the R3-T032 implementation is canonical while its task-ledger closeout remains a separate governed change.

This research update changes roadmap planning only. It does not authorize R3-T033 by itself, does not close R3, does not qualify the five studied sources for reuse, and does not authorize any post-R3 successor slice. Active implementation permission continues to come only from the Constitution and the canonical Spec 003 artifacts.
