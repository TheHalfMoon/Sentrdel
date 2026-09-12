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
9. `specs/000-sentrdel-roadmap/security-control-plane-expansion-2026-09-12.md`

Supporting research/provenance records:

- `docs/third-party/source-candidate-assessment-2026-09-08.md` — AI infrastructure, artifact routing, benchmark, secure-guidance, and external-engine source study.
- `docs/third-party/source-candidate-assessment-2026-09-12.md` — GlitchTip, HackerAI, HackAgent, HexStrike AI, Shannon, HackBot, and Strix security-control-plane study.
- `docs/third-party/founder-source-reuse-attestation-2026-09-12.md` — durable record of the founder's permission statement for the 2026-09-12 sources; permission context only, not source qualification.

Candidate assessments are not Source Qualification Ledger entries and authorize no source/data/dependency/runtime adoption. Exact qualification remains mandatory before copied/vendored/linked source lands.

If any lower document conflicts with a higher authority, the lower document must change.

## Current implementation boundary

R3 is canonically complete. The historical post-R3 planning gate that once withheld implementation authority has been superseded by a fully specified active S1 Spec Kit.

**R5 / S1 — Security Invariant Regression Core is now the active implementation program under `specs/004-security-invariant-regression/`.** At this roadmap reconciliation base (`main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`), S1-T001 through S1-T010 are canonical. The exact current frontier after that base is controlled only by live repository truth plus `specs/004-security-invariant-regression/tasks.md`; this navigation file intentionally does not duplicate a rapidly changing implementation frontier.

S2, S3, and all later roadmap work remain unauthorized until their declared predecessor gates are satisfied and their own Spec Kit lifecycle establishes implementation authority.

The strategic documents in this directory **must not** bypass the active Spec Kit, task dependency order, or canonical governance gates.

## Strategic thesis

The core thesis remains deliberately narrower and more defensible than “build an open-source AppSec platform clone”:

> **Sentrdel is the open-source security-invariant regression and evidence judgment engine for AI-built software.**

The 2026-09-12 expansion defines the long-term product envelope around that kernel:

> **Sentrdel becomes an open security control plane that connects source changes, evidence, coverage, bounded verification, deployments, runtime observations, remediation, and re-verification without surrendering canonical judgment to scanners, models, or control-plane services.**

The **Sentrdel Semantic Security Graph (SSG)** is the bounded reasoning substrate, not the product category by itself.

The core product question is:

> **What security property did this change weaken, what evidence proves it, what analysis is missing, what stronger claim—if any—was separately verified, what actually shipped, what happened in runtime, and did the remediation truly hold?**

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
- proof-artifact and retest semantics;
- source/revision/deployment/runtime correlation identity;
- Finding lifecycle transition validity;
- conformance and benchmark contracts;
- local-first developer judgment and forge/agent delivery through stable protocols.

## What Sentrdel should normally reuse or import

Sentrdel should prefer qualified mature infrastructure for capabilities that do not materially improve its invariant/evidence moat:

- generic SAST engines;
- SCA/SBOM generation;
- vulnerability/advisory databases;
- secret scanners;
- IaC/cloud/container scanners;
- package intelligence;
- DAST/runtime engines;
- runtime event producers;
- observability telemetry protocols/collectors;
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
10. mature SSG-backed project posture and lifecycle/control-plane projection;
11. controlled open-intelligence/research learning flywheel.

The 2026-09-08 source-driven research adds three planning gates without renumbering S1-S11 or creating a prerequisite between S4 and S5:

- after Open Regression Conformance, an **Agentic Code Security Conformance** profile becomes research/conformance-eligible, but it is explicitly non-blocking for S5;
- before broad external-producer expansion, **Artifact Identity + Evasion-Resistant Analyzer Routing** must separate deterministic observations from probabilistic classification and keep routing disagreement visible;
- after the stable external-evidence import boundary, a **static/local Agent/MCP/Skill Security Domain** may correlate observations through ASEL and the SSG without inheriting dynamic red-team authority.

The 2026-09-12 security-control-plane blueprint adds implementation-ready **internal packages and later tracks**, not new implementation authority or a renumbering of S1-S11:

- S5 must freeze Rules of Engagement, Tool Capability Manifest, reusable verification isolation, proof artifacts, and point-retest semantics before meaningful dynamic verification;
- after S6 import contracts, an **Operational Evidence Bridge** may standardize deployment/release/error/log/trace/uptime/runtime observations using standards-first protocols;
- a later **Finding Lifecycle + Remediation** track can add triage/risk/fix/retest/reopen workflow without moving Finding creation authority out of the reconciler;
- a later **Agent Security Verification** profile may test owned/authorized synthetic/local agents only after S5 isolation and Gate A conformance exist;
- an optional self-hosted control plane may project stable local protocols only after lifecycle/runtime contracts mature; it must never become required for local judgment.

S1-S5 therefore remain the first product path. Each numbered item, planning gate, internal package, and later track requires its own future Spec Kit lifecycle and dependency/authority proof before implementation.

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

## 2026-09-12 security-control-plane refinement

The study of GlitchTip, HackerAI, HackAgent, HexStrike AI, Shannon, HackBot, and Strix identifies a second class of gaps: Sentrdel's judgment architecture is strong, but the long-term lifecycle around that judgment needs explicit contracts.

The latest blueprint therefore adds:

1. **A source-to-runtime security lifecycle spine.** Revision, Finding, fix, verification, deployment, runtime contradiction, reopen, and point retest must share stable identities and immutable lifecycle events.
2. **A typed Tool Capability Registry.** External engines declare exact executable/image identity, privileges, network/credential/target-mutation capabilities, resource bounds, output schema, and epistemic ceiling; no generic shell-string escape hatch.
3. **Machine-readable Rules of Engagement.** Any dynamic network/target verification must bind exact targets, actions, mutation budget, rate/resource/network scope, credentials references, expiry, and authorization provenance.
4. **Immutable proof artifacts.** Verification-backed claims must point to request/response exchange IDs, structured test/process/browser records, or equivalent bounded artifacts—not prose-only “exploit succeeded” claims.
5. **Durable run/checkpoint/cancellation semantics.** Long security work must distinguish interrupted/incomplete from completed clean and support bounded recovery without duplicate proof.
6. **Operational Evidence Bridge.** Prefer OpenTelemetry/OTLP and compatible event ecosystems for runtime telemetry; imported operational events remain runtime observations until reconciled.
7. **Finding lifecycle and remediation/retest.** Once the reconciler creates a Finding, lifecycle state can include acknowledgement, risk acceptance, fix candidate, retest, verified closure, stale/reopen, and related/duplicate state with audit provenance.
8. **Signed/versioned Security Packs.** Packs declare source/license/capabilities/dependencies/authority ceiling/conformance and cannot widen permissions through instructions.
9. **Agent-security verification after isolation.** Prompt injection/tool misuse/goal hijacking tests belong in a future bounded verification profile for owned/authorized agents, not ordinary review.
10. **Optional control-plane UX over stable protocols.** A web/server layer may provide inventory, lifecycle, runtime correlation and portfolio views later, while the local Rust judgment path remains independently useful.

The full gap register G15–G38, target architecture, contracts, dependency order, acceptance gates, benchmark metrics, adversarial cases, and source-specific adoption backlog are in `security-control-plane-expansion-2026-09-12.md`.

## First proof-of-category demos

Before broad feature expansion, the project should prove four end-to-end cases:

1. tenant-isolation regression;
2. elevated provider-authority regression;
3. protected-property mutation regression;
4. coverage regression where a previously provable security property becomes unsupported or ambiguous.

The fourth demo is mandatory because it proves that losing visibility is not silently converted into a clean result.

After those category demos and the S1-S4 contracts are mature, the agentic-code conformance profile should add analogous repository-level AI/agent-generated cases without changing evaluator authority or exposing protected holdouts to candidate-generation logic. That profile remains non-blocking for S5.

After S5/S6/runtime/lifecycle contracts mature, the long-term category demo expands to one full source→verification→deployment→runtime→remediation→retest chain as defined in the 2026-09-12 blueprint.

## Defensibility filter

Before approving a major future feature, ask:

1. Does it improve deterministic invariant judgment, evidence provenance, coverage truth, verification, lifecycle/retest, runtime correlation, conformance, or safe analyzer routing?
2. Is a mature external engine already good enough at the raw scanning/classification/telemetry capability?
3. Can Sentrdel import or consume the result behind an explicit untrusted-evidence boundary instead of rebuilding the engine?
4. Does building/adopting it introduce new credential, network, process, native runtime, model artifact, execution, target-mutation, or supply-chain authority?
5. Would the feature make the proof-of-category demos or protected conformance materially better?
6. Can probabilistic/external/runtime results remain structurally incapable of bypassing canonical judgment authority?
7. Can failure, timeout, unsupported state, drop/sampling, and budget exhaustion remain visible Coverage instead of becoming clean?
8. Can the capability remain optional so the local base install stays small and useful?

If the answer is mostly “no,” defer the feature.

## Planning reconciliation status

This navigation file is reconciled to protected `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`, where R3 is complete and S1 implementation is active under Spec 004 with S1-T001 through S1-T010 canonical.

The 2026-09-08 and 2026-09-12 source studies remain planning/provenance only. They do not qualify donor source for reuse, widen the active S1 implementation scope, or authorize S2+.

The next dependency-ordered implementation action is always whatever the active canonical `specs/004-security-invariant-regression/tasks.md` and live repository state authorize. After S1 closes canonically, later roadmap work still requires its own Spec Kit lifecycle before implementation.