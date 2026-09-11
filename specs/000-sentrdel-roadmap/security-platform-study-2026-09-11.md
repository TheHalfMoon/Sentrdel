# Sentrdel Security Platform Study and Roadmap Refinement — 2026-09-11

**Status:** ROADMAP_RESEARCH_SUPPLEMENT  
**Research date:** 2026-09-11  
**Planning base:** `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`  
**Active implementation boundary at planning time:** S1-T010 is canonical; S1-T011 is open in PR #330 and remains governed exclusively by `specs/004-security-invariant-regression/`.  
**Source assessment:** `docs/third-party/source-candidate-assessment-2026-09-11.md`  
**Sources studied:** GlitchTip, HackerAI, HackAgent, HexStrike AI, Shannon, HackBot, Strix.  
**Authority:** Roadmap planning/research only. This document does not amend the Constitution, modify the active S1 spec/plan/tasks, authorize donor-source reuse, admit dependencies, authorize target/network/credential execution, or authorize autonomous exploitation.

## Executive decision

The current Sentrdel category is correct and should become **more opinionated, not broader by imitation**.

Sentrdel should **not** become another autonomous pentesting agent, scanner bundle, generic SIEM/APM, or offensive-tool orchestrator. Those products can be copied, commoditized, or delegated to mature external engines.

The stronger product is:

> **Sentrdel is the local-first Security Evidence Control Plane for AI-built software: it knows what security property changed, what evidence supports the claim, what analysis was incomplete, what proof was separately verified, and whether runtime reality later confirmed or contradicted the static judgment.**

The post-R3 roadmap already owns the right moat: Evidence, Coverage, SSG, invariants, regression, reconciliation, conformance and bounded verification. The source study exposes missing **contracts around execution and lifecycle**, not a need to add more scanners to S1.

The principal roadmap refinements are:

1. freeze a sealed **VerificationRun** contract before Sentrdel executes any future verifier;
2. freeze a qualified **ToolCapabilityManifest** for every executable external engine/tool;
3. make **RunCompleteness** independent from "findings found" so partial/capped/failed work can never become clean;
4. make long verification resumable only through a contract-bound **CheckpointManifest**;
5. add digest-bound authorization receipts for source/target snapshots and capability scopes;
6. turn R8 runtime work into a versioned **Runtime Evidence Ingest** plane, with Sentry-compatible telemetry considered as an adapter rather than rebuilding an APM;
7. add an auditable **Finding/Regression Lifecycle** and local Security Workbench over canonical Sentrdel records;
8. standardize evidence-rich report bundles and SARIF export without granting report formats authority;
9. treat remediation as a candidate loop whose stronger `FIX_VERIFIED` state requires exact re-analysis/execution evidence;
10. add open conformance for run completeness, tool manifests, resume integrity, cleanup ambiguity and runtime correlation.

These refinements do **not** reorder S1-S5. S1 remains intentionally static, local and execution-free.

---

## Review of the active S1 plan

The active S1 plan and task ledger were reviewed against the seven studied systems.

### What is already strong and should not change

S1 correctly freezes:

- exact trusted-base/candidate identities;
- bounded SemanticSnapshot composition;
- stable invariant matching;
- exact semantic-object continuity without fuzzy identity;
- bilateral Evidence/provenance preservation;
- explicit Coverage pairing;
- deterministic regression semantics;
- no forge/network/provider credentials/target execution/model/external engine;
- no direct Finding authority;
- benchmark and authority qualification before promotion.

Those constraints are an advantage. They prevent the common failure mode seen in agentic security products where orchestration, model opinion, exploit execution and reporting are allowed to blur into one authority surface.

### S1 gaps found

**No active S1 contract gap was found that justifies changing `specs/004-security-invariant-regression/plan.md` or reordering `tasks.md`.**

The new gaps begin when future slices add execution, external engines, long-running runs, runtime telemetry and persistent developer workflows. Therefore this study updates successor-roadmap planning only.

This is an intentional governance decision: do not destabilize a correctly bounded implementation-ready spec because later products expose additional requirements.

---

## Strategic architecture after this study

```text
                         ┌───────────────────────────────────────┐
                         │ Developer / Agent / CI / Workbench    │
                         │ local CLI · forge · IDE · reports     │
                         └──────────────────┬────────────────────┘
                                            │ versioned contracts
                                            v
┌────────────────────────────────────────────────────────────────────────────┐
│                     TRUSTED RUST JUDGMENT PLANE                           │
│ Evidence · Coverage · SSG · Invariants · Regression · Policy · Reconciler │
│ exact identity · authority ceilings · deterministic reason codes           │
└───────────────┬────────────────────┬─────────────────────┬─────────────────┘
                │                    │                     │
                v                    v                     v
     ┌──────────────────┐  ┌──────────────────────┐  ┌─────────────────────┐
     │ Evidence Import  │  │ Verification Plane   │  │ Runtime Evidence    │
     │ SARIF/SBOM/etc.  │  │ sealed Verification │  │ errors/logs/CSP/    │
     │ untrusted input  │  │ Run + capabilities  │  │ uptime/perf/events  │
     └─────────┬────────┘  └──────────┬───────────┘  └──────────┬──────────┘
               │                      │                         │
               v                      v                         v
     qualified parsers       qualified sandbox/tool       versioned adapters
                             backends, least authority      redaction/retention
                                      │
                                      v
                             external engines/tools
                             (never judgment authority)

              ┌─────────────────────────────────────────────┐
              │ Candidate Research / Learning Plane         │
              │ propose only; frozen evaluator/holdouts win │
              └─────────────────────────────────────────────┘
```

The architecture intentionally separates **observation**, **verification**, **judgment** and **delivery**. No external engine, model, sandbox or report renderer receives a shortcut into canonical Finding authority.

---

## Gap analysis

### G1 — Verification execution has no frozen run contract yet

R6/S5 correctly says bounded, opt-in and isolated verification, but the roadmap does not yet enumerate the minimum immutable contract that makes a verification run auditable and resumable.

Future `VerificationRun` should bind at minimum:

- run contract/schema version;
- exact trusted-base and candidate identity where relevant;
- exact target/source snapshot digest;
- invariant/Finding/regression identities being verified;
- verifier profile and verifier version/digest;
- tool/container/runtime backend identity;
- authorization receipt and scope;
- allowed filesystem roots and mutation policy;
- network policy and destination scope;
- credential policy and exact credential-class declarations without persisting plaintext;
- resource/budget ceilings;
- environment allowlist/scrubbing policy;
- artifact-retention/redaction policy;
- timeout/cancellation policy;
- expected evidence outputs;
- completeness requirements;
- created/start/end state;
- deterministic run ID derived from canonical non-secret material where safe.

**Hard rule:** a verifier MUST NOT run if the approved target snapshot or security-relevant run contract has changed since authorization.

### G2 — Run outcome and run completeness are currently under-separated

Agentic tools commonly expose an exit code or final finding count that invites a false "clean" interpretation.

Sentrdel should freeze a first-class `RunCompleteness` state independent from security outcome. Candidate states should be specified later, but the design must distinguish at least:

- complete/supported;
- incomplete due to producer/verifier failure;
- incomplete due to timeout;
- incomplete due to resource/budget cap;
- incomplete due to authorization/scope restriction;
- unsupported capability;
- cancelled;
- launch outcome uncertain;
- cleanup outcome uncertain;
- output invalid/unparseable;
- dependency/runtime unavailable.

A run with zero verified failures and incomplete Coverage is **not clean**.

### G3 — External executable tools need capability manifests, not just names

Sentrdel's future external-engine story is stronger if every executable producer/verifier exposes a signed/digested `ToolCapabilityManifest` or equivalent canonical descriptor.

It should record:

- tool identity/version/digest/source qualification ID;
- executable/container identity;
- accepted inputs and emitted output schema;
- whether output is deterministic, heuristic, probabilistic or model-assisted;
- read/write filesystem scope;
- subprocess authority;
- network authority/destinations;
- browser authority;
- credential classes;
- target mutation/side-effect class;
- resource ceilings;
- expected cleanup behavior;
- Evidence classes emitted;
- Coverage dimensions emitted;
- maximum authority ceiling;
- benchmark/conformance qualification;
- revocation/retirement state.

Unknown or undeclared capabilities fail closed before execution.

### G4 — Least-authority tool binding must be per run

A broad plugin/tool registry is useful for discovery but dangerous as ambient authority.

Future verification orchestration should construct an explicit per-run capability set from the frozen run profile. The runtime receives only those capabilities. Tools not admitted by the profile are structurally unavailable, not merely discouraged by a prompt.

Repository-controlled configuration MUST NOT be able to widen the capability set beyond trusted policy.

### G5 — Long-running verification needs sealed resumability

Shannon's run-state/checkpoint patterns reveal a roadmap gap: when verification lasts long enough to resume, the **resume itself becomes a security boundary**.

Future `CheckpointManifest` should bind:

- original VerificationRun ID/digest;
- stage identity;
- completed work units;
- artifact digests;
- canonical Evidence records already accepted;
- pending work;
- resource/budget consumption;
- verifier/tool/runtime versions;
- finalization/publication state;
- integrity link to the previous checkpoint.

Resume must reject changes to target digest, authorization, network/credential policy, verifier/tool identity, evidence schema or other security-relevant fields unless a new run is explicitly authorized.

No "resume with convenient new settings" path should exist.

### G6 — Launch/cleanup ambiguity needs an explicit state

Distributed or sandboxed execution can fail after a request is accepted but before the client knows whether work started, and cleanup can be uncertain after interruption.

Sentrdel should never blindly retry potentially side-effecting verification under ambiguity. It needs explicit `LAUNCH_UNKNOWN` / `CLEANUP_UNKNOWN`-like semantics or equivalent future names, plus reconciliation before retry.

This is both a safety property and an evidence-integrity property.

### G7 — Digest-bound authorization should be a reusable primitive

Strix's source-upload approval pattern highlights a useful generic control: the human/policy approval should bind exactly what is being authorized.

Future Sentrdel authorization receipts should bind:

- exact source/target digest;
- exact target identity/scope;
- verification profile;
- capability set;
- network policy;
- credential classes;
- expiry;
- approving principal/policy identity;
- optional environment/deployment identity.

A changed snapshot invalidates the receipt.

This primitive can later protect verification, provider live posture, build-action guards and destructive remediation flows.

### G8 — Runtime observability needs a security-evidence adapter contract

R8 currently says runtime observations should correlate back into semantic identities, but it does not yet define the operational telemetry boundary.

A future `RuntimeObservation`/adapter contract should cover, where privacy-safe and useful:

- application exceptions;
- security-relevant log events;
- CSP violations;
- route/transaction observations;
- selected performance anomalies;
- uptime/heartbeat state;
- release/deployment identity;
- process/service identity;
- sanitized request/actor/resource correlation keys;
- source SDK/collector identity and version;
- sampling state;
- dropped/truncated event diagnostics.

A Sentry-compatible intake adapter is a high-leverage candidate because open Sentry SDKs already exist across languages and GlitchTip demonstrates a self-hosted compatible model. Sentrdel should consume the telemetry necessary for security correlation rather than become a general error-tracking/APM clone.

Runtime observations remain a separate epistemic class. They cannot retroactively rewrite repository facts or prove static causality solely through temporal correlation.

### G9 — Runtime telemetry needs privacy, retention and cardinality gates

Before any runtime ingestion is implementation-ready, freeze:

- local-first default;
- tenant/project binding;
- secret/PII redaction before persistence;
- field allowlists;
- payload/event size caps;
- tag/cardinality caps;
- sampling semantics;
- event deduplication/replay identity;
- retention/deletion policy;
- raw-body/header/cookie default denial;
- encrypted-at-rest expectations where applicable;
- backpressure/drop diagnostics;
- offline behavior.

Dropped or sampled telemetry must become visible Coverage context, not silent absence.

### G10 — Finding/regression lifecycle is not yet a first-class product contract

Sentrdel has canonical Finding authority and S1 is building regression records, but the long-term developer workflow needs an auditable lifecycle that does not mutate history.

A future lifecycle model should preserve:

- Finding/regression stable identity;
- first/last observed revision;
- current canonical disposition;
- historical Evidence/Coverage snapshots by immutable reference;
- remediation candidate links;
- verification run links;
- risk acceptance/suppression with author, reason, scope and expiry;
- reopen/reintroduction state;
- assignment/ownership as workflow metadata only;
- provider/runtime correlation;
- retirement/obsolete reason.

Suppression changes developer workflow, not historical truth. A suppressed violation remains historically observed.

### G11 — Sentrdel needs a local Security Workbench, not just CLI text

After S2/S3 contracts stabilize, a local-first workbench can make Sentrdel substantially more useful without changing judgment authority.

High-value views:

- change-relative security regressions;
- exact Evidence chain and Coverage gaps;
- SSG attack/trust-boundary explorer;
- before/after invariant view;
- verification status and run completeness;
- imported external evidence by producer;
- runtime confirmation/contradiction;
- finding lifecycle/remediation state;
- dependency/provider/action authority changes;
- benchmark/conformance status for packs/tools.

The UI is a projection over canonical contracts. It cannot create stronger epistemic authority than the Rust core.

### G12 — Reporting should be standardized and evidence-rich

Future Sentrdel report bundles should separate canonical machine data from rendered presentation.

Candidate outputs:

- versioned canonical Sentrdel JSON;
- SARIF 2.1.0 for forge/code-scanning interoperability;
- Markdown/HTML/PDF rendered from canonical data;
- optional standards mappings where justified;
- manifest containing report schema version, source revision/run IDs, producer/importer versions and artifact digests.

Export formats must not alter canonical classification. If SARIF requires a severity/result mapping, record the mapping rule explicitly and preserve Sentrdel's original Evidence/Coverage/verification state.

### G13 — Remediation needs a candidate/proof separation

Model-assisted patches can improve UX but must never be treated as proof.

A future remediation loop should be:

`canonical issue/regression -> candidate remediation -> exact candidate digest -> S1/S2 re-analysis -> optional bounded VerificationRun -> reconciled result -> FIX_VERIFIED only if proof contract succeeds`

Auto-generated commands, patches or configuration changes remain non-authoritative assistance. No one-click merge receives bypass authority over ordinary repository governance.

### G14 — Campaign/portfolio grouping must not merge security authority

Teams will eventually need multi-repository or multi-service views. Campaigns may group runs for UX and reporting, but each target keeps independent:

- authorization;
- target digest/identity;
- Coverage;
- verifier/tool set;
- Evidence provenance;
- runtime observation binding;
- Finding/regression identity.

A campaign summary is an aggregate view, not an authority domain.

### G15 — Compliance and ATT&CK mappings are useful derived context, not the moat

HackBot demonstrates the UX value of compliance and ATT&CK mapping. Sentrdel should support them later where canonical Evidence makes the mapping defensible, but these are derived views.

A mapping must preserve:

- source taxonomy/version;
- mapping rule/version;
- exact canonical records mapped;
- confidence/ambiguity when the mapping is not deterministic.

A framework mapping cannot upgrade a hypothesis into a Finding or verification result.

### G16 — Operational reliability metrics should become qualification data

Verification and external-engine quality is not only security accuracy. Future qualification should measure:

- queue/start latency;
- sandbox readiness time;
- verifier execution duration;
- cancellation latency;
- retry/recovery counts;
- CPU/memory/output bytes;
- budget consumption;
- timeout/cap rates;
- launch/cleanup ambiguity rate;
- parse/validation failure rate;
- warm/cold latency;
- cross-platform behavior.

These are operational metrics, not evidence authority. They help decide whether a verifier/tool is safe and useful enough for release.

### G17 — Plugin/pack distribution needs executable-authority supply-chain controls

The existing roadmap already treats Rules/Security Packs as supply-chain objects. This study tightens the future distinction between declarative content and executable capability.

Every distributed artifact should expose:

- digest;
- publisher/provenance;
- signature/attestation where available;
- schema version;
- declared capabilities;
- whether it executes code;
- authority ceiling;
- benchmark/conformance qualification;
- dependency closure where applicable;
- revocation/retirement state;
- revalidation deadline.

Declarative rules receive no process/network/secret authority. Executable plugins require a much stronger qualification tier and should normally run outside the trusted core.

### G18 — Attack-surface inventory should be a product view over the SSG

Agentic pentest products gain usability from showing discovered interfaces, trust boundaries and data flows. Sentrdel should expose this insight without inventing a second graph engine.

The SSG-backed workbench should eventually answer:

- which externally influenced routes reach high-authority operations?
- which actor/auth/guard assumptions protect each sensitive resource?
- where does provider authority exceed application authorization?
- which new edge/path appeared in the candidate?
- which paths lost analysis Coverage?
- which paths have runtime observations or verification evidence?

This is a view over bounded SSG semantics, not a universal CPG or causal proof engine.

---

## New planning contracts

The names below are planning targets, not implementation-authorized public APIs.

### 1. `VerificationRun`

Purpose: freeze exact target, scope, verifier, capabilities, authorization, limits and evidence expectations before execution.

Security property: execution cannot silently widen after approval.

### 2. `AuthorizationReceipt`

Purpose: bind a human/policy authorization to exact target/source digest, profile, capability set, network/credential scope and expiry.

Security property: authorization is not transferable to a changed target.

### 3. `ToolCapabilityManifest`

Purpose: make executable tool authority reviewable and machine-enforceable.

Security property: a tool cannot gain ambient undeclared filesystem/network/process/credential authority.

### 4. `RunCompleteness`

Purpose: distinguish security outcome from whether required analysis/verification actually completed.

Security property: incomplete work cannot become clean.

### 5. `CheckpointManifest`

Purpose: make long-run resume/finalization contract-bound and auditable.

Security property: resumed work cannot change security-relevant semantics or duplicate/contradict prior publication silently.

### 6. `RuntimeObservation`

Purpose: ingest bounded operational telemetry with explicit collector, sampling, redaction, retention and semantic correlation.

Security property: runtime evidence stays separately typed and cannot rewrite static facts.

### 7. `FindingLifecycleEvent`

Purpose: preserve suppression, acceptance, remediation, verification, reintroduction and workflow history without mutating original Evidence.

Security property: workflow state cannot erase historical security truth.

### 8. `ReportBundleManifest`

Purpose: bind canonical JSON plus rendered/SARIF artifacts to exact revisions/runs/schema/renderers.

Security property: rendering/interchange cannot silently change judgment.

---

## Refined post-R3 sequence

Canonical S1-S11 identities remain unchanged. The gates below are planning refinements, not new authorized slice IDs.

1. **S1 — Security Invariant Regression Core** — unchanged; finish current tasks exactly as specified.
2. **S2 — Security Regression Developer Contract** — unchanged.
3. **S3 — GitHub / Forge Delivery** — unchanged.
4. **S4 — Open Regression Conformance** — extend future conformance design to anticipate executable-tool/run-completeness contracts, but do not delay core regression conformance.
5. **Gate D — Verification Run Contract (R6 planning prerequisite)** — before any S5 executable verifier, freeze `VerificationRun`, `AuthorizationReceipt`, `ToolCapabilityManifest`, `RunCompleteness`, cancellation, resource and cleanup semantics.
6. **S5 — Bounded Verification of High-Value Invariants** — preserve the current tiny/synthetic/local initial scope; no generic autonomous pentesting.
7. **Gate E — Resumable Verification Integrity (R6/R9)** — before long-running/resumable verifier campaigns become supported, freeze `CheckpointManifest`, resume compatibility, idempotent finalization and launch/cleanup ambiguity semantics.
8. **Gate B — Artifact Identity + Evasion-Resistant Routing (existing R7/R9 refinement)** — unchanged.
9. **S6 — External Evidence Import Protocol** — add generic producer/tool manifest linkage and run-completeness import fields where the producer exposes them.
10. **Gate C — Agent/MCP/Skill Static Security Domain (existing R7/R9 refinement)** — unchanged; no dynamic red-team authority by default.
11. **S7 — Semantic Provider Expansion** — unchanged, selected by invariant leverage.
12. **S8 — Dependency/Build Action Guard** — reuse `AuthorizationReceipt`/capability-manifest concepts at controllable execution seams.
13. **Gate F — Runtime Evidence Intake Contract (R8/R9)** — freeze telemetry schema, privacy/redaction/sampling/retention, collector identity and correlation semantics before broad runtime ingestion.
14. **S9 — Runtime Correlation** — correlate bounded runtime observations to stable semantic identities; consider Sentry-compatible SDK/envelope interoperability rather than building a generic APM.
15. **Gate G — Workbench/Lifecycle Contract (R10)** — freeze immutable lifecycle events, suppression/acceptance semantics and report-bundle projection before persistent team workflows.
16. **S10 — SSG Project Posture** — mature into the local Security Workbench / attack-surface and lifecycle view over canonical data.
17. **S11 — Open Intelligence / Controlled Learning Flywheel** — use historical run/lifecycle data only through candidate generation; it cannot self-promote or alter its evaluator.

**Dependency invariant:** none of Gates D-G authorizes implementation by this document. Each requires its own future Spec Kit or inclusion in a separately implementation-ready successor spec.

---

## R6 / S5 target architecture — bounded verification, not autonomous pentesting

The best ideas from Shannon, Strix, HackerAI and HackAgent should converge into this defensive form:

```text
canonical regression/Finding/hypothesis
              |
              v
     VerificationRun contract
 target digest · authorization · limits
 capabilities · network · credentials
              |
              v
   qualified isolated runtime backend
              |
       only admitted tools
              |
              v
 verifier produces raw observations
              |
              v
 bounded parser / Evidence normalizer
              |
              v
 Sentrdel reconciler + Coverage truth
              |
              +--> VERIFIED / CONTRADICTED / INCONCLUSIVE / unavailable
              |
              +--> immutable artifacts + CheckpointManifest
```

The verifier may prove or disprove a selected claim. It does not become the judge of unrelated project security.

### Initial verification classes should remain narrow

Preserve the existing S5 direction:

- synthetic tenant/object isolation;
- protected-property mutation;
- future webhook signature/state transition assertions;
- exact fix validation for deterministic supported findings.

Do not start with generic internet reconnaissance, broad pentest autonomy, exploit-chain search, credential attacks or post-exploitation.

---

## R8 / S9 target architecture — runtime evidence without becoming an APM

```text
open runtime SDK/collector
  errors · logs · CSP · uptime · selected performance
                |
                v
      bounded intake adapter
 schema · size · tenant · redaction · sampling
                |
                v
        RuntimeObservation
 collector/version · release · route/process hints
                |
                v
        SSG correlation layer
 exact provenance where possible; ambiguity visible
                |
                v
       canonical Evidence/reconciler
 static state preserved; runtime is separate proof/context
```

### High-value correlations

Examples of useful future correlation, without overclaiming causality:

- a route involved in a static authorization regression also emits repeated access-denied or unexpected privileged-operation runtime events;
- a deployment release matching a candidate revision produces new CSP violations tied to an affected route;
- a provider/client path classified as elevated in the SSG appears in runtime error/log evidence for a request-controlled flow;
- a static finding claimed fixed is contradicted by a runtime observation on the exact post-fix release;
- a route expected to be exercised has no runtime telemetry because sampling/collector Coverage is missing, which remains visible rather than interpreted as safe.

---

## Developer product direction

### Local Security Workbench

After canonical contracts exist, the ideal Sentrdel user experience should feel like a security-specific change debugger:

1. **What changed?** — exact invariant/regression and SSG delta.
2. **Why does it matter?** — affected actor, route, guard, data/resource/provider boundary.
3. **What proves it?** — Evidence chain and epistemic class.
4. **What is missing?** — Coverage by producer/domain/runtime/verification.
5. **Can it be proven stronger?** — authorized bounded verification profile.
6. **Did the proposed fix actually work?** — exact candidate re-analysis and optional `FIX_VERIFIED` evidence.
7. **What happened after deploy?** — separately labeled runtime observations.
8. **What is the lifecycle state?** — open/accepted/remediated/reintroduced/suppressed-with-expiry as workflow context.

This is more defensible than a generic chat interface because every answer is grounded in versioned canonical contracts.

### Agent integration

Coding agents should consume the same local protocol as humans and CI. Future agents may request explanation, propose remediation or request an allowed verification profile. They do not receive hidden bypass authority.

A powerful agent integration should be safer than manual shell use because Sentrdel can expose **narrow typed security actions** rather than a generic unrestricted terminal.

---

## External engine strategy

The studied products reinforce the roadmap's existing deferral rule.

### Adopt/import when mature externally

Prefer qualified external engines for raw capability such as:

- generic SAST/DAST;
- browser-driving verification;
- Nuclei-like template scanning;
- SBOM/SCA/IaC/secrets;
- container/cloud posture scanners;
- runtime error/log collection;
- CVE/advisory intelligence;
- PDF/report rendering.

### Sentrdel value added

For every imported/executed producer, Sentrdel adds:

- exact producer/tool identity;
- config/rule-pack digest;
- capability/authority manifest;
- bounded parser;
- Evidence normalization;
- Coverage state;
- stable SSG/invariant correlation;
- trusted-base/candidate comparison;
- verification state;
- contradiction handling;
- deterministic lifecycle/reporting;
- benchmark/conformance qualification.

That layer is the product moat.

---

## Source adaptation matrix

| Source | Adapt | Do not adopt |
|---|---|---|
| GlitchTip | Sentry-compatible runtime intake concepts; local/self-hosted privacy; errors/logs/CSP/performance/uptime as observations | general APM clone; raw sensitive telemetry by default |
| HackerAI | sandbox health/readiness; durable run/reconnect/cancel/resource-pressure patterns | cloud/provider lock-in; ambient model credentials; unrestricted agent shell |
| HackAgent | modular target/verifier/generator roles; agent-security conformance adapters | LLM judge as truth; automated jailbreak engine in trusted core |
| HexStrike AI | tool registry/capability metadata; process/resource/error management; progress UX | autonomous attack chains; exploit/post-exploit/credential tooling as default Sentrdel authority |
| Shannon | sealed resume/run state; checkpoints/finalization; incomplete-vs-clean; evidence-rich SARIF/reporting | AGPL code in permissive core without separate qualification; autonomous exploitation as general verification |
| HackBot | finding lifecycle/workbench; assessment history; campaign grouping; derived ATT&CK/compliance views | zero-day exploit-chain automation; unrestricted proxy/replay; auto-remediation authority |
| Strix | digest-bound source approval; explicit run completeness/budgets; pluggable per-run sandbox; structured run artifacts | autonomous pentest graph; broad shell/browser authority; cloud upload as a base requirement |

---

## Conformance additions for R9

Future SentrdelBench/Open Conformance should add fixture families for:

### Verification run conformance

- valid exact target digest;
- changed target after authorization;
- expired/wrong-scope authorization;
- undeclared tool capability;
- network destination outside policy;
- credential class outside policy;
- timeout/resource cap;
- verifier unavailable;
- malformed output;
- cancellation;
- launch ambiguity;
- cleanup ambiguity;
- complete no-issue result;
- incomplete no-issue result that must not become clean.

### Resume/checkpoint conformance

- exact compatible resume;
- changed target digest;
- changed verifier/tool version;
- changed network/credential policy;
- changed Evidence schema;
- corrupt checkpoint;
- duplicate/forked finalization;
- replay/idempotency behavior;
- truncated history/checkpoint chain.

### Tool-manifest conformance

- missing digest/version;
- undeclared subprocess/network/browser capability;
- output exceeding cap;
- producer severity/confidence attempting authority escalation;
- revoked tool manifest;
- config/rule-pack drift;
- process exits without required Coverage state.

### Runtime-evidence conformance

- valid error/log/CSP observation;
- wrong tenant/project binding;
- secret/PII field rejection/redaction;
- oversized event;
- high-cardinality tag cap;
- sampling/drop diagnostics;
- duplicate/replayed event;
- ambiguous semantic correlation;
- release/revision mismatch;
- runtime contradiction of a static claim;
- collector failure that must become Coverage loss/unknown.

---

## Product scorecard after S5

Keep existing precision/recall/FP/coverage/latency gates and add:

| Dimension | Measure |
|---|---|
| Regression truth | supported invariant-regression precision/recall and clean-change FP rate |
| Coverage honesty | rate at which failed/missing/capped producers remain visible rather than clean |
| Verification quality | proof success, contradiction, inconclusive and unavailable rates by supported profile |
| Run integrity | unauthorized contract-drift rejection rate; resume replay determinism |
| Sandbox safety | undeclared capability escapes = zero; network/credential policy violations = zero |
| Operational reliability | timeout/cancel/cleanup ambiguity rates, queue and execution latency, resource pressure |
| Import quality | malformed external record rejection; authority-escalation attempts blocked |
| Runtime correlation | precision of semantic identity correlation; ambiguous links kept ambiguous |
| Privacy | plaintext secret persistence = zero; redaction/cardinality/retention conformance |
| Developer utility | time-to-explanation, time-to-triage, time-to-fix, false-block rate |
| Lifecycle integrity | suppression/acceptance cannot delete or rewrite historical Evidence |
| Cross-platform | equivalent authority/coverage semantics across supported OS/runtime backends |

Rule count, tool count, agent count and raw alert count remain non-goals.

---

## Proof-of-platform demos

The existing four proof-of-category demos remain mandatory. After S1-S5 mature, add these demonstrations in dependency order:

### Demo 5 — Exact fix verification

A candidate fixes a supported invariant regression. Static comparison shows mitigation, then a separately authorized local verification profile proves the fixed property. `FIX_VERIFIED` links to the exact candidate digest and VerificationRun.

### Demo 6 — Incomplete verifier does not become clean

A verifier stops due to timeout/budget/resource cap after finding nothing. Sentrdel reports incomplete Coverage/verification, not PASS.

### Demo 7 — Authorization digest drift is rejected

A source/target snapshot changes after authorization but before verification. Sentrdel refuses execution until a new exact-snapshot authorization exists.

### Demo 8 — Resume contract drift is rejected

A long verification is interrupted. Resume with the exact run contract succeeds; changing the verifier/tool/network profile fails closed and requires a new run.

### Demo 9 — Runtime evidence confirms or contradicts static judgment

A deployed release emits bounded runtime evidence that can be mapped to an existing route/resource/invariant identity. Sentrdel shows the runtime observation beside the static result without rewriting the original fact.

### Demo 10 — Multi-source evidence reconciliation

The same semantic issue receives R3 static Evidence, imported SARIF, optional verifier output and runtime observations. Sentrdel keeps all producer provenance and Coverage separate, reconciles contradictions, and produces one canonical developer judgment without trusting any producer's severity/confidence by itself.

---

## Implementation non-goals reaffirmed

This study explicitly does **not** authorize:

- autonomous exploitation;
- testing arbitrary third-party or production targets;
- credential spraying, password cracking or post-exploitation;
- internet-scale reconnaissance;
- unrestricted agent shell/browser/network access;
- cloud accounts or model-provider keys as base requirements;
- importing AGPL/restricted donor code into the permissive trusted core without exact qualification/permission terms;
- copying donor datasets, PoCs, containers or rule libraries without artifact-level rights/provenance review;
- changing S1 implementation tasks to add verification/runtime behavior;
- making an LLM or external tool a canonical Sentrdel judge;
- making "verified exploit" the only way a legitimate static security finding can exist;
- turning missing telemetry, unsupported analysis or exhausted budgets into PASS.

---

## Plan update decision

### Keep unchanged now

- Constitution v1.0.1.
- Active S1 spec/plan/contracts/tasks.
- S1-S5 dependency order.
- Rust trusted-core and reconciler-only Finding authority.
- no-autonomous-exploitation boundary.
- local-first/vendor-neutral base product.

### Refine future planning

1. R6/S5 must start by specifying `VerificationRun`, `AuthorizationReceipt`, `ToolCapabilityManifest` and `RunCompleteness`.
2. Long-running R6 work must add `CheckpointManifest`/resume/finalization semantics before claiming resumability.
3. R7/S6 import contracts should carry producer/tool capability/completeness provenance where available.
4. R8/S9 should explicitly plan a runtime telemetry intake adapter with Sentry-compatible interoperability as a candidate, strict privacy/resource gates and no APM scope expansion.
5. R9 should add execution/run/resume/runtime-evidence conformance families.
6. R10 should include the local Security Workbench, Finding/regression lifecycle and SSG attack-surface explorer as projections over canonical records.
7. Rule/pack/plugin distribution should distinguish declarative content from executable capabilities and apply revocation/qualification accordingly.
8. Remediation automation should remain candidate-only until exact re-analysis and, when required, bounded verification proves the result.

## Immediate repository sequencing

At the time of this study, active implementation authority remains S1-T011 in PR #330. This planning supplement should not be used to bypass, widen or reorder that task.

The safe sequencing is:

1. complete S1 under the existing Spec 004 ledger;
2. qualify/canonicalize roadmap research independently without changing historical S1 authority;
3. when S5 planning begins, import the applicable VerificationRun/run-completeness/resume requirements into a new dedicated Spec Kit;
4. when S9 planning begins, import the runtime-evidence requirements into its dedicated Spec Kit;
5. when S10 planning begins, freeze lifecycle/workbench contracts against the mature canonical data model.

The roadmap becomes stronger by keeping these concerns explicit and dependency-ordered—not by implementing them prematurely.
