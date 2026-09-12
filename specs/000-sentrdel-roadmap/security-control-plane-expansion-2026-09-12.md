# Security Control Plane Expansion — 2026-09-12

**Status:** STRATEGIC_EXECUTION_BLUEPRINT / SPEC_KIT_READY / NO IMPLEMENTATION AUTHORITY  
**Planning base:** protected `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`  
**Active implementation authority remains:** `specs/004-security-invariant-regression/` and its canonical `tasks.md`  
**Related research:** `docs/third-party/source-candidate-assessment-2026-09-12.md`  
**Permission context:** `docs/third-party/founder-source-reuse-attestation-2026-09-12.md`  
**Strengthens, does not replace:** the canonical roadmap, 2026-09-02 semantic-security strategy, post-R3 execution blueprint, and 2026-09-08 source-driven expansion.

## 1. Executive decision

Sentrdel should become the **open security control plane for AI-built software** while preserving the existing product moat:

> Sentrdel owns security judgment, evidence provenance, coverage truth, invariant regression, bounded verification, and the lifecycle that connects source changes to deployed/runtime truth.

It should **not** become an autonomous pentesting bot, a bundle of 150 shell tools, a mandatory SaaS, or a vulnerability database clone.

The strongest architecture combines eight capabilities that are usually fragmented across separate products:

1. **pre-change and pre-merge judgment** — Evidence, Coverage, SSG, invariants, regression;
2. **external analyzer/import fabric** — mature scanners as untrusted producers;
3. **bounded verification** — explicit authorization, isolation, proof artifacts, point retest;
4. **runtime/operational evidence** — errors, logs, traces, health, deployments, runtime security events;
5. **finding/remediation lifecycle** — ownership, risk, fix candidates, retest, verified closure;
6. **agent/MCP/tool security** — static first, isolated dynamic testing later;
7. **open conformance and learning** — reproducible benchmarks, protected holdouts, candidate packs/rules that cannot self-promote;
8. **bounded runtime enforcement and response** — explicit prevention/response policy at controlled seams, separate from observation and disabled unless a future authorized profile proves the safety envelope.

This is how Sentrdel can be broader than a scanner **without becoming shallower than one**.

## 2. What “best” must mean

“Best” is not measured by scanner count, exploit count, model count, or dashboard size. A defensible Sentrdel release should win on measurable security qualities:

- high precision on supported invariant families;
- explicit and honest Coverage when analysis is missing;
- stable evidence/provenance chains;
- low false-block rate at enforced seams;
- deterministic local replay where deterministic claims are made;
- strong separation between FACT, INFERENCE, RUNTIME_OBSERVATION, VERIFIED, contradiction, and missing coverage;
- bounded, auditable verification rather than unbounded exploitation;
- proof-linked remediation and point retest;
- local-first operation with optional self-hosted/team control-plane surfaces;
- protocol/producer neutrality;
- low base-install dependency, memory, and latency cost;
- source-to-runtime identity continuity;
- supply-chain integrity for Sentrdel packs, engines, rules, fixtures, and releases;
- an open conformance suite that makes quality independently measurable.

A feature that increases breadth but weakens these properties is a regression, not progress.

## 3. Strategic differentiation after source triangulation

The 2026-09-12 study compared Sentrdel's plan with GlitchTip, HackerAI, HackAgent, HexStrike AI, Shannon, HackBot, and Strix, plus mature references such as OpenTelemetry, DefectDojo, Sigstore, and Falco.

### What those systems demonstrate well

- **GlitchTip:** operational telemetry, issue lifecycle, releases/environments, self-hosted observability, retention.
- **HackerAI:** durable agent runs, sandbox transports, recovery/cancellation, provider abstraction.
- **HackAgent:** agent-security generator/judge/target separation and evaluation datasets.
- **HexStrike:** broad tool catalog, orchestration, process/resource/caching patterns.
- **Shannon:** rules of engagement, resumable workspaces, source-to-live verification, incomplete-vs-clean semantics.
- **HackBot:** finding database/lifecycle, assessment diff, campaigns, reporting, operator UX.
- **Strix:** multi-agent execution, skills, coverage discipline, remediation/retest, immutable HTTP proof references.
- **DefectDojo:** vulnerability import/dedup/triage/risk/SLA workflow.
- **OpenTelemetry:** standard runtime traces/logs/metrics/resources and OTLP transport.
- **Sigstore/in-toto:** signed artifact identity and attestations.
- **Falco:** rich optional runtime event production from privileged Linux sources.

### What Sentrdel should uniquely own

None of those external systems should own or override:

- Evidence epistemic class;
- Coverage truth;
- stable semantic identity;
- SSG relationships;
- invariant definition/evaluation;
- trusted-base vs candidate security regression;
- reconciler-only Finding creation;
- policy/guard monotonicity;
- verification upgrade semantics;
- source→deployment→runtime correlation identity;
- protected conformance labels;
- whether an external producer is allowed to influence a canonical judgment.

## 4. Non-negotiable boundaries

These remain binding across every future sub-spec.

1. **Rust trusted judgment core.** External runtimes may produce evidence but do not own canonical judgment.
2. **No autonomous exploitation.** Dynamic security testing requires a bounded verification spec, explicit authorization, isolation, and target scope.
3. **No generic shell-command execution API.** Every external tool uses a typed adapter with explicit argv/environment/cwd/output/resource/network policy.
4. **No hidden clean state.** Crash, timeout, cap exhaustion, unavailable engine, unsupported artifact, denied permission, or incomplete run remains visible Coverage/diagnostic state.
5. **No mandatory cloud/model/provider.** Base Sentrdel stays useful offline/local-first.
6. **No LLM verdict authority.** Model output is hypothesis/inference unless independently proven through stronger evidence.
7. **No repository-controlled permission widening.** Target content cannot enable network, credentials, filesystem, tool, or mutation capability.
8. **No copied donor code without exact qualification.** Founder permission context does not replace exact ref/file/license/security review.
9. **No production mutation by default.** Bounded verification begins with synthetic/local/staging targets; stronger tiers require an explicit future spec.
10. **No mega-runtime.** Python, Node, Docker, browsers, eBPF, external scanners, and model providers remain optional surfaces rather than base-install requirements.

## 5. Gap register — additions after G1–G14

The 2026-09-08 study defined G1–G14. This study adds the following gaps.

### G15 — No end-to-end security lifecycle spine

The roadmap has strong analysis primitives but does not yet freeze a single lifecycle connecting:

`source revision → review run → Finding → fix candidate → verification → release/deployment → runtime evidence → incident/reopen → remediation → point retest → verified closure`.

Without this spine, later UI/runtime features risk inventing incompatible IDs and states.

**Required correction:** define stable cross-stage identities and lifecycle events before building a large control-plane UI.

### G16 — Runtime observability import is underspecified

R8 mentions runtime evidence, but not the concrete contract for errors, logs, traces, performance transactions, uptime/health, alerts, and deployment/release context.

**Required correction:** create an Operational Evidence Bridge using standards-first telemetry contracts. Prefer OTLP/resource semantic conventions and compatible envelope adapters over a proprietary transport.

### G17 — Deployment/release identity is not a first-class join key

Static revision identity alone cannot prove what code is running.

**Required correction:** future deployment identity must represent repository/revision, artifact/image digest, environment, service, deployment ID/time, optional attestation, and verification strength. Claimed deployment identity is not automatically trusted.

### G18 — External tool capability is not machine-readable enough

A future catalog of scanners/verifiers cannot safely rely on names and command templates.

**Required correction:** freeze a `ToolCapabilityManifest` contract before broad engine growth.

### G19 — Verification worker isolation is not a reusable plane

R6 requires safe verification but the roadmap does not yet define a reusable worker envelope across browser, HTTP, process, container, and agent-security tests.

**Required correction:** build one bounded Verification Worker contract with platform-specific implementations rather than bespoke sandbox logic per rule.

### G20 — Rules of Engagement are missing as a canonical authorization object

Network/dynamic verification requires more than a boolean “authorized”.

**Required correction:** machine-readable scope must include target identities, allowed hosts/IPs/URLs, methods/actions, accounts, mutation budget, rate/concurrency limits, network egress, exclusions, time window, data classification, and approver provenance.

### G21 — Proof artifacts lack a unified identity contract

A prose claim that a test succeeded is insufficient.

**Required correction:** verification results must reference immutable bounded artifacts: request/response exchanges, browser captures, process/test records, command adapter records, structured assertions, or other frozen proof items. Baseline and candidate proof should be distinguishable where relevant.

### G22 — Long-running security work lacks durable run semantics

Future dynamic/import/runtime workflows need checkpoint, cancellation, retry, resumption, timeout, budget, and incomplete-run semantics.

**Required correction:** define `RunManifest`, `RunCheckpoint`, and terminal/incomplete states independent of any Trigger.dev/Celery/cloud implementation.

### G23 — Agent security has static planning but no bounded dynamic profile

Gate C correctly prioritizes static Agent/MCP/Skill security. A later isolated verification profile is still needed for prompt injection, goal hijacking, tool misuse, and policy-boundary tests on owned/authorized agents.

**Required correction:** add an R6/R9 Agent Security Verification profile with Generator/Judge/Target separation and non-authoritative LLM judge semantics.

### G24 — Finding lifecycle after creation is incomplete

Reconciler-only Finding creation is correct, but mature operation needs lifecycle state without weakening that authority.

**Required correction:** define lifecycle transitions such as `OPEN`, `ACKNOWLEDGED`, `ACCEPTED_RISK`, `FIX_IN_PROGRESS`, `FIX_CANDIDATE`, `RETEST_REQUIRED`, `FIX_VERIFIED`, `REOPENED`, `STALE`, and bounded suppression/duplicate relationships, with actor/time/reason provenance.

### G25 — Remediation generation and fix verification are not separated enough

A generated patch is not a verified fix.

**Required correction:** `RemediationCandidate` remains untrusted/advisory. `FIX_VERIFIED` requires replay of the relevant invariant/proof/retest plan and execution evidence when the original claim required execution.

### G26 — Security Packs need a supply-chain and capability contract

Future packs/skills can become a new code/instruction supply-chain risk.

**Required correction:** packs require identity/version/digest/signature/author/license/dependencies/capabilities/authority ceiling/benchmark status/revocation/revalidation metadata. Pack instructions cannot widen host permissions.

### G27 — The operator control plane is not separated from the local trusted core

A future dashboard could accidentally make database/web/cloud services mandatory.

**Required correction:** keep the Rust protocol/CLI usable standalone. Any server/dashboard is an optional consumer of stable Sentrdel protocols/events.

### G28 — Portfolio/campaign semantics are absent

R10 project posture needs a bounded model for organizations, projects, repositories, services, environments, releases, and engagements without turning a “campaign” into permission to scan arbitrary targets.

**Required correction:** portfolio scope and dynamic target authorization remain separate objects.

### G29 — Sentrdel's own observability is under-specified

Security quality needs producer latency, cap exhaustion, coverage gaps, queue depth, worker health, retry/cancel behavior, and resource usage.

**Required correction:** add local structured run telemetry and optional OTLP export with strict content/redaction rules. Source/prompts/evidence content must never be exported as metrics by default.

### G30 — Future network verifiers need SSRF/rebinding controls

Any uptime/HTTP/browser verifier creates an SSRF surface.

**Required correction:** private/loopback/link-local/metadata destinations denied by default; redirect count/target revalidation/DNS rebinding policy/port allowlist/egress policy must be explicit. Internal targets require a stronger authorization tier.

### G31 — Untrusted source can prompt-inject security agents

An agent that reads repository text may interpret malicious source/comments/docs as instructions.

**Required correction:** repository content is data, never control-plane instruction. Tool capabilities originate only from trusted manifests/policy; model prompts must delimit untrusted content; suspicious instruction-like content can become evidence but never permission.

### G32 — Security telemetry retention/privacy needs explicit policy

Runtime evidence can contain secrets, PII, credentials, tokens, customer data, and request bodies.

**Required correction:** per-field classification, pre-persistence redaction, body capture defaults, retention tiers, deletion/export, tenant isolation, encryption boundary, and hot/cold retention policy must be frozen before broad telemetry ingestion.

### G33 — External-engine supply-chain integrity is incomplete

Version pins alone are insufficient for downloaded binaries/images/rules/templates/models.

**Required correction:** record digest/signature/SBOM/source/version/image identity, install/update provenance, vulnerability state, privileges, and requalification triggers. Prefer Sigstore/in-toto compatible attestations where useful.

### G34 — Cost and performance escalation policy is missing

Running every analyzer/verifier/model on every change is expensive and slow.

**Required correction:** progressive escalation with explicit budgets: cheap deterministic analysis first; bounded external evidence next; verification only when justified; runtime correlation asynchronously. Budget exhaustion becomes Coverage, never silent omission.

### G35 — Extensibility surfaces need versioned conformance

External producers, verifiers, runtime adapters, and packs should not each invent a custom integration.

**Required correction:** four stable extension classes with conformance suites:

- Evidence Producer / Import Adapter;
- Tool / Verification Adapter;
- Runtime Telemetry Adapter;
- Security Pack.

### G36 — Source-to-runtime temporal graph is not explicit

SSG currently models semantic relationships, but runtime and lifecycle data add time/release/environment dimensions.

**Required correction:** keep the semantic graph bounded and add temporal correlation edges/events rather than mutating static identity or building an unlimited universal graph.

### G37 — Benchmarks do not yet test false proof and operational failure

R9 needs tests for more than finding precision.

**Required correction:** benchmark false verification, proof-artifact completeness, unauthorized network attempts, sandbox boundary failures, run recovery, telemetry correlation, lifecycle correctness, redaction, and operator comprehension.

### G38 — Human approval surfaces need explicit semantics

“Ask user” is not a security contract.

**Required correction:** approvals must bind exact action/capability/target/scope/expiry/run identity, record approver identity/provenance where available, and never authorize a broader future action implicitly.

### G39 — Runtime enforcement and automated response authority is under-specified

Runtime telemetry and runtime prevention are different authority classes. A system that can block a request, kill a workload, quarantine an artifact, rotate a route, revoke a token, or change policy has materially more blast radius than an observer.

**Required correction:** define a separate runtime-response contract with explicit control points, action allowlists, target/environment scope, expiry, latency/SLO budget, fail-open/fail-closed semantics, rollback/disable behavior, actor/policy provenance, and immutable action records. Runtime observation alone MUST NOT authorize a response action. Production mutation remains outside this blueprint until a future explicit Spec Kit and constitutional review authorize a bounded profile.

### G40 — Optional control-plane trust, tenancy, and administration are under-specified

An optional web/API control plane becomes a high-value security target because it can expose Findings, proof artifacts, runtime telemetry, source metadata, authorizations, pack/tool state, and remediation actions. “Add auth later” is not an acceptable architecture.

**Required correction:** before multi-user/server implementation, freeze tenant/project boundaries, principal/session/API-token identity, RBAC/ABAC or equivalent authorization semantics, admin break-glass behavior, audit events, CSRF/session protections where applicable, key/secret handling, encryption boundaries, rate limits, export/delete controls, migration/backup/restore expectations, and denial tests for cross-tenant access. The server remains a projection/orchestration surface, never canonical Finding authority.

### G41 — Asset, service, API, and environment identity is not explicit enough

Project posture and runtime correlation need a stable inventory vocabulary, but inventory must not become permission to probe arbitrary external assets.

**Required correction:** define bounded `AssetIdentity` / service/API/environment relationships derived from repository metadata, deployments, explicit operator inventory, or qualified imports. Discovery provenance and confidence must be explicit; imported or inferred assets do not automatically enter dynamic target scope. Internet-wide/external attack-surface discovery is not authorized by this blueprint.

### G42 — Operational incidents and canonical Findings need separate semantics

A runtime attack signal, outage, exploit attempt, WAF/RASP block, suspicious process event, or telemetry anomaly is not necessarily the same object as a source-level Finding. Conflating them would either weaken Finding authority or make incident response unusably rigid.

**Required correction:** define a bounded operational-incident/event projection that can link to zero or more Findings, deployments, assets, proof artifacts, and runtime observations. Incident creation/triage may be operational, but it cannot create or rewrite a canonical Finding without normal reconciliation. Response actions must reference their incident/evidence/policy basis.

## 6. Target architecture

### Plane A — Trusted Judgment Core

**Implementation:** Rust-first, existing Sentrdel core.

Owns:

- canonical Evidence and Coverage;
- stable identities/provenance;
- SSG bounded graph logic;
- invariant definition/evaluation;
- regression comparison;
- reconciler-only Findings;
- policy/guard verdicts;
- lifecycle state validation;
- canonical event/audit serialization.

Must remain useful without network, cloud, model, browser, container, or external scanner.

### Plane B — Analyzer and Import Fabric

Contains:

- native deterministic Sentrdel packs;
- standards-first importers (SARIF and future bounded formats);
- generic external-producer adapters;
- optional artifact classifier signals;
- qualified external static engines.

All output is untrusted until schema validation, path/provenance checks, caps, producer identity verification where available, and reconciliation.

### Plane C — Bounded Verification Fabric

Contains optional isolated workers for approved verification profiles.

Every run requires:

- `VerificationAuthorization` / Rules of Engagement;
- exact `ToolCapabilityManifest` set;
- worker/isolation tier;
- network/credential/filesystem/resource policy;
- exact target/revision identity;
- run budget/time limit;
- proof-artifact retention policy;
- fail-closed incomplete states.

This plane may use containers, browsers, external engines, or model providers only when the applicable profile authorizes them.

### Plane D — Runtime and Operational Evidence Bridge

Imports bounded observations from:

- errors/exceptions;
- logs;
- traces/spans;
- service/deployment/resource metadata;
- health/uptime/heartbeat checks;
- optional runtime-security producers such as Falco;
- deployment/CI/release events.

Prefer OpenTelemetry/OTLP semantics and compatible existing SDK/envelope ecosystems rather than proprietary instrumentation.

Runtime observations do not overwrite static facts. They may corroborate, contradict, or create new Evidence for reconciliation.

### Plane E — Finding and Remediation Lifecycle

Provides canonical state transitions after reconciler-created Findings:

- ownership/assignment;
- acknowledgement;
- dedup/relationship;
- accepted risk with expiry/reason;
- remediation candidates;
- retest plans/results;
- `FIX_VERIFIED` evidence;
- reopen/stale/suppression state;
- SLA/age/notification projections.

The control plane may render/manage these states, but transition validity remains kernel-owned.

### Plane F — Agent/MCP/Tool Security

Static/local scope first:

- manifests/tool schemas;
- instructions/prompts as untrusted artifacts;
- capability declarations;
- install/build/dependency behavior;
- secret/network/filesystem/command scope;
- ASEL/SSG linkage;
- provider/model identity context.

Later dynamic agent-security verification runs only in Plane C under explicit authorization.

### Plane G — Open Conformance and Learning

Contains:

- public fixtures;
- protected holdouts;
- SentrdelBench profiles;
- producer/adapter conformance;
- pack qualification;
- candidate rule/research generation;
- source freshness/license/provenance tracking.

Candidate generation cannot modify the evaluator/holdout that judges it and cannot self-promote into trusted policy.

### Plane H — Optional Bounded Runtime Enforcement and Response

This plane is deliberately separate from Plane D observation. It MAY eventually contain narrowly authorized controls such as request blocking, quarantine, service protection, or other reversible response actions at known enforcement seams.

Every action requires:

- an authorized response profile and exact environment/asset/control-point scope;
- a kernel-validated policy/authorization decision;
- explicit action type and maximum blast radius;
- immutable policy, Evidence/incident, actor and action provenance;
- bounded latency/resource impact;
- rollback/disable behavior;
- visible failure/partial-enforcement state;
- conformance proving that telemetry/model/tool output cannot independently trigger a broader action.

Production mutation, destructive response, credential revocation, privileged host control, or autonomous incident response is **not authorized by this blueprint**. Those require a future explicit Spec Kit and constitutional review.

## 7. Contracts to freeze before broad implementation

The names below are planning names. A future Spec Kit may refine names, but must preserve the authority separation.

### 7.1 `ToolCapabilityManifest`

Minimum semantics:

- tool/adapter ID and semantic version;
- exact binary/image/package digest and provenance;
- invocation protocol and typed parameters;
- declared capabilities: network, browser, process, filesystem read/write, credentials, target mutation, container privilege, host privilege;
- allowed target classes;
- output schema/version;
- resource limits and expected upper bounds;
- determinism/replay class;
- epistemic output ceiling;
- sandbox requirement;
- known dangerous modes disabled by Sentrdel;
- qualification ID and expiry/revalidation conditions.

### 7.2 `VerificationAuthorization` / Rules of Engagement

Minimum semantics:

- authorization ID;
- target identity and environment;
- host/IP/URL/service allowlist;
- denied/private/metadata destinations;
- allowed methods/actions;
- explicit mutation allowance/budget;
- account/credential scope references without secret plaintext;
- rate/concurrency/time/resource budgets;
- network egress allowlist;
- data classification and body/artifact capture policy;
- start/expiry;
- approver/provenance where available;
- applicable verification profiles/tools;
- emergency cancellation semantics.

### 7.3 `VerificationRunManifest`

Minimum semantics:

- run ID;
- trusted revision/target/deployment identity;
- authorization ID/digest;
- adapter/tool manifests and exact versions;
- worker/isolation identity;
- deterministic input/config digests;
- start/end/terminal state;
- timeout/cancellation/incomplete reason;
- resource/network counters;
- checkpoint/resume lineage;
- proof artifact index;
- coverage/diagnostics.

### 7.4 `ProofArtifactReference`

Minimum semantics:

- stable artifact ID;
- run ID;
- artifact type;
- content digest;
- bounded size;
- timestamp/order;
- producer/tool identity;
- baseline/candidate/probe role where relevant;
- request/response exchange IDs or structured test/assertion IDs;
- redaction/classification state;
- retention/availability state;
- chain to Evidence IDs.

No raw secret value becomes an identity.

### 7.5 `DeploymentIdentity`

Minimum semantics:

- repository/project identity;
- revision/commit;
- build/artifact/container digest;
- service name/instance class;
- environment;
- deployment/release ID and timestamp;
- CI/build provenance;
- optional signature/attestation identity;
- verification level (`CLAIMED`, `ATTESTED`, `MISMATCH`, or future frozen equivalent).

### 7.6 `RuntimeObservationEnvelope`

Minimum semantics:

- observation ID;
- source/producer identity;
- service/environment/deployment identity;
- trace/span/log/error/event linkage where available;
- timestamp and bounded attributes;
- severity as producer metadata, not Finding authority;
- redaction/classification state;
- sampling/drop/truncation metadata;
- SSG/revision correlation result;
- epistemic class `RUNTIME_OBSERVATION` unless upgraded by a stronger contract.

### 7.7 `FindingLifecycleEvent`

Minimum semantics:

- Finding ID;
- previous/new state;
- actor/provenance;
- timestamp;
- reason/expiry for risk/suppression states;
- related remediation/retest/run IDs;
- immutable audit event identity.

Lifecycle transitions cannot create a Finding that did not originate from the reconciler.

### 7.8 `RemediationCandidate`

Minimum semantics:

- candidate ID;
- Finding/invariant linkage;
- proposed diff/config change;
- generator identity as context;
- evidence considered;
- expected invariant effect;
- review status;
- no verified status until retest evidence exists.

### 7.9 `RetestPlan` / `RetestResult`

Minimum semantics:

- exact Finding/invariant/proof linkage;
- minimal relevant analyzers/verifiers;
- original proof replay requirements;
- target revision/deployment identity;
- authorization requirements;
- expected deterministic assertions;
- terminal result and evidence IDs;
- coverage/incomplete reason.

### 7.10 `SecurityPackManifest`

Minimum semantics:

- pack ID/version/digest;
- publisher/provenance/signature where configured;
- license/source qualification;
- supported domains/languages/providers;
- declared dependencies/tools;
- declared capabilities;
- evidence types emitted;
- authority ceiling;
- required benchmarks/conformance version;
- revocation/revalidation state;
- no ambient network/credential/filesystem authority.

### 7.11 `AssetIdentity`

Minimum semantics:

- stable asset/service/API/environment ID within a declared project/tenant scope;
- asset kind and ownership/context;
- repository/revision/deployment relationships where known;
- canonical address/endpoint identifiers only when explicitly supplied or safely derived;
- discovery/import source and confidence;
- lifecycle state (`ACTIVE`, `RETIRED`, `UNRESOLVED`, or future frozen equivalent);
- explicit statement that inventory presence is **not** dynamic target authorization.

### 7.12 `RuntimeResponseAuthorization` / `EnforcementActionRecord`

Minimum semantics:

- response authorization/policy ID and digest;
- exact environment/asset/control-point scope;
- allowed action types and parameters;
- source policy plus Evidence/incident prerequisites;
- actor/service identity;
- start/expiry and emergency disable;
- maximum blast radius/rate/concurrency;
- latency/SLO and fail-open/fail-closed mode;
- rollback/recovery semantics;
- action result, partial/failure state and immutable audit identity.

Observation or model confidence cannot independently satisfy this authorization.

### 7.13 `ControlPlanePrincipal` / `ControlPlaneAuditEvent`

Minimum semantics:

- principal/session/API-client identity;
- tenant/project scope;
- role/grant/capability set with explicit expiry where applicable;
- authentication strength/context without storing credential plaintext;
- requested operation, target object and authorization outcome;
- admin/break-glass provenance;
- immutable audit event identity and timestamp;
- redaction/export/retention class.

### 7.14 `OperationalIncidentRecord`

Minimum semantics:

- incident ID and lifecycle state;
- asset/service/environment/deployment linkage;
- related runtime observation/Evidence/proof IDs;
- related canonical Finding IDs when reconciled;
- actor/owner/timestamps/severity as operational metadata;
- response-action IDs and policy basis;
- explicit separation from reconciler-only Finding creation.

## 8. Progressive security escalation model

Sentrdel should minimize risk, latency, and cost by escalating only when needed.

### Stage 0 — Identity and change scope

Establish revision/config/producer identity and changed semantic scope. Failure here is fail-visible and blocks stronger claims.

### Stage 1 — Native deterministic analysis

Run bounded local providers/invariants first. This is the lowest-authority-cost path and should answer the common regression question quickly.

### Stage 2 — External evidence import

When useful, run or consume qualified external producers through typed adapters. External severity/confidence remains producer metadata.

### Stage 3 — Cross-layer correlation

Reconcile Evidence/Coverage through stable IDs/SSG/invariants. Decide whether additional verification could materially upgrade a specific claim.

### Stage 4 — Bounded verification

Only with explicit profile + authorization + isolation. Produce immutable proof artifacts and execution evidence. Never widen scope because a model/tool requests it.

### Stage 5 — Deployment/runtime correlation

Asynchronously correlate real operational observations to the shipped revision/deployment and relevant Findings/invariants.

### Stage 6 — Optional bounded runtime response

Only at a separately authorized control point and response profile. A policy kernel validates the exact environment/asset/action scope. Observation, external severity, or model confidence alone cannot trigger a broader action. Production/destructive response remains unauthorized until a future explicit Spec Kit permits it.

### Stage 7 — Remediation and point retest

Generate or ingest fix candidates, then rerun the smallest sufficient regression/verification plan. Only execution-backed proof can create execution-backed verified closure.

## 9. Dependency-ordered roadmap refinement

This supplement does **not** renumber canonical S1–S11 and does not authorize a new slice by itself.

### Phase 1 — Finish the current regression moat

1. **S1 — Security Invariant Regression Core** — continue only through active Spec 004 tasks.
2. **S2 — Local Security Regression Developer Contract**.
3. **S3 — Forge/GitHub Delivery** using the same local judgment protocol.
4. **S4 — Open Regression Conformance** with public + protected cases.
5. **S5 — Bounded Verification of High-Value Invariants**.

No new source study may reorder this path.

### S5 mandatory internal planning packages

Before S5 executes any dynamic target action, its Spec Kit MUST include these bounded packages:

#### VF-1 — Verification safety foundation

Freeze:

- verification authorization / Rules of Engagement;
- worker/isolation tiers;
- default network-deny behavior;
- secret reference handling;
- resource/time/output limits;
- cancellation/termination;
- incomplete-vs-clean semantics.

**Exit:** deterministic tests prove denied scope cannot be widened by repository content, tool output, model output, redirects, or adapter parameters.

#### VF-2 — Tool capability registry

Freeze `ToolCapabilityManifest` and adapter conformance.

**Exit:** at least one harmless synthetic test adapter proves typed invocation, env scrub, cwd confinement, cap enforcement, version/digest binding, output parsing, and fail-visible unavailable/crash/timeout states.

#### VF-3 — Proof artifact contract

Freeze `ProofArtifactReference` and bounded artifact store/index semantics.

**Exit:** one selected S5 verification produces replayable structured proof linked to Evidence without persisting secrets/plaintext credentials.

#### VF-4 — Point retest

Freeze `RetestPlan/Result` and prove one fix candidate can be re-evaluated without granting broader scan scope.

**Exit:** `FIX_VERIFIED` requires the correct execution evidence; static/model review alone cannot produce it.

### Existing Gate A — Agentic Code Security Conformance

Retain the 2026-09-08 sequencing: research/conformance eligible after S4, non-blocking for S5, mandatory before broad agent-specific detector expansion.

Extend the benchmark later with:

- prompt-injection/source-instruction cases;
- tool-capability misuse cases;
- evaluator/generator separation;
- protected holdout leakage tests;
- false-proof and incomplete-run cases.

### Existing Gate B — Artifact Identity + Evasion-Resistant Routing

Retain before broad producer growth.

### S6 — External Evidence Import Protocol

S6 should freeze the generic `Evidence Producer / Import Adapter` class and standards-first formats.

**New exit requirements:**

- producer identity/version/config binding;
- bounded parser/resource limits;
- path normalization/confinement;
- truncation/drop diagnostics;
- authority ceiling;
- import of incomplete/failed producer state;
- dedup/reconciliation without trusting external severity;
- conformance fixtures for malformed/adversarial output.

### Existing Gate C — Agent/MCP/Skill Static Security Domain

Retain static/local-first. Add Security Pack manifest/signing/capability requirements before accepting third-party packs.

### R7/R8 Track — Operational Evidence Bridge

**Entry:** S6 import contracts canonical; DeploymentIdentity draft frozen; runtime privacy/redaction checklist complete.

**First bounded scope:**

- deployment/release event import;
- error/exception event import;
- structured log import;
- trace/span identity import;
- health/uptime observation import;
- explicit drop/sampling/unsupported diagnostics.

Prefer OTLP/OpenTelemetry resource semantics; add Sentry-compatible envelopes only as a qualified interoperability adapter where useful.

**Exit:** runtime observations from a synthetic deployed service correlate to exact revision/deployment/SSG identities without changing static facts or bypassing the reconciler.

### R8 Track — Bounded Runtime Enforcement and Response (later)

**Entry:** Operational Evidence Bridge canonical; stable `AssetIdentity`; explicit response authorization/action contracts; incident projection; protected conformance for false-positive/latency/failure behavior.

**First bounded scope:** synthetic or explicitly authorized staging control points only. Start with reversible, low-blast-radius actions and a disabled-by-default posture.

**Mandatory gates:**

- runtime observation and response authority remain separate;
- action types/targets/parameters are code/policy allowlisted;
- no repository/model/external-tool output can widen response scope;
- fail-open/fail-closed choice is explicit per control point and benchmarked;
- emergency disable/rollback is tested;
- partial enforcement/failure stays visible;
- performance/availability regression budget is enforced;
- every action emits an immutable `EnforcementActionRecord`;
- production/destructive/credential-revocation/privileged-host response is excluded until separately authorized.

**Exit:** a synthetic runtime attack can be observed, reconciled to an incident/finding context, blocked at an authorized staging control point, audited, rolled back/disabled, and replayed without any false autonomous expansion of scope.

### R6/R9 Track — Agent Security Verification Profile

**Entry:** S5 verification safety foundation canonical + Gate A conformance substrate.

**Scope:** owned/explicitly authorized local/synthetic agents only at first.

**Profiles:** prompt injection, goal hijacking, tool misuse, permission-boundary behavior, secret/data exfiltration canaries using synthetic secrets.

**Exit:** generator/judge/target identities separated; judge output cannot create VERIFIED; deterministic/synthetic assertions decide success where possible; network/tool permissions cannot be widened by target instructions.

### R10 Track — Finding Lifecycle and Remediation

**Entry:** S2/S3 developer contract mature; S5 retest semantics canonical.

**First scope:**

- immutable lifecycle events;
- ownership/acknowledgement;
- risk acceptance with expiry;
- fix candidate linkage;
- retest requested/completed;
- verified closure/reopen;
- duplicate/related relationships;
- SLA/age projections.

**Exit:** one Finding survives source change → fix candidate → point retest → verified closure → synthetic runtime contradiction → reopen, with complete audit/evidence lineage.

### R10 Track — Optional Self-Hosted Control Plane

**Entry:** local protocols/events stable; lifecycle/runtime contracts canonical.

The control plane MAY provide:

- project/repository/service/environment/API inventory;
- run history;
- Finding triage;
- runtime/incident correlation;
- proof artifact viewer;
- coverage dashboard;
- remediation/retest workflow;
- pack/tool/source qualification status;
- alerts/integrations;
- team/portfolio posture.

Before multi-user/server delivery, its Spec Kit MUST freeze principal/session/API-token identity, tenant/project isolation, authorization semantics, admin/break-glass behavior, immutable audit events, key/secret boundaries, cross-tenant denial tests, CSRF/session controls where applicable, rate limits, export/delete behavior, migration/backup/restore expectations, and incident response for control-plane compromise.

It MUST NOT be required for local CLI judgment, and web/database code MUST NOT become canonical Finding or verification authority.

### S7 — Semantic Provider Expansion

Choose providers by invariant leverage and benchmark impact, not framework popularity alone.

### S8 — Dependency/Build Action Guard

Extend to agent/skill/tool installation only at genuinely controlled seams. Pack/tool manifests provide the capability vocabulary; repository config cannot widen it.

### S9 — Runtime Correlation

Build on the Operational Evidence Bridge. Add temporal/deployment/asset correlation, bounded runtime-security producers, and operational-incident relationships. Any later active runtime enforcement follows the separate response-authorization gates above. Do not embed privileged eBPF/kernel collection or active blocking into the base install.

### S10 — Mature SSG Project Posture

Compose static regression, external evidence, verification, runtime observations, Finding lifecycle, supply-chain provenance, deployment identity, and agent/tool authority paths into project posture.

### S11 — Open Intelligence / Controlled Learning

Use production/benchmark signals only through privacy/provenance/consent boundaries. Candidate rules/packs require independent conformance and cannot self-promote.

## 10. First implementation-ready future Spec Kits

The following are the recommended next bounded Spec Kits **when their dependencies become canonical**. Each still needs the normal constitution → specify → clarify → plan/research/design → checklist → tasks → analyze → implement → converge lifecycle.

### Spec Kit candidate A — Verification Safety Foundation

**Owner roadmap area:** R6 / S5  
**Dependencies:** S1–S4 canonical; S5 planning entry authorized.  
**Primary outputs:** authorization, capability manifest, worker contract, proof artifacts, retest semantics.  
**No-go:** real third-party targets, production mutation, broad scanner catalog.

### Spec Kit candidate B — Generic External Evidence Import

**Owner:** S6  
**Dependencies:** S4; Gate B routing where artifact identity applies.  
**Primary outputs:** generic producer envelope, SARIF-first importer hardening, conformance/adversarial parser suite.  
**No-go:** external severity → Finding shortcut.

### Spec Kit candidate C — Static Agent/MCP/Skill Security

**Owner:** Gate C / R7/R9  
**Dependencies:** S6 + Gate A/B applicable substrate.  
**Primary outputs:** artifact/capability model, pack manifest, static agent threat evidence, ASEL/SSG correlation.  
**No-go:** autonomous jailbreak/exploitation.

### Spec Kit candidate D — Operational Evidence Bridge

**Owner:** R8/S9 precursor  
**Dependencies:** S6 + deployment identity design + privacy checklist.  
**Primary outputs:** runtime envelope, OTLP/resource mapping, deployment correlation, redaction/retention/drop semantics.  
**No-go:** runtime event automatically equals Finding.

### Spec Kit candidate E — Finding Lifecycle + Point Retest

**Owner:** R10  
**Dependencies:** S2/S3 contract + S5 retest semantics.  
**Primary outputs:** state machine, audit events, remediation candidates, retest linkage, SLA/risk projections.  
**No-go:** UI/database service becomes Finding authority.

### Spec Kit candidate F — Agent Security Verification

**Owner:** R6/R9  
**Dependencies:** Verification Safety Foundation + Gate A.  
**Primary outputs:** synthetic target adapters, generator/judge/target separation, deterministic canaries, proof artifacts.  
**No-go:** public-target red teaming.

### Spec Kit candidate G — Optional Self-Hosted Control Plane

**Owner:** R10  
**Dependencies:** stable local API/event/lifecycle/runtime contracts + `AssetIdentity` + principal/tenant/audit design.
**Primary outputs:** optional server/API/UI projection; local-first sync/import; asset/service/API inventory; principal/session/API-token identity; tenant isolation; authorization; immutable audit; backup/restore/migration and admin-security contracts.
**No-go:** moving kernel judgment into web/database code or using inventory presence as target authorization.

### Spec Kit candidate H — Bounded Runtime Enforcement and Response

**Owner:** R8
**Dependencies:** Operational Evidence Bridge + asset/deployment identity + incident projection + protected enforcement conformance.
**Primary outputs:** response authorization, bounded reversible staging control point, immutable action record, performance/failure/rollback gates.
**No-go:** autonomous production mutation, credential revocation, destructive response, ambient host privilege, or runtime telemetry directly triggering a canonical response action.

## 11. External engine strategy

Sentrdel should become broad through **qualified composition**, not by rewriting mature tools.

### Raw detection usually reuse/import

Prefer mature engines for:

- SAST;
- SCA/SBOM;
- secret scanning;
- IaC/cloud posture;
- container/image scanning;
- DAST/fuzzing where authorized;
- runtime event collection;
- observability telemetry;
- vulnerability/advisory intelligence.

### Sentrdel-owned value around those engines

Own:

- selection/routing justification;
- exact producer identity/config;
- parser/cap safety;
- Evidence/Coverage mapping;
- stable semantic correlation;
- regression judgment;
- proof state;
- policy/guard decisions;
- lifecycle/retest;
- conformance.

## 12. Tool Capability Registry design rules

A tool registry is **not** an allowlist of command strings.

Each tool adapter MUST:

- have code-owned executable identity resolution;
- use explicit argv, never `sh -c`/string-built shell;
- scrub inherited environment and pass an allowlist;
- confine cwd and file inputs;
- reject traversal/symlink escape where applicable;
- enforce output/time/memory/process limits;
- declare whether it can write/mutate target state;
- declare network requirements and enforce policy externally where possible;
- declare credential classes without exposing secret values;
- validate structured output before Evidence conversion;
- emit unavailable/crash/timeout/truncation as visible diagnostics/Coverage;
- pin/attest version/digest;
- expose no generic “extra args” escape hatch from untrusted repository config;
- be individually revocable/requalifiable.

## 13. Verification worker isolation tiers

A future spec should choose exact platform mechanisms, but the trust model should distinguish at least:

### Tier 0 — No execution

Static/import-only. Default base behavior.

### Tier 1 — Synthetic in-process deterministic verification

No untrusted target execution; deterministic Sentrdel-owned fixtures/assertions.

### Tier 2 — Local isolated test process

Explicit executable/argv, scrubbed environment, restricted cwd/filesystem, no network by default, hard resource limits.

### Tier 3 — Container/VM/browser test environment

For explicitly authorized local/staging targets. Network allowlist and target policy required. Credentials are scoped references with redaction and expiry.

### Higher tiers

Production, privileged host/kernel, internal-network, or destructive/mutating verification is **not authorized by this blueprint**. Any such tier requires a future explicit constitutional/spec review.

## 14. Runtime evidence design

### Standards-first ingestion

Prefer:

- OpenTelemetry resources/traces/logs/metrics/events;
- deployment/release metadata from CI/CD;
- qualified Sentry-compatible envelopes where useful;
- qualified runtime-security event producers.

### Correlation keys

Use bounded combinations of:

- repository/revision;
- build/artifact/container digest;
- service/environment;
- deployment/release ID;
- trace/span/request IDs;
- stable route/resource/invariant/SSG IDs when derivable;
- source map/debug-symbol identity where applicable.

Correlation confidence must remain explicit. A guessed mapping cannot silently become exact stable identity.

### Privacy defaults

- no request/response bodies by default;
- no secret plaintext persistence;
- redact before persistence, not only at display;
- cap attribute count/key/value/body sizes;
- bounded sampling/drop metadata;
- retention policy per data class;
- tenant/project isolation;
- explicit export/delete controls in any future server.

### Asset and incident separation

Runtime telemetry may introduce an asset/service/API identity or operational incident candidate, but neither object grants network/verification scope and neither object is automatically a canonical Finding. Correlation quality (`EXACT`, `ATTESTED`, `AMBIGUOUS`, `UNMAPPED`, or future frozen equivalent) must remain visible.

### Runtime enforcement boundary

Observation and response are separate contracts. A future response action requires an explicit `RuntimeResponseAuthorization`, a supported control point, a bounded action type, and an immutable `EnforcementActionRecord`. Model output, scanner severity, telemetry severity, or incident priority cannot independently authorize the action. Default base behavior is observation-only.

## 15. Finding lifecycle state machine constraints

The exact enum belongs in a future spec. The minimum semantics are:

```text
RECONCILED_OPEN
  -> ACKNOWLEDGED
  -> FIX_IN_PROGRESS
  -> FIX_CANDIDATE
  -> RETEST_REQUIRED
  -> FIX_VERIFIED

RECONCILED_OPEN / ACKNOWLEDGED
  -> ACCEPTED_RISK (reason + owner + expiry)

FIX_VERIFIED
  -> REOPENED (new regression or contradicting runtime/verification evidence)

Any active state
  -> STALE (identity/source no longer valid or required revalidation expired)
```

Duplicate/suppression relationships are metadata/lifecycle decisions, not deletion of underlying Evidence.

Risk acceptance must expire or be explicitly permanent under future policy; it never rewrites the Finding as false.

## 16. Remediation model

Remediation assistance may come from deterministic transforms, humans, or models, but all generated patches/config changes are candidates.

A remediation workflow should preserve:

- exact original Finding/invariant/evidence;
- generated/human author identity;
- proposed changes;
- expected security effect;
- regression risk/affected graph context;
- review approval;
- exact retest plan;
- post-fix Evidence/Coverage;
- verification proof where required.

The strongest product loop is:

> **find → explain → propose → review → apply → point-retest → verify → monitor → reopen if reality contradicts**

## 17. Agent/MCP security model

### Static layer

Inspect:

- tool schemas/manifests;
- instruction/skill files;
- install/build hooks;
- package/dependency declarations;
- filesystem/network/credential/command capabilities;
- MCP transport and auth configuration;
- remote-resource references;
- action provenance and ASEL events.

### Dynamic layer — later and isolated

Test owned/authorized agents using synthetic secrets/data and deterministic canaries for:

- instruction hierarchy violations;
- prompt injection handling;
- tool permission boundary violations;
- goal hijacking;
- unauthorized data movement;
- unauthorized network/command attempts.

An LLM judge may assist classification but cannot be the sole basis for VERIFIED.

## 18. Security Pack model

Packs should be composable domain knowledge, not arbitrary executable plugins.

Preferred order:

1. declarative rules/contracts/data;
2. Rust-native deterministic provider when required;
3. qualified external engine adapter;
4. model-assisted candidate analysis only as inference.

Every pack should publish:

- support matrix;
- Evidence/Coverage types;
- required privileges/dependencies;
- benchmark precision/recall/FPR;
- compatibility/conformance version;
- provenance/license;
- maintenance/freshness;
- revocation/revalidation status.

## 19. UX architecture

### Developer surface

Keep fast/local:

- CLI review;
- machine-readable JSON;
- IDE/MCP contract;
- forge/PR annotations;
- clear new/fixed/persistent/coverage-lost regression views;
- “why” evidence chain;
- optional point verification/retest.

### Security/operator surface

Optional control plane:

- inventory/posture;
- Finding triage/lifecycle;
- run/verification history;
- proof artifacts;
- coverage trends;
- runtime/deployment correlation;
- remediation/retest queue;
- pack/tool/source qualification state;
- alerts/integrations;
- portfolio/team views.

### Trust UX

Always display whether a statement is:

- observed;
- deterministically inferred;
- model/heuristic hypothesis;
- runtime observed;
- execution verified;
- contradicted;
- unsupported due to missing coverage.

## 20. Benchmark and release gates

Future applicable releases should measure at least:

### Judgment quality

- precision/recall by supported invariant family;
- high-severity evidence-location accuracy;
- false-block rate;
- coverage-loss detection rate;
- duplicate/reconciliation correctness.

### Verification safety

- unauthorized target/network action rate: **0** in conformance;
- repository/model/tool attempt to widen capability: **0 successful**;
- false VERIFIED rate: target **0** on protected adversarial suite;
- proof-artifact completeness;
- timeout/cancel/process-tree containment;
- incomplete-vs-clean correctness;
- point-retest fidelity.

### Runtime correlation

- deployment→revision mapping correctness;
- runtime observation→semantic identity precision;
- asset/service/API identity correlation precision and explicit unresolved rate;
- explicit ambiguous/unmapped rate;
- dropped/sampled/truncated truthfulness;
- PII/secret redaction failures: target **0** on protected canaries.

### Runtime enforcement and control-plane safety

- unauthorized response actions: target **0** on protected conformance;
- cross-tenant/project authorization escapes: target **0**;
- response false-block rate by supported profile/control point;
- response latency and application SLO impact;
- emergency-disable/rollback success;
- fail-open/fail-closed behavior matches frozen policy under dependency outage;
- every response action has complete immutable authorization/evidence/audit lineage.

### Durability/recovery

- checkpoint/resume idempotence;
- cancellation latency;
- retry duplicate-artifact rate;
- crash recovery correctness;
- stale-run detection.

### Performance

- warm local review latency;
- guard verdict latency;
- memory;
- base install size/dependency closure;
- per-stage CPU/time/network budget;
- optional verifier cost;
- telemetry ingest overhead where applicable.

### Supply chain

- unsigned/unpinned external engine admission rate: **0** where policy requires identity;
- pack/tool/source qualification expiry detection;
- vulnerable engine/dependency requalification behavior;
- attestation verification correctness.

### Operator quality

- time to understand a high-severity regression;
- time to identify missing coverage;
- remediation/retest completion rate;
- stale accepted-risk rate;
- user ability to distinguish hypothesis from verified result in usability tests.

## 21. Adversarial conformance cases required before scale

At minimum, future suites should cover:

- external tool exits 0 but emits malformed/truncated output;
- external tool crashes after partial evidence;
- repository contains text instructing the agent to ignore policy or exfiltrate secrets;
- symlink/path traversal from target artifacts;
- redirect/DNS rebinding toward private or cloud-metadata addresses;
- verifier asks for undeclared tool/network/credential capability;
- model claims success without proof artifact;
- repeated/deduplicated evidence attempts to bypass count caps;
- runtime telemetry claims wrong release/environment;
- deployment claim conflicts with signed artifact identity;
- accepted-risk item expires;
- verified fix regresses in a later revision;
- runtime contradiction reopens a previously verified fix;
- a high-severity runtime event attempts to trigger an undeclared response action;
- a response policy tries to cross tenant/environment/asset boundaries;
- fail-open/fail-closed behavior is exercised under control-plane or telemetry outage;
- an inventory-only external asset is incorrectly proposed as an authorized verification target;
- cross-tenant control-plane API/object references are denied and audited;
- sampling/drop/cap exhaustion is represented as missing coverage, not clean;
- malicious pack/rule tries to widen permissions;
- signed but unqualified engine proves that integrity is not equivalent to trust;
- resume/retry attempts to duplicate or reorder proof artifacts.

## 22. Data/storage strategy

The trusted contracts must be storage-agnostic.

### Base local mode

Prefer simple local persistence appropriate to existing Sentrdel architecture, with deterministic serialization and export. No database server should become mandatory merely for lifecycle features.

### Optional control-plane mode

A later server may use relational/object storage/search/cold storage as needed, but must preserve canonical IDs/events and tenant isolation.

### Artifact retention

Separate:

- canonical small structured Evidence/lifecycle events;
- bounded proof artifacts;
- large optional runtime/log/trace payloads;
- cold/expired/deleted objects.

A missing expired artifact must remain visible as retention state; historical VERIFIED claims must retain enough immutable metadata/digest/provenance to explain what proof existed.

## 23. Supply-chain hardening roadmap

Future pack/tool/worker releases should support:

- immutable digests;
- SBOMs;
- signed release artifacts/images;
- provenance attestations;
- exact dependency closure;
- vulnerability audit;
- controlled update channels;
- revocation;
- reproducibility evidence where practical.

Sigstore/Cosign/in-toto are preferred references; Sentrdel should not invent a proprietary signing ecosystem unless requirements prove necessary.

## 24. Source-specific adoption backlog

No item below authorizes implementation.

### GlitchTip

Research/qualify only if Sentrdel needs code rather than protocol interoperability:

- release/environment event identity;
- issue/lifecycle UX;
- trace/log correlation;
- retention/cold-storage patterns;
- uptime SSRF defenses.

Prefer standards/protocol compatibility over backend fork/reuse.

### HackerAI

Before any source copy:

- store source-specific permission/relicense evidence for the intended files/use;
- isolate durable-run/sandbox transport patterns from cloud/vendor stack;
- benchmark against a smaller Sentrdel-owned Rust protocol implementation.

### HackAgent

Prioritize methodology/fixtures:

- generator/judge/target separation;
- framework adapters;
- agent-security benchmark taxonomy.

External-engine integration only after verification isolation exists.

### HexStrike AI

Do not import the broad autonomous attack engine. Study/qualify selectively for:

- tool metadata/catalog concepts;
- process/resource/caching/error-recovery patterns;
- progress visualization.

### Shannon

Do not copy AGPL implementation into permissive core without exact separate permission. Study/qualify:

- rules-of-engagement modeling;
- resumable workspace/run semantics;
- incomplete-vs-clean behavior;
- verification/retest workflow.

### HackBot

Study/qualify selectively for:

- vulnerability lifecycle UX;
- diff/trend reports;
- campaigns/inventory;
- plugin/tool UX;
- report generation.

Do not inherit autonomous exploit/zero-day generation authority.

### Strix

High-priority selective research/qualification:

- proof artifact links such as HTTP exchange IDs;
- reporting/coverage state;
- skill metadata/loading boundaries;
- remediation→retest workflow;
- sandbox/run artifact handling.

Do not inherit autonomous exploit authority.

## 25. Defensibility filter for every future feature

Approve a major feature only if it passes most of these questions:

1. Does it improve invariant judgment, Evidence provenance, Coverage truth, verification, runtime correlation, lifecycle/retest, or conformance?
2. Can a mature external component provide the raw capability behind a safer boundary?
3. Is the new privilege/network/credential/process/model/native surface explicit and justified?
4. Can missing/failing capability remain visible rather than clean?
5. Can the feature run without forcing the entire base installation to adopt its runtime/dependencies?
6. Is its authority ceiling structurally enforced?
7. Can it be benchmarked with public fixtures + protected adversarial cases?
8. Does it preserve local-first operation?
9. Is source/license/provenance/update state auditable?
10. Does it make the source→verification→runtime→remediation story stronger?

If not, defer it.

## 26. Explicit non-goals

This blueprint does **not** authorize or propose:

- autonomous exploitation of third-party targets;
- internet-wide scanning;
- password cracking/credential attacks as a base capability;
- production mutation by default;
- an unbounded browser/shell/Python agent with ambient credentials;
- mandatory LLMs;
- mandatory Docker/Kubernetes/browser/eBPF in the base install;
- cloning GlitchTip, DefectDojo, Shannon, Strix, HexStrike, HackBot, HackerAI, or HackAgent wholesale;
- replacing best-of-breed scanners merely to increase Sentrdel code size;
- a universal CPG;
- external severity/confidence as Finding authority;
- a vulnerability “clean score” that hides missing Coverage;
- source code/comments/docs as trusted agent instructions;
- arbitrary remote MCP servers in a trusted default path;
- copying restricted/copyleft donor code into the permissive core without exact compatible permission/qualification.

## 27. Immediate repository actions

These actions are safe while S1 implementation continues:

1. keep this blueprint and its source assessment canonical as roadmap/research only;
2. fix roadmap navigation/current-boundary wording so it no longer claims post-R3 work is unauthorized while S1 is active;
3. preserve active Spec 004 task order unchanged;
4. finish S1 canonically before opening implementation for S2+;
5. when S5 planning begins, use VF-1 through VF-4 as mandatory design inputs;
6. when S6 planning begins, include the generic producer/import conformance requirements;
7. create no dynamic agent/pentest implementation from this research before the relevant verification Spec Kit authorizes it;
8. perform exact source qualification only when a concrete future implementation chooses specific donor files/artifacts.

## 28. Completion definition for the long-term platform

Sentrdel reaches the intended security-control-plane category when a single demonstrable workflow can prove all of the following without authority ambiguity:

1. an AI-authored change weakens a defined security invariant;
2. Sentrdel identifies the exact semantic regression and evidence chain;
3. missing analysis is explicit rather than clean;
4. a developer sees the same canonical judgment locally and in forge/IDE surfaces;
5. a bounded verification profile can prove or disprove a selected high-value claim under explicit authorization;
6. proof artifacts are immutable, attributable, bounded, and linked to the Finding;
7. a remediation candidate is proposed/reviewed without being mislabeled as a verified fix;
8. point retest proves the relevant invariant/proof after the fix;
9. deployment identity links the verified revision/artifact to a runtime environment;
10. runtime errors/logs/traces/security observations correlate back to stable identities without rewriting static facts;
11. a contradicting runtime observation can reopen the lifecycle transparently;
12. an operator can explain every verdict, proof state, coverage gap, source, and lifecycle transition;
13. external tools/packs can be added through conformance-tested contracts without gaining canonical judgment authority;
14. the base tool remains local-first, useful, and lightweight when all optional external/control-plane features are absent.

That is the target: **not the most autonomous security tool, but the most trustworthy open system for knowing what changed, what it means, what is missing, what was actually proven, what shipped, what happened in reality, and whether the fix truly held.**