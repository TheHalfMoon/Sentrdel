# Sentrdel Spec-of-Specs Roadmap

**Status:** ACTIVE  
**Created:** 2026-08-24  
**Last major review:** 2026-09-12  
**Improvement Plan of Record:** `improvement-plan-2026-08-26.md`  
**Strategic Amendment of Record:** `strategic-amendment-2026-09-02-semantic-security-graph.md`  
**Post-R3 Execution Blueprint of Record:** `post-r3-execution-blueprint-2026-09-02.md`  
**Source-Driven Research Supplement:** `source-driven-security-expansion-2026-09-08.md`  
**Security Control Plane Expansion:** `security-control-plane-expansion-2026-09-12.md`  
**Roadmap Navigation:** `README.md`  
**Purpose:** Decompose the A-to-Z Sentrdel mission into bounded Spec Kit slices. Each roadmap item MUST receive its own `spec.md`, clarification closeout, plan/research/design artifacts, checklist, tasks, analysis, and implementation lifecycle.

## Product North Star

Sentrdel becomes the essential open-source security system developers use whenever they code—especially with AI coding agents. It protects the whole project from authoring to production while remaining Rust-first, local-first, vendor-neutral, evidence-first, and explicit about what is enforced versus advisory.

## Category

**Sentrdel is the open-source security-invariant regression and evidence judgment engine for AI-built software, operating as the semantic security evidence and control plane for the whole software project.**

It MUST NOT compete primarily on rule count, generic "AI code scanning," scanner aggregation, autonomous pentesting, or one IDE/agent integration. Those capabilities are increasingly available from large security and coding-agent vendors. Sentrdel's durable differentiation is independent adjudication, coverage truth, ASEL agent evidence, security invariants, the Sentrdel Semantic Security Graph, trusted-base/candidate security-property regression, provider-aware project posture, safe verification, proof artifacts, source→deployment→runtime identity, remediation/retest, context/instruction provenance, open conformance contracts, and continuously evaluated security judgment.

The defining developer question is:

> **What security property did this change weaken, what evidence proves it, what analysis is missing, what stronger claim—if any—was separately verified, what actually shipped, what happened in runtime, and did the remediation truly hold?**

## Architectural thesis

Sentrdel is **not** a new universal CPG, **not** an autonomous exploitation agent, and **not** a wrapper that treats scanner output as truth. The trusted Rust core owns:

1. canonical Agent Security Event and Evidence schemas;
2. integrity-linked local storage and trusted-head semantics;
3. the bounded **Sentrdel Semantic Security Graph (SSG)** with provenance, explicit coverage and authority separation;
4. monotonic policy/guard verdicts at controllable seams;
5. reconciliation from evidence into findings;
6. provider-aware security posture;
7. security invariants and business-logic substrate;
8. trusted-base versus candidate security-invariant regression;
9. bounded verification and fix validation;
10. developer-facing security judgment and change-relative explanation;
11. authority rules separating untrusted context from authorized instruction;
12. immutable evaluation/conformance contracts used to measure precision, misses, coverage, false blocks and latency;
13. promotion boundaries that keep future learning/research automation candidate-only until independently qualified;
14. machine-readable verification authorization, tool capability and proof-artifact semantics;
15. source/revision/build/deployment/runtime correlation identity;
16. Finding lifecycle transition validity and point-retest semantics;
17. pack/tool/source qualification state and authority ceilings.

External engines provide evidence through strict, versioned boundaries. Graph context, model output, runtime telemetry, and external-engine severity/confidence MUST NOT independently upgrade epistemic authority.

## Cross-cutting 2026-08-26 amendment

The repository adopts `improvement-plan-2026-08-26.md` as the human-readable Plan of Record for the 2026-08-26 major evaluation.

Binding direction:

- finish the current R1 trusted foundation before broad scope changes;
- establish SentrdelBench Core before detector proliferation;
- prove one excellent end-to-end `sentrdel review` steel thread before optimizing for rule count;
- move repository self-security and MCP credential-isolation controls forward;
- make context/instruction provenance and scoped security memory explicit authority-bounded concepts;
- add temporal finding state and producer calibration as measured context, not new epistemic authority;
- treat community Rules/Security Packs as supply-chain objects;
- add a later continuous Security Research/Learning Plane whose candidates cannot self-promote or modify the trusted judgment/evaluation authority used to judge them.

## Cross-cutting 2026-09-02 semantic-security amendment

The repository adopts `strategic-amendment-2026-09-02-semantic-security-graph.md` as the strategic refinement produced by the AppSec/platform evaluation and `post-r3-execution-blueprint-2026-09-02.md` as the dependency-ordered roadmap decomposition for that strategy after canonical R3 closeout.

Binding direction:

- R3 is canonically complete; its task sequence remains the historical authority for that completed slice and no successor inherits implementation authority from R3 closeout;
- name the bounded canonical graph direction the **Sentrdel Semantic Security Graph (SSG)** without creating a universal CPG or second graph runtime;
- make **Security Invariant Regression** over a trusted base the first post-R3 product wedge, not generic diff-aware scanning;
- treat **coverage regression** as a first-class security outcome so loss of visibility cannot become an implicit clean result;
- prioritize R5 invariant-regression + forge integration before broad provider-pack proliferation;
- define trusted-base/candidate states only through separately frozen contracts;
- strengthen R9 into an open Evidence/Coverage/Invariant/Regression/Importer/Verification conformance and benchmark ecosystem;
- define a later External Evidence Import Protocol so mature scanners/SBOM/SARIF/advisory engines contribute untrusted Evidence rather than being rebuilt or treated as judges;
- frame R6 as an Evidence Upgrade + Fix Validation plane where `FIX_VERIFIED` requires the right execution evidence;
- use R7/R11 for qualified multi-source security intelligence and dependency/action-control work rather than making a proprietary feed mandatory;
- keep the core open, local-first, inspectable and useful without account creation, source upload, provider credentials or a proprietary API;
- if a mature external engine can provide the raw capability and rebuilding it does not materially strengthen invariant judgment, coverage truth, verification or conformance, prefer import/reuse.

## Cross-cutting 2026-09-08 source-driven refinement

The repository preserves `source-driven-security-expansion-2026-09-08.md` and `docs/third-party/source-candidate-assessment-2026-09-08.md` as research/planning records. The research confirms the invariant-regression-first strategy and adds future planning gates for artifact identity/evasion-resistant routing, agent/MCP/skill static security, and agent-generated-code conformance.

Binding boundaries:

- the source study does not qualify donor source, data, models, binaries, containers, dependencies, network services, credentials, target execution, or dynamic verification;
- probabilistic classification and external producer confidence remain bounded evidence/inference and cannot become Sentrdel FACT/VERIFIED authority by score alone;
- S1-S5 remain the first product path; source-driven gates do not reorder or delay bounded verification;
- every future adoption still requires exact source/dependency/data/runtime qualification under the Constitution and repository governance.

## Cross-cutting 2026-09-12 security-control-plane refinement

The repository adopts `security-control-plane-expansion-2026-09-12.md`, `docs/third-party/source-candidate-assessment-2026-09-12.md`, and `docs/third-party/founder-source-reuse-attestation-2026-09-12.md` as the planning/provenance records for the GlitchTip, HackerAI, HackAgent, HexStrike AI, Shannon, HackBot, and Strix study.

The source triangulation strengthens the long-term product envelope without changing the active S1 task order or authorizing dynamic exploitation.

Binding direction:

- preserve **Sentrdel judgment as the kernel** and make runtime/control-plane services optional projections over stable local protocols;
- define a source→Finding→fix→verification→deployment→runtime→reopen→retest lifecycle with stable identity and immutable audit events;
- make S5 freeze machine-readable Rules of Engagement, typed Tool Capability Manifests, reusable verification isolation, immutable proof-artifact references, and point-retest semantics before meaningful dynamic verification;
- prohibit generic shell-string execution, ambient tool permission, repository-controlled scope widening, and autonomous exploitation;
- make S6 generic producer/import conformance the foundation for broad external evidence and later runtime adapters;
- prefer OpenTelemetry/OTLP/resource semantics for a future Operational Evidence Bridge; runtime events remain observations until reconciled and cannot rewrite static facts;
- add Finding lifecycle/remediation/retest after the developer/verification contracts are mature while keeping Finding creation reconciler-only;
- treat third-party Security Packs/tools/rules as signed/versioned/capability-declared supply-chain objects with explicit authority ceilings and requalification;
- allow later bounded agent-security verification only for owned/explicitly authorized isolated targets after S5 safety and R9/Gate-A conformance exist;
- keep runtime observation separate from active response authority; any future blocking/quarantine/response capability requires explicit response authorization, supported control points, immutable action records, rollback/disable semantics, and protected false-block/latency conformance before production consideration;
- make asset/service/API inventory identities explicit while keeping inventory presence structurally incapable of authorizing verification or scanning;
- require any optional multi-user control plane to freeze principal/session/API-token identity, tenant/project isolation, authorization, immutable audit and admin/break-glass boundaries before it can manage sensitive evidence/runtime/remediation state;
- preserve local-first operation: no cloud, model provider, Docker, browser, Python, Node, eBPF or web control plane becomes a base requirement;
- founder source-copy permission context does not replace exact source/file/license/security qualification. Restricted/copyleft public terms remain controlling unless a sufficiently specific separate permission/relicense record is stored.

## Roadmap

| ID | Slice | Goal | Depends on | Status | Sub-spec |
|---|---|---|---|---|---|
| R1 | Evidence + Guard Foundation | Ship a useful Rust CLI for diff review, canonical evidence, stack detection, bounded stdio MCP guard, git guard seams, coverage gaps, high-signal baseline checks, and the minimum immutable evaluation foundation required to measure quality before detector breadth | — | complete | `specs/001-v0-1-evidence-guard-foundation/` |
| R2 | **Supabase P0 Static/Posture Pack** | Offline deterministic Supabase security posture: RLS/policies, grants/functions, SECURITY DEFINER/search_path, exposed schemas/sensitive columns, service-role/client boundaries, Storage and Auth/config signals; separate optional live posture later | R1 | complete | `specs/002-supabase-static-posture/` |
| R3 | Business-Logic Substrate + Invariants | Build the first application-semantic SSG slice: route × actor/auth × guard × value/data operation × provider authority × invariant analysis, including tenant isolation/authz; augment Supabase and generalize only through bounded adapters | R1, R2 | complete | `specs/003-business-logic-invariants/` |
| R4 | Provider Pack Expansion | Expand framework/provider semantics where they materially strengthen cross-layer judgment: Firebase, common Auth/OIDC/JWT/session stacks, Stripe/payment/webhook integrity, Vercel/Cloudflare/deploy surfaces, PostgreSQL and selected cloud/IaC providers | R1, R3 | planned | — |
| R5 | **Security Invariant Regression + CI/Forge/IDE Integrations** | Compare trusted-base vs candidate SSG/invariant/coverage state, surface high-signal security-property regressions and coverage loss, deliver through the local CLI/protocol and GitHub/forge review first, then IDE/agent integrations without making vendor hooks canonical judgment implementations | R1, R3 | **implementation active — S1 Spec 004; exact frontier is canonical `tasks.md`; S2/S3 roadmap-only** | `specs/004-security-invariant-regression/` |
| R6 | **Evidence Upgrade + Safe Verification + Fix Validation** | Opt-in isolated differential tests and bounded verification that prove/disprove selected claims. Freeze Rules of Engagement, Tool Capability Manifest, worker isolation, proof artifacts, durable incomplete/cancel semantics and point retest; emit `FIX_VERIFIED` only with the evidence strength required by the original claim | R1, R3; S1-S4 before S5 product verification | planned | — |
| R7 | Supply Chain + External Evidence + Infrastructure + Deployment | Add qualified generic producer/import contracts, SARIF/SBOM/scanner/advisory evidence, SCA/IaC/workflow/container/deployment security, signed pack/tool provenance, artifact identity/routing, and later bounded dependency/build action controls/open intelligence ingestion. Provider/infrastructure expansion additionally depends on R4 where it consumes R4 semantics. | R1, R3; R4 where provider semantics are consumed | planned | — |
| R8 | **Runtime & Operational Evidence + Enforcement Tiers** | Add a standards-first Operational Evidence Bridge for deployment/release identity, errors, logs, traces/spans, health/uptime and optional qualified runtime-security producers; correlate observations back into stable semantic identities without rewriting static facts or pretending cross-platform parity | R1, R6, S6 import contracts | planned | — |
| R9 | **SentrdelBench + Open Semantic Security Conformance/Judgment Specs** | Mature the evaluation core into public/protected conformance spanning Evidence, Coverage, invariants, regression pairs, imports, verify/fix, agent security, false proof, runtime correlation, unauthorized-capability attempts, FP/false-block/coverage-loss/latency and operator comprehension; mature ASEL/Evidence/SSG extension contracts as public specs | R1 onward | planned | — |
| R10 | **Semantic Security Graph + A-to-Z Security Control Plane/Posture** | Correlate code, identity, data, dependencies, providers, CI, cloud, deployment, agents and runtime into explainable SSG-backed posture; add reconciler-preserving Finding lifecycle, risk/remediation/retest/reopen audit state and an optional self-hosted/team control-plane projection over stable local protocols | R2–R9 | planned | — |
| R11 | Continuous Security Research + Learning Plane | Controlled observe→distill→hypothesize→candidate→replay→benchmark→protected-holdout→shadow→approve/sign loop for rules, packs, graph heuristics, fixtures, fuzz targets and intelligence candidates; preserve source/license/freshness/provenance and prohibit direct self-modification or self-promotion of trusted judgment authority | R1, R6, R9 | planned | — |

## Post-R3 strategic priority

Roadmap IDs are stable identifiers, not permission to assume numerical execution order. R3 closeout is canonical and S1 implementation is active under Spec 004. The preferred product priority remains:

1. **R5 / S1-S3: Security Invariant Regression Core → local developer contract → GitHub/forge delivery**;
2. **R9 / S4: Open Regression Conformance** — measure precision, misses, coverage loss, deterministic graph diff and explanation quality before broad detector expansion;
3. **R6 / S5: bounded verification/fix validation** — include the VF-1→VF-4 safety/capability/proof/retest packages defined in the 2026-09-12 blueprint;
4. **R7 / S6: External Evidence Import Protocol** — gain standards-first breadth without rebuilding mature scanners;
5. **R4 / S7: semantic provider/auth expansion** — add frameworks/providers by invariant leverage rather than checklist count;
6. **R7 / S8: dependency/build action guard** at genuinely controllable seams;
7. **R8 / S9: runtime/operational correlation** built on S6 import and deployment identity contracts;
8. **R10 / S10: mature full-project SSG posture + Finding lifecycle/control-plane projection**;
9. **R11 / S11: controlled research/intelligence/learning flywheel**.

Existing Gate A (Agentic Code Security Conformance), Gate B (Artifact Identity + Evasion-Resistant Routing), and Gate C (static/local Agent/MCP/Skill Security) remain as defined in the 2026-09-08 supplement. Agent Security Verification, Operational Evidence Bridge, Finding Lifecycle/Remediation and the optional control plane use the dependency/entry gates in the 2026-09-12 blueprint and do not create implementation authority by appearing here.

Every new slice still requires its own Spec Kit lifecycle and dependency proof before implementation. The exact current S1 frontier is controlled by live repository truth and `specs/004-security-invariant-regression/tasks.md`; this roadmap intentionally does not duplicate a mutable task frontier. S2/S3 remain roadmap-only until separately authorized.

## Proof-of-category demos

Before broad feature expansion, Sentrdel should prove four end-to-end demos through the same evidence/coverage/invariant contracts:

1. tenant-isolation regression;
2. elevated provider-authority regression;
3. protected-property mutation regression;
4. **coverage regression** where a previously provable security property becomes unsupported, dynamic, failed, or ambiguous.

Demo 4 is mandatory. It demonstrates the Evidence Before Verdict thesis more strongly than another raw vulnerability screenshot: losing analysis capability must never silently become a clean result.

After the S5/S6/runtime/lifecycle contracts mature, the long-term category demo adds a fifth end-to-end proof:

5. **source→verification→deployment→runtime→remediation→point-retest** — a reconciled regression is selectively verified with immutable proof artifacts, fixed, point-retested, linked to an attested/claimed deployment with explicit verification strength, correlated with bounded runtime observations, and transparently reopened if reality contradicts the fix.

## R11 hard boundary

R11 is not "self-modifying Sentrdel Core." Its Research/Learning Plane may propose candidate artifacts only. It cannot autonomously change or promote:

- kernel invariants;
- epistemic authority rules;
- reconciler-only Finding authority;
- verification semantics;
- lifecycle transition validity;
- tool/pack capability ceilings;
- the evaluator/holdout labels used to judge its current candidate;
- release gates.

Those remain ordinary reviewed Spec Kit/repository changes.

## Provider Pack priority

The provider-pack system MUST be extensible but must not become hundreds of shallow checklists. Initial priority:

1. **Supabase** — first dedicated post-R1 spec; static/offline posture before credentialed live mode; later cross-layer business logic.
2. Firebase — Firestore/Storage/Realtime rules, Auth, Admin SDK boundaries, App Check, Functions.
3. Auth stacks — OAuth/OIDC/JWT/session/cookie/provider configuration and server/client trust boundaries.
4. **Stripe** — webhook signature/raw-body handling, duplicate/idempotency/state-transition risks, live-vs-test key exposure and server/client boundaries.
5. Vercel/Cloudflare and common deployment surfaces.
6. AWS/Azure/GCP, Kubernetes, Terraform/Pulumi, Docker/Helm.

GitHub Actions high-signal change analysis starts in R1 and broader invariant-regression/forge integration continues in R5. R4 provider expansion should follow the post-R3 product priority above unless a separately approved spec establishes a stronger dependency reason.

Every pack emits the same canonical Evidence schema and is subject to the same proof/coverage rules. Detection, offline/static posture, optional live posture, cross-layer/business-logic coverage and runtime/verification coverage are separate dimensions. Security Packs additionally require source/license/provenance, capability, dependency, authority-ceiling, conformance and revocation/revalidation metadata before broad third-party distribution.

## External Evidence interoperability direction

Sentrdel SHOULD gain breadth by consuming mature external evidence rather than recreating every scanner.

Future bounded import specifications may cover SARIF, CycloneDX/SPDX, OSV-compatible advisories, Trivy/Grype/Syft, Semgrep/Opengrep, user-supplied CodeQL, Gitleaks, Checkov/Terrascan and later qualified DAST/runtime producers.

Imported records remain untrusted observations. Producer version/config/digest, schema validation, resource bounds, provenance, coverage and authority ceilings must be explicit. External severity, reachability or confidence MUST NOT become canonical Sentrdel Finding authority by itself.

The 2026-09-12 plan further separates four extension classes that should receive versioned conformance rather than ad-hoc integrations:

1. Evidence Producer / Import Adapter;
2. Tool / Verification Adapter;
3. Runtime Telemetry Adapter;
4. Security Pack.

## Rule, Tool and Pack supply-chain direction

As distribution matures, Rules/Security Packs and external tool adapters should expose digest, provenance/publisher, schema version, capability declarations, authority ceiling, benchmark qualification, license/source qualification, SBOM/attestation where applicable, update/revocation/retirement state, and requalification triggers.

Declarative security content receives no ambient process/network/secret authority by default. A valid signature proves integrity/identity under a trust policy; it does not prove security correctness or grant execution authority.

## Runtime and operational evidence direction

Sentrdel SHOULD prefer standards-first runtime interoperability rather than inventing a proprietary telemetry stack.

Future bounded runtime work should prioritize:

- OpenTelemetry/OTLP resources, traces, logs, metrics/events where useful;
- deployment/release/build identity;
- compatible error/envelope ecosystems where they materially reduce integration cost;
- optional qualified runtime-security producers such as Falco behind an import boundary;
- explicit sampling/drop/truncation/retention/redaction state;
- exact/ambiguous/unmapped correlation outcomes;
- no request/response bodies or secret-bearing payloads by default.

Runtime observations remain a separate epistemic class until reconciled and cannot retroactively rewrite static FACT records.

## Finding lifecycle and remediation direction

The reconciler remains the only canonical Finding creator. After creation, future R10 lifecycle contracts may support ownership, acknowledgement, accepted risk with reason/expiry, fix candidates, retest-required, `FIX_VERIFIED`, reopen/stale/suppression and duplicate/related projections through immutable audit events.

Generated remediation is a candidate, not a verified fix. `FIX_VERIFIED` requires replay of the relevant invariant/proof/retest plan with the evidence strength required by the original claim.

## Open security intelligence direction

Future R7/R11 work MAY ingest multiple security-intelligence sources, package/advisory metadata and community research through explicit versioned provenance rather than requiring a proprietary threat feed.

Intelligence is evidence/context until validated under Sentrdel rules. Research automation may propose candidate rules, fixtures or advisories but cannot self-promote them into trusted judgment authority.

## Donor and product-reference strategy

The following are candidates or references, not automatically trusted dependencies:

- `tree-sitter`, `ast-grep-core`, SCIP, `petgraph`, qualified `gix`, `regorus`, `rmcp` — native/high-priority foundations subject to exact security qualification.
- Joern, Opengrep, CodeQL (user-supplied), Syft/Trivy/Checkov and other mature scanners — optional external evidence engines where qualified.
- `Graphify-Labs/graphify` — study/adapt graph-diff, confidence, affected/blast-radius patterns; do not introduce a second canonical graph runtime.
- `vitali87/code-graph-rag` — study/adapt schema, resource/data-flow, static/runtime merge concepts; do not import its Python/Memgraph runtime as Sentrdel core.
- `deepseek-ai/deepseek-harness` — study/adapt durable agent events, tool guard pipeline, approval/sandbox seam concepts.
- `continuedev/continue` — study/adapt permissively licensed IDE/CLI integration patterns; do not fork the archived product wholesale.
- `karpathy/autoresearch` — study the immutable-evaluator/iterative experiment pattern only; do not transfer autonomous mutation authority into the trusted security plane.
- Hermes Agent learning/skills patterns — study inspectable distill/reuse/refine lifecycle concepts; do not treat accumulated memory/skills as security authority without Sentrdel promotion, expiry, invalidation and provenance controls.
- `Tencent/AI-Infra-Guard` — taxonomy/conformance reference for Agent/MCP/Skill security and adversarial routing; no full runtime or dynamic-red-team adoption from the research record.
- `google/magika` — optional artifact-classifier candidate for future routing research; probabilistic output remains inference and no native/model dependency is authorized by the research record.
- `Tencent/AICGSecEval` — benchmark-methodology reference for repository-level AI/agent-generated code evaluation; no dataset/PoC/image/provider-credential adoption from the research record.
- `Tencent/secguide` — knowledge-source reference only; license/freshness constraints require separate validation before adaptation or trusted-rule promotion.
- `Tencent/TscanCode` — low-priority external-engine/import-format reference; GPL implementation remains outside the permissive trusted core.
- **GlitchTip** — reference for self-hosted error/log/trace/uptime correlation, release/environment identity, issue/lifecycle UX, retention and SSRF-safe monitoring defaults; prefer protocol/standards interoperability over cloning its backend.
- `hackerai-tech/hackerai` — architecture reference for durable runs, sandbox transports, cancellation/recovery and provider isolation. Its observed license adds commercial-use restrictions; source copy into Sentrdel requires a sufficiently specific separate permission record and exact qualification.
- `AISecurityLab/hackagent` — reference for agent-security generator/judge/target separation and conformance methodology; dynamic attack generation belongs only in a separately authorized isolated verification profile.
- `0x4m4/hexstrike-ai` — reference for typed tool catalog/process/resource/caching/progress patterns; do not import autonomous exploitation/tool-selection authority into ordinary review.
- `KeygraphHQ/shannon` — reference for Rules of Engagement, resumable workspaces, incomplete-vs-clean semantics, proof-oriented verification and retest. Public AGPL code remains outside the permissive core absent a sufficiently specific separate relicense/permission basis.
- `yashab-cyber/hackbot` — reference for Finding lifecycle UX, assessment diff, campaign/inventory, plugin/tool UX and reporting; do not inherit autonomous exploit/zero-day authority.
- `usestrix/strix` — high-value reference for immutable HTTP proof exchange IDs, coverage discipline, skill metadata, remediation→retest and sandbox/run artifacts; autonomous exploitation remains outside Sentrdel core authority.
- **OpenTelemetry / OTLP** — primary standards reference for future runtime telemetry and resource/service/deployment correlation.
- **DefectDojo** — workflow/reference for import/reimport, dedup, triage, risk acceptance, SLA and asset/engagement modeling; do not recreate hundreds of parser integrations where generic producer contracts suffice.
- **Sigstore / Cosign / in-toto** — supply-chain identity/attestation reference for packs, tools, images, benchmarks and release artifacts; signatures do not imply semantic trust.
- **Falco** — optional future runtime producer reference; privileged kernel/eBPF collection must remain outside the base install and enter through bounded runtime evidence adapters.
- **Aikido Security** — product/competitive reference for full-context PR review, reachability/correlation, validation/retesting, threat-intelligence flywheels, package-action protection and developer-first distribution. Do not interpret its platform breadth as a mandate to rebuild equivalent scanners.
- **Semgrep** — product/reference for diff-aware PR scanning and cross-file analysis; these capabilities are table stakes, not Sentrdel's category moat.
- **Endor Labs** — product/reference for reachability, AI SAST, package/firewall, and agent-action policy surfaces; guard/reachability breadth alone is not sufficient differentiation.
- **Socket** — product/reference for behavior-oriented dependency/package risk; prefer evidence interop over building a proprietary package-analysis platform first.
- **GitHub Code Security / CodeQL** — product/reference for native forge delivery, code scanning, reachability/query infrastructure and autofix; forge-native scanning/autofix alone is not sufficient differentiation.
- **XBOW** — product/reference for proof-oriented offensive validation; Sentrdel remains bounded and opt-in rather than adopting autonomous exploitation authority.
- `AikidoSec/safe-chain` — study the package-install control seam and adoption model only. Source reuse or dependency adoption requires an ordinary exact source/dependency qualification record first.

Before any source reuse, a Source Qualification Ledger entry MUST record exact commit/file provenance, license/permission basis, notices, dependency/security implications, integration mode and chosen authority boundary.

## Definition of roadmap success

Sentrdel succeeds when developers can install one trusted Rust tool, obtain understandable high-signal security judgment with explicit proof/coverage status, use it across coding agents and development environments, and progressively protect the whole project without needing to become security experts.

Sentrdel should answer its defining developer question with a trusted-base/candidate invariant delta, deterministic provenance, explicit uncertainty/coverage, reconciled judgment, optional bounded verification evidence, deployment/runtime correlation and remediation/retest history.

Long-term, one demonstrable workflow should connect an AI-authored source regression to evidence, explicit Coverage, bounded proof artifacts, a reviewed fix, point retest, deployment identity, runtime observations and transparent reopen/closure without allowing any scanner, model, runtime event, dashboard or donor engine to bypass canonical judgment authority.

Sentrdel also proves that its judgment is improving through repeatable evaluation and open conformance rather than relying on rule count, vendor severity, model confidence, scanner aggregation, exploit count, or unmeasured self-learning.