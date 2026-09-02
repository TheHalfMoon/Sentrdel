# Sentrdel Spec-of-Specs Roadmap

**Status:** ACTIVE  
**Created:** 2026-08-24  
**Last major review:** 2026-09-02  
**Improvement Plan of Record:** `improvement-plan-2026-08-26.md`  
**Strategic Amendment of Record:** `strategic-amendment-2026-09-02-semantic-security-graph.md`  
**Post-R3 Execution Blueprint of Record:** `post-r3-execution-blueprint-2026-09-02.md`  
**Roadmap Navigation:** `README.md`  
**Purpose:** Decompose the A-to-Z Sentrdel mission into bounded Spec Kit slices. Each roadmap item MUST receive its own `spec.md`, clarification closeout, plan/research/design artifacts, checklist, tasks, analysis, and implementation lifecycle.

## Product North Star

Sentrdel becomes the essential open-source security system developers use whenever they code—especially with AI coding agents. It protects the whole project from authoring to production while remaining Rust-first, local-first, vendor-neutral, evidence-first, and explicit about what is enforced versus advisory.

## Category

**Sentrdel is the open-source security-invariant regression and evidence judgment engine for AI-built software, operating as the semantic security evidence and control plane for the whole software project.**

It MUST NOT compete primarily on rule count, generic "AI code scanning," scanner aggregation, or one IDE/agent integration. Those capabilities are increasingly available from large security and coding-agent vendors. Sentrdel's durable differentiation is independent adjudication, coverage truth, ASEL agent evidence, security invariants, the Sentrdel Semantic Security Graph, trusted-base/candidate security-property regression, provider-aware project posture, safe verification, context/instruction provenance, open conformance contracts, and continuously evaluated security judgment.

The defining developer question is:

> **What security property did this change weaken, what evidence proves it, what analysis is missing, and what stronger claim—if any—was separately verified?**

## Architectural thesis

Sentrdel is **not** a new universal CPG and **not** a wrapper that treats scanner output as truth. The trusted Rust core owns:

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
13. promotion boundaries that keep future learning/research automation candidate-only until independently qualified.

External engines provide evidence through strict, versioned boundaries. Graph context, model output, and external-engine severity/confidence MUST NOT independently upgrade epistemic authority.

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

The repository adopts `strategic-amendment-2026-09-02-semantic-security-graph.md` as the strategic refinement produced by the latest AppSec/platform evaluation and `post-r3-execution-blueprint-2026-09-02.md` as the dependency-ordered roadmap decomposition for that strategy after canonical R3 closeout.

Binding direction:

- finish the active R3 task sequence exactly as governed; this amendment does not reorder `R3-T009 -> ... -> R3-T038`;
- name the bounded canonical graph direction the **Sentrdel Semantic Security Graph (SSG)** without creating a universal CPG or second graph runtime;
- make **Security Invariant Regression** over a trusted base the first post-R3 product wedge, not generic diff-aware scanning;
- treat **coverage regression** as a first-class security outcome so loss of visibility cannot become an implicit clean result;
- prioritize a post-R3 R5 invariant-regression + forge integration slice before broad provider-pack proliferation;
- define future trusted-base/candidate states such as `NEW`, `WORSENED`, `MITIGATED`, `REINTRODUCED`, `UNCERTAIN`, `COVERAGE_LOST`, and related evidence-backed states only through separately frozen contracts;
- strengthen R9 into an open Evidence/Coverage/Invariant/Regression/Importer/Verification conformance and benchmark ecosystem;
- define a later External Evidence Import Protocol so mature scanners/SBOM/SARIF/advisory engines contribute untrusted Evidence rather than being rebuilt or treated as judges;
- frame R6 as an Evidence Upgrade + Fix Validation plane where `FIX_VERIFIED` requires execution evidence;
- use R7/R11 for qualified multi-source security intelligence and dependency/action-control work rather than making a proprietary feed mandatory;
- keep the core open, local-first, inspectable and useful without account creation, source upload, provider credentials or a proprietary API;
- evaluate future major features with the defensibility filter in the strategic amendment and roadmap index: if a mature external engine can provide the raw capability and rebuilding it does not materially strengthen invariant judgment, coverage truth, verification or conformance, prefer import/reuse.

## Roadmap

| ID | Slice | Goal | Depends on | Status | Sub-spec |
|---|---|---|---|---|---|
| R1 | Evidence + Guard Foundation | Ship a useful Rust CLI for diff review, canonical evidence, stack detection, bounded stdio MCP guard, git guard seams, coverage gaps, high-signal baseline checks, and the minimum immutable evaluation foundation required to measure quality before detector breadth | — | complete | `specs/001-v0-1-evidence-guard-foundation/` |
| R2 | **Supabase P0 Static/Posture Pack** | Offline deterministic Supabase security posture: RLS/policies, grants/functions, SECURITY DEFINER/search_path, exposed schemas/sensitive columns, service-role/client boundaries, Storage and Auth/config signals; separate optional live posture later | R1 | complete | `specs/002-supabase-static-posture/` |
| R3 | Business-Logic Substrate + Invariants | Build the first application-semantic SSG slice: route × actor/auth × guard × value/data operation × provider authority × invariant analysis, including tenant isolation/authz; augment Supabase and generalize only through bounded adapters | R1, R2 | active | `specs/003-business-logic-invariants/` |
| R4 | Provider Pack Expansion | Expand framework/provider semantics where they materially strengthen cross-layer judgment: Firebase, common Auth/OIDC/JWT/session stacks, Stripe/payment/webhook integrity, Vercel/Cloudflare/deploy surfaces, PostgreSQL and selected cloud/IaC providers | R1, R3 | planned | — |
| R5 | **Security Invariant Regression + CI/Forge/IDE Integrations** | Compare trusted-base vs candidate SSG/invariant/coverage state, surface high-signal security-property regressions and coverage loss, deliver through the local CLI/protocol and GitHub/forge review first, then IDE/agent integrations without making vendor hooks canonical judgment implementations | R1, R3 | planned — first post-R3 productization priority | — |
| R6 | **Evidence Upgrade + Safe Verification + Fix Validation** | Opt-in isolated differential tests and bounded verification that prove/disprove selected claims; re-analyze candidate fixes and emit `FIX_VERIFIED` only with authorized execution evidence | R1, R3 | planned | — |
| R7 | Supply Chain + External Evidence + Infrastructure + Deployment | Add qualified SARIF/SBOM/scanner/advisory evidence imports, broaden SCA/IaC/workflow/container/deployment security, provenance/release security, and later bounded dependency/build action controls/open intelligence ingestion | R1, R4 | planned | — |
| R8 | Runtime Evidence + Enforcement Tiers | Add runtime observations, Linux enforcement/telemetry integrations, deployment/runtime posture and correlation back into stable semantic identities without pretending cross-platform parity | R1, R6 | planned | — |
| R9 | **SentrdelBench + Open Semantic Security Conformance/Judgment Specs** | Mature the R1 evaluation core into public benchmark/conformance infrastructure spanning Evidence, Coverage, invariants, regression pairs, imports, verify/fix, FP/false-block/coverage-loss/latency/novice comprehension; mature ASEL/Evidence/SSG contracts as public specs | R1 onward | planned | — |
| R10 | **Semantic Security Graph + A-to-Z Project Posture** | Correlate code, identity, data, dependencies, providers, CI, cloud, deployment, agents and runtime into an explainable SSG-backed full-project security posture | R2–R9 | planned | — |
| R11 | Continuous Security Research + Learning Plane | Controlled observe→distill→hypothesize→candidate→replay→benchmark→protected-holdout→shadow→approve/sign loop for rules, packs, graph heuristics, fixtures, fuzz targets and intelligence candidates; no direct self-modification or self-promotion of trusted judgment authority | R1, R6, R9 | planned | — |

## Post-R3 strategic priority

Roadmap IDs are stable identifiers, not permission to assume numerical execution order. After canonical R3 closeout and after the planning amendment itself is reconciled and qualified, the preferred product priority is:

1. **R5 / S1-S3: Security Invariant Regression Core → local developer contract → GitHub/forge delivery**;
2. **R9 / S4: Open Regression Conformance** — measure precision, misses, coverage loss, deterministic graph diff and explanation quality before broad detector expansion;
3. **R6 / S5: bounded verification/fix validation** — create a trustworthy evidence-upgrade loop for a small set of high-value invariants;
4. **R7 / S6: External Evidence Import Protocol** — gain standards-first breadth without rebuilding mature scanners;
5. **R4 / S7: semantic provider/auth expansion** — add frameworks/providers by invariant leverage rather than checklist count;
6. **R7 / S8: dependency/build action guard** at genuinely controllable seams;
7. **R8 / S9: runtime correlation**;
8. **R10 / S10: mature full-project SSG posture**;
9. **R11 / S11: controlled research/intelligence/learning flywheel**.

Every new slice still requires its own Spec Kit lifecycle and dependency proof before implementation. The blueprint sequence is planning guidance, not implementation authority.

## Proof-of-category demos

Before broad feature expansion, Sentrdel should prove four end-to-end demos through the same evidence/coverage/invariant contracts:

1. tenant-isolation regression;
2. elevated provider-authority regression;
3. protected-property mutation regression;
4. **coverage regression** where a previously provable security property becomes unsupported, dynamic, failed, or ambiguous.

Demo 4 is mandatory. It demonstrates the Evidence Before Verdict thesis more strongly than another raw vulnerability screenshot: losing analysis capability must never silently become a clean result.

## R11 hard boundary

R11 is not "self-modifying Sentrdel Core." Its Research/Learning Plane may propose candidate artifacts only. It cannot autonomously change or promote:

- kernel invariants;
- epistemic authority rules;
- reconciler-only Finding authority;
- verification semantics;
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

Every pack emits the same canonical Evidence schema and is subject to the same proof/coverage rules. Detection, offline/static posture, optional live posture, cross-layer/business-logic coverage and runtime/verification coverage are separate dimensions.

## External Evidence interoperability direction

Sentrdel SHOULD gain breadth by consuming mature external evidence rather than recreating every scanner.

Future bounded import specifications may cover SARIF, CycloneDX/SPDX, OSV-compatible advisories, Trivy/Grype/Syft, Semgrep/Opengrep, user-supplied CodeQL, Gitleaks, Checkov/Terrascan and later qualified DAST/runtime producers.

Imported records remain untrusted observations. Producer version/config/digest, schema validation, resource bounds, provenance, coverage and authority ceilings must be explicit. External severity, reachability or confidence MUST NOT become canonical Sentrdel Finding authority by itself.

## Rule and Pack supply-chain direction

As distribution matures, Rules/Security Packs should expose digest, provenance/publisher, schema version, capability declarations, authority ceiling, benchmark qualification, and revocation/retirement state. Declarative security content receives no ambient process/network/secret authority by default.

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
- **Aikido Security** — product/competitive reference for full-context PR review, reachability/correlation, validation/retesting, threat-intelligence flywheels, package-action protection and developer-first distribution. Do not interpret its platform breadth as a mandate to rebuild equivalent scanners.
- **Semgrep** — product/reference for diff-aware PR scanning and cross-file analysis; these capabilities are table stakes, not Sentrdel's category moat.
- **Endor Labs** — product/reference for reachability, AI SAST, package/firewall, and agent-action policy surfaces; guard/reachability breadth alone is not sufficient differentiation.
- **Socket** — product/reference for behavior-oriented dependency/package risk; prefer evidence interop over building a proprietary package-analysis platform first.
- **GitHub Code Security / CodeQL** — product/reference for native forge delivery, code scanning, reachability/query infrastructure and autofix; forge-native scanning/autofix alone is not sufficient differentiation.
- **XBOW** — product/reference for proof-oriented offensive validation; Sentrdel remains bounded and opt-in rather than adopting autonomous exploitation authority.
- `AikidoSec/safe-chain` — study the package-install control seam and adoption model only. Source reuse or dependency adoption requires an ordinary exact source/dependency qualification record first.

Before any source reuse, a source-qualification ledger MUST record exact commit/file provenance, license, dependency/security implications, and the chosen boundary.

## Definition of roadmap success

Sentrdel succeeds when developers can install one trusted Rust tool, obtain understandable high-signal security judgment with explicit proof/coverage status, use it across coding agents and development environments, and progressively protect the whole project without needing to become security experts.

Sentrdel should answer its defining developer question with a trusted-base/candidate invariant delta, deterministic provenance, explicit uncertainty/coverage, reconciled judgment and optional bounded verification evidence.

Long-term, Sentrdel also proves that its judgment is improving through repeatable evaluation and open conformance rather than relying on rule count, vendor severity, model confidence, scanner aggregation, or unmeasured self-learning.
