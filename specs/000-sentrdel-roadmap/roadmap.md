# Sentrdel Spec-of-Specs Roadmap

**Status:** ACTIVE  
**Created:** 2026-08-24  
**Last major review:** 2026-08-26  
**Improvement Plan of Record:** `improvement-plan-2026-08-26.md`  
**Purpose:** Decompose the A-to-Z Sentrdel mission into bounded Spec Kit slices. Each roadmap item MUST receive its own `spec.md`, clarification closeout, plan/research/design artifacts, checklist, tasks, analysis, and implementation lifecycle.

## Product North Star

Sentrdel becomes the essential open-source security system developers use whenever they code—especially with AI coding agents. It protects the whole project from authoring to production while remaining Rust-first, local-first, vendor-neutral, evidence-first, and explicit about what is enforced versus advisory.

## Category

**Sentrdel is the open-source security evidence and control plane for the whole software project — from agent action to production.**

It MUST NOT compete primarily on rule count, generic "AI code scanning," or one IDE/agent integration. Those capabilities are increasingly available from large security and coding-agent vendors. Sentrdel's durable differentiation is independent adjudication, coverage truth, ASEL agent evidence, security invariants, provider-aware project posture, safe verification, context/instruction provenance, and continuously evaluated security judgment.

## Architectural thesis

Sentrdel is **not** a new universal CPG and **not** a wrapper that treats scanner output as truth. The trusted Rust core owns:

1. canonical Agent Security Event and Evidence schemas;
2. integrity-linked local storage and trusted-head semantics;
3. evidence/property graph with provenance and confidence;
4. monotonic policy/guard verdicts at controllable seams;
5. reconciliation from evidence into findings;
6. provider-aware security posture;
7. security invariants and business-logic substrate;
8. bounded verification and fix validation;
9. developer-facing security judgment;
10. authority rules separating untrusted context from authorized instruction;
11. immutable evaluation contracts used to measure precision, misses, coverage, false blocks and latency;
12. promotion boundaries that keep future learning/research automation candidate-only until independently qualified.

External engines provide evidence through strict, versioned boundaries.

## Cross-cutting 2026-08-26 amendment

The repository adopts `improvement-plan-2026-08-26.md` as the human-readable Plan of Record for the latest major evaluation.

Binding direction:

- finish the current R1 trusted foundation before broad scope changes;
- establish SentrdelBench Core before detector proliferation;
- prove one excellent end-to-end `sentrdel review` steel thread before optimizing for rule count;
- move repository self-security and MCP credential-isolation controls forward;
- make context/instruction provenance and scoped security memory explicit authority-bounded concepts;
- add temporal finding state and producer calibration as measured context, not new epistemic authority;
- treat community Rules/Security Packs as supply-chain objects;
- add a later continuous Security Research/Learning Plane whose candidates cannot self-promote or modify the trusted judgment/evaluation authority used to judge them.

## Roadmap

| ID | Slice | Goal | Depends on | Status | Sub-spec |
|---|---|---|---|---|---|
| R1 | Evidence + Guard Foundation | Ship a useful Rust CLI for diff review, canonical evidence, stack detection, bounded stdio MCP guard, git guard seams, coverage gaps, high-signal baseline checks, and the minimum immutable evaluation foundation required to measure quality before detector breadth | — | complete | `specs/001-v0-1-evidence-guard-foundation/` |
| R2 | **Supabase P0 Static/Posture Pack** | Offline deterministic Supabase security posture: RLS/policies, grants/functions, SECURITY DEFINER/search_path, exposed schemas/sensitive columns, service-role/client boundaries, Storage and Auth/config signals; separate optional live posture later | R1 | complete | `specs/002-supabase-static-posture/` |
| R3 | Business-Logic Substrate + Invariants | Build route × guard × data-model analysis and executable security invariants, including tenant isolation/authz; augment Supabase and generalize across frameworks | R1, R2 | planning | `specs/003-business-logic-invariants/` |
| R4 | Provider Pack Expansion | Firebase, common Auth/OIDC/JWT/session stacks, Stripe/payment/webhook integrity, Vercel/Cloudflare/deploy surfaces, PostgreSQL and selected cloud/IaC providers | R1, R3 | planned | — |
| R5 | CI + Forge + IDE Integrations | GitHub Actions/App, VS Code/Cursor, Claude hooks, Codex policies, JetBrains via daemon; reuse qualified integration patterns without making vendor hooks canonical | R1 | planned | — |
| R6 | Safe Verification + Fix Validation | Opt-in isolated differential tests, local API/security assertions, regression checks, and `FIX_VERIFIED` evidence | R1, R3 | planned | — |
| R7 | Supply Chain + Infrastructure + Deployment | Broaden SCA/SBOM, IaC, workflows, containers, cloud/deployment posture, provenance and release security | R1, R4 | planned | — |
| R8 | Runtime Evidence + Enforcement Tiers | Add runtime observations, Linux enforcement/telemetry integrations, deployment/runtime posture without pretending cross-platform parity | R1, R6 | planned | — |
| R9 | SentrdelBench + Open Security Judgment Specs | Mature the R1 evaluation core into public benchmark/spec infrastructure spanning code, guard, packs, invariants, verify/fix, FP/false-block/latency/novice comprehension; mature ASEL/Evidence contracts as public specs | R1 onward | planned | — |
| R10 | A-to-Z Project Posture | Correlate code, identity, data, providers, CI, cloud, deployment, agents, and runtime into an explainable full-project security posture | R2–R9 | planned | — |
| R11 | Continuous Security Research + Learning Plane | Controlled observe→distill→hypothesize→candidate→replay→benchmark→protected-holdout→shadow→approve/sign loop for rules, packs, graph heuristics, fixtures and fuzz targets; no direct self-modification or self-promotion of trusted judgment authority | R1, R6, R9 | planned | — |

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

GitHub Actions high-signal change analysis starts in R1 and broader CI/forge integration continues in R5/R7.

Every pack emits the same canonical Evidence schema and is subject to the same proof/coverage rules. Detection, offline/static posture, optional live posture, and cross-layer/business-logic coverage are separate dimensions.

## Rule and Pack supply-chain direction

As distribution matures, Rules/Security Packs should expose digest, provenance/publisher, schema version, capability declarations, authority ceiling, benchmark qualification, and revocation/retirement state. Declarative security content receives no ambient process/network/secret authority by default.

## Donor strategy

The following are candidates, not automatically trusted dependencies:

- `tree-sitter`, `ast-grep-core`, SCIP, `petgraph`, qualified `gix`, `regorus`, `rmcp` — native/high-priority foundations subject to exact security qualification.
- Joern, Opengrep, CodeQL (user-supplied), Syft/Trivy/Checkov and other mature scanners — optional external evidence engines where qualified.
- `Graphify-Labs/graphify` — study/adapt graph-diff, confidence, affected/blast-radius patterns; do not introduce a second canonical graph runtime.
- `vitali87/code-graph-rag` — study/adapt schema, resource/data-flow, static/runtime merge concepts; do not import its Python/Memgraph runtime as Sentrdel core.
- `deepseek-ai/deepseek-harness` — study/adapt durable agent events, tool guard pipeline, approval/sandbox seam concepts.
- `continuedev/continue` — study/adapt permissively licensed IDE/CLI integration patterns; do not fork the archived product wholesale.
- `karpathy/autoresearch` — study the immutable-evaluator/iterative experiment pattern only; do not transfer autonomous mutation authority into the trusted security plane.
- Hermes Agent learning/skills patterns — study inspectable distill/reuse/refine lifecycle concepts; do not treat accumulated memory/skills as security authority without Sentrdel promotion, expiry, invalidation and provenance controls.

Before any source reuse, a source-qualification ledger MUST record exact commit/file provenance, license, dependency/security implications, and the chosen boundary.

## Definition of roadmap success

Sentrdel succeeds when developers can install one trusted Rust tool, obtain understandable high-signal security judgment with explicit proof/coverage status, use it across coding agents and development environments, and progressively protect the whole project without needing to become security experts.

Long-term, Sentrdel also proves that its judgment is improving through repeatable evaluation rather than relying on rule count, model confidence, or unmeasured self-learning.
