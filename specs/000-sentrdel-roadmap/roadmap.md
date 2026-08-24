# Sentrdel Spec-of-Specs Roadmap

**Status:** ACTIVE  
**Created:** 2026-08-24  
**Purpose:** Decompose the A-to-Z Sentrdel mission into bounded Spec Kit slices. Each roadmap item MUST receive its own `spec.md`, clarification closeout, plan/research/design artifacts, checklist, tasks, analysis, and implementation lifecycle.

## Product North Star

Sentrdel becomes the essential open-source security system developers use whenever they code—especially with AI coding agents. It protects the whole project from authoring to production while remaining Rust-first, local-first, vendor-neutral, evidence-first, and explicit about what is enforced versus advisory.

## Architectural thesis

Sentrdel is **not** a new universal CPG and **not** a wrapper that treats scanner output as truth. The trusted Rust core owns:

1. canonical Agent Security Event and Evidence schemas;
2. tamper-evident local storage;
3. evidence/property graph with provenance and confidence;
4. monotonic policy/guard verdicts at controllable seams;
5. reconciliation from evidence into findings;
6. security invariants and business-logic substrate;
7. bounded verification and fix validation;
8. developer-facing security judgment.

External engines provide evidence through strict, versioned boundaries.

## Roadmap

| ID | Slice | Goal | Depends on | Status | Sub-spec |
|---|---|---|---|---|---|
| R1 | Evidence + Guard Foundation | Ship a useful Rust CLI for diff review, canonical evidence, stack detection, MCP/git guard seams, coverage gaps, and high-signal baseline checks | — | planning | `specs/001-v0-1-evidence-guard-foundation/` |
| R2 | Business-Logic Substrate + Invariants | Build route × guard × data-model analysis and executable project security invariants, including tenant isolation and authorization candidates | R1 | planned | — |
| R3 | Provider Security Packs | Introduce provider/framework packs with **Supabase as P0**, then Firebase, common auth/payment/deploy/cloud stacks | R1, R2 | planned | — |
| R4 | CI + Forge + IDE Integrations | GitHub Actions/App, VS Code/Cursor, Claude hooks, Codex policies, JetBrains via daemon; reuse mature integration patterns where qualified | R1 | planned | — |
| R5 | Safe Verification + Fix Validation | Opt-in isolated differential tests, local API/security assertions, regression checks, and `FIX_VERIFIED` evidence | R1, R2 | planned | — |
| R6 | Supply Chain + Infrastructure + Deployment | Broaden SCA/SBOM, IaC, workflows, containers, cloud/deployment posture, provenance and release security | R1, R3 | planned | — |
| R7 | Runtime Evidence + Enforcement Tiers | Add runtime observations, Linux enforcement/telemetry integrations, deployment/runtime posture without pretending cross-platform parity | R1, R5 | planned | — |
| R8 | SentrdelBench + Open Security Judgment Specs | Mature ASEL/evidence schemas as public specs; benchmark code, guard, invariants, verify/fix, FP/false-block/latency/novice comprehension | R1 onward | planned | — |
| R9 | A-to-Z Project Posture | Correlate code, identity, data, providers, CI, cloud, deployment, agents, and runtime into an explainable full-project security posture | R2–R8 | planned | — |

## Provider Pack priority

The provider-pack system MUST be extensible but must not become hundreds of shallow checklists. Initial priority:

1. **Supabase** — Postgres/RLS/grants/Auth/service-role boundaries/Storage/Edge Functions/migrations/exposed schemas.
2. Firebase — Firestore/Storage/Realtime rules, Auth, Admin SDK boundaries, App Check, Functions.
3. GitHub Actions — permissions, secrets, OIDC, untrusted PR execution, action pinning, workflow mutation.
4. Vercel/Cloudflare and common deployment surfaces.
5. Stripe and payment/webhook state integrity.
6. Auth providers and common OAuth/OIDC/JWT/session stacks.
7. AWS/Azure/GCP, Kubernetes, Terraform/Pulumi, Docker/Helm.

Every pack emits the same canonical Evidence schema and is subject to the same proof/coverage rules.

## Donor strategy

The following are candidates, not automatically trusted dependencies:

- `tree-sitter`, `ast-grep-core`, SCIP, `petgraph`, `regorus` — likely native/high-priority foundations.
- Joern, Opengrep, CodeQL (user-supplied), Syft/Trivy/Checkov and other mature scanners — optional external evidence engines where qualified.
- `Graphify-Labs/graphify` — study/adapt graph-diff, confidence, affected/blast-radius patterns; do not introduce a second canonical graph runtime.
- `vitali87/code-graph-rag` — study/adapt schema, resource/data-flow, static/runtime merge concepts; do not import its Python/Memgraph runtime as Sentrdel core.
- `deepseek-ai/deepseek-harness` — study/adapt durable agent events, tool guard pipeline, approval/sandbox seam concepts.
- `continuedev/continue` — study/adapt permissively licensed IDE/CLI integration patterns; do not fork the archived product wholesale.

Before any source reuse, a source-qualification ledger MUST record exact commit/file provenance, license, dependency/security implications, and the chosen boundary.

## Definition of roadmap success

Sentrdel succeeds when developers can install one trusted Rust tool, obtain understandable high-signal security judgment with explicit proof/coverage status, use it across coding agents and development environments, and progressively protect the whole project without needing to become security experts.
