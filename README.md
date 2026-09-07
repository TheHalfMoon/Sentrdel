# Sentrdel

**Open-source security evidence and control plane for software development.**

Sentrdel is a Rust-first, local-first, vendor-neutral security layer for AI-assisted and ordinary software development. R1 provides the trustworthy evidence, diff review, explicit coverage, monotonic guardrail, stdio MCP, profiling, explanation, and lower-authority reasoning substrate. R2 adds the first provider-specific pack: bounded offline Supabase static posture. R3 adds bounded static cross-layer business-logic analysis and security invariants over the declared JavaScript/TypeScript adapter scope.

## North Star

A developer should be able to build with Codex, Cursor, Claude Code, JetBrains/Junie, Windsurf, Copilot, or another coding agent and rely on Sentrdel as an independent security judgment and guardrail plane between generated change and merge/deploy.

High-severity security claims carry explicit evidence and proof state. Sentrdel distinguishes facts, deterministic inferences, hypotheses, runtime observations, contradictions, and stronger verification authority rather than treating scanner or LLM output as equivalent truth.

## R1 implemented capabilities

The current R1 implementation includes:

- a Rust 1.98.0 workspace with canonical Evidence, Finding, Coverage, ASEL, policy, engine, pack, project-profile, graph, and reasoner contracts;
- deterministic canonical serialization/content identities and generated public JSON schemas;
- local SQLite persistence for evidence, findings/projections, coverage/profile state, and integrity-linked ASEL state, with redaction before persistence;
- non-executing Git discovery and working-tree/staged/base diff selection that does not invoke target hooks, external diff/textconv/filter helpers, package managers, Cargo metadata, submodule fetches, credential helpers, or network remotes;
- bounded repository/file views with path, traversal, symlink, confusable, and file-size defenses;
- Rust-native structural matching and a deliberately small high-signal rule set;
- changed-secret Evidence that persists only redacted/sanitized metadata rather than discovered plaintext or stable unkeyed value-only hashes;
- supported dependency-delta parsing with an offline advisory fixture provider and optional OSV-compatible lookup/cache that respects no-network operation;
- high-signal GitHub Actions review for permissions/OIDC, untrusted PR paths, `pull_request_target`, expression-to-shell interpolation, mutable action refs, self-hosted/untrusted runners, and trust-sensitive cache/artifact handoffs;
- deterministic Evidence correlation/reconciliation into canonical Findings while retaining provenance and contradictions;
- bounded graph/reverse-reachability context, review coverage aggregation, and plain-language explanation tiers;
- project profiling for supported repository/language/package/CI/MCP/provider signals without executing target build/install tooling;
- monotonic Rust-owned policy with `ALLOW` / `ASK` / `DENY` / `UNDECIDABLE`, absorbing kernel DENY, bounded policy input, and repository configuration that may narrow but not widen authority;
- integrity-linked ASEL with explicit local-chain/trusted-head limitations;
- a bounded **stdio-only** MCP guard gateway with explicit protocol negotiation, framing/input bounds, scoped approvals, declared enforcement fidelity, and deny-by-default credential inheritance for Sentrdel-launched children;
- git-hook guard support reported as a partial/advisory seam rather than universal interception;
- an optional provider-neutral reasoner boundary with local HTTP/Ollama-compatible and explicitly configured remote HTTP adapters; model output is restricted to `INFERENCE` / `HYPOTHESIS` and cannot weaken policy or canonical Findings;
- SentrdelBench evaluation contracts/harnesses for deterministic replay, precision/known-ground-truth misses, clean-PR false positives, coverage/provenance completeness, latency/resource behavior, guard false blocks, and authority-boundary cases;
- self-security and release gates covering the exact Rust toolchain, committed lockfile/source policy, privileged dependency declarations, `cargo-audit`, `cargo-deny`, malicious-package defense-in-depth policy, and Linux/macOS/Windows CI.

See `docs/architecture/r1-evidence-control-plane.md` and `docs/security/threat-model.md` for the implemented R1 authority and trust boundaries.

## R2 implemented Supabase static posture

R2 extends the R1 pack/evidence substrate with a Rust-owned, offline, deterministic Supabase static posture pack. Its declared supported subset includes repository-visible migration/SQL posture for RLS, policies, grants/revokes, `SECURITY DEFINER`/`search_path`, Storage authorization policy SQL, bounded `supabase/config.toml` Auth/API/Edge Function settings, Supabase key authority classes and source-context boundaries, and supported Edge Function authorization posture.

R2 producers emit canonical Evidence and Coverage only; the existing R1 reconciler remains the only canonical Finding creation path. Unsupported, malformed, ambiguous, dynamic, oversized, missing, or hosted-only state remains explicit coverage rather than becoming a clean result by absence.

R2 does **not** connect to Supabase, use provider-admin credentials, run the Supabase CLI, execute SQL/migrations/Edge Functions, or claim hosted/runtime state. `LIVE_POSTURE` and `RUNTIME` remain unimplemented/not-executed dimensions. R3 may consume compatible R2 static Evidence as supporting input, but it does not upgrade repository-derived posture into hosted truth.

See `docs/architecture/r2-supabase-static-posture.md` for the implemented architecture, coverage matrix, qualification boundaries, and explicit non-claims.

## R3 implemented business-logic substrate and invariants

R3 adds a bounded, static cross-layer business-logic substrate over the existing evidence, coverage, reconciliation, and Sentrdel Semantic Security Graph foundations. Within the declared JavaScript/TypeScript adapter scope, it can correlate supported route entry points, actor/auth identity observations, authorization guards, bounded value origins, Supabase data operations, provider-client authority, and explicit security invariants.

The implemented initial adapter scope is deliberately narrow: supported Express-style routes, Next.js App Router Route Handlers, Next.js Pages API routes, supported Supabase Edge Function patterns, and the bounded Supabase JavaScript data-operation subset frozen by Spec 003. Built-in invariant families cover tenant/object binding, privileged function/role authorization, protected-property mutation, and elevated provider-client application boundaries. Project-declared invariants are structured, bounded, and tightening-only.

R3 producers emit canonical Evidence and Coverage only. The reconciler remains the sole canonical Finding creation path. `BUSINESS_LOGIC` / `CROSS_LAYER_BUSINESS_LOGIC` coverage remains distinct from provider `STATIC_POSTURE`, credentialed `LIVE_POSTURE`, and runtime/verification evidence. Unsupported frameworks, dynamic registration or dispatch, unresolved semantic links, ambiguous identity/guard/data flow, unsupported data operations, and resource-cap exhaustion remain explicit coverage gaps or UNKNOWN/PARTIAL state rather than implicit security.

R3 remains local-first and non-executing. Ordinary R3 analysis does not execute target builds, package managers, application routes, tests, migrations, database queries, provider tooling, or repository helpers; it does not connect to hosted providers or request provider-admin credentials; and it does not prove runtime exploitability, actual cross-tenant access, or production authorization behavior. It reuses the bounded existing SSG/graph substrate and does not claim universal CPG/compiler semantics.

See `docs/architecture/r3-business-logic-invariants.md` and `docs/security/threat-model.md` for the implemented R3 architecture, coverage boundaries, authority ceilings, and explicit non-claims.

## Security invariants

- Rust owns the trusted judgment and control plane.
- Only the reconciler creates canonical Findings from validated Evidence.
- LLM output is lower-authority `INFERENCE` / `HYPOTHESIS`; it cannot mint FACT/VERIFIED authority, suppress deterministic evidence, or weaken policy.
- Missing, failed, unsupported, or unavailable analysis remains visible as Coverage and never becomes a clean result by absence.
- Secret plaintext and stable unkeyed value-only secret hashes are not persisted.
- Target repository content is data, not execution authority.
- External processes use explicit argv and bounded/scrubbed environments; shell-built target commands are not part of the trusted path.
- Project-declared R3 invariants may tighten analysis only; they cannot suppress Evidence, waive Findings, reduce severity, widen execution/network/credential authority, or bypass the reconciler.
- Enforcement is labeled `ENFORCED`, `PARTIAL`, or `ADVISORY` according to the seam Sentrdel actually controls.
- A local ASEL hash chain demonstrates internal consistency relative to the checked state/head; it is not described as independently tamper-proof or non-repudiable.

## Explicit non-claims

The following are **not implemented capabilities** unless a later specification explicitly authorizes them:

- live/credentialed Supabase posture, hosted database/dashboard interrogation, or runtime Supabase verification;
- runtime proof that an R3 business-logic path is exploitable or that cross-tenant access actually occurs;
- complete support for every framework, language, middleware pattern, ORM, database SDK, auth library, or dynamic JavaScript/TypeScript semantic;
- broad provider/cloud/payment/database packs beyond the implemented bounded R2/R3 Supabase-related scope;
- remote/Streamable HTTP MCP enforcement;
- a general verification sandbox, autonomous exploit generation, production pentesting, or ordinary R1/R2/R3 `VERIFIED` producer;
- general-purpose Security Memory;
- autonomous Research/Learning that mutates trusted production rules or self-promotes candidates;
- universal CPG/compiler semantics;
- universal interception of every coding agent or development environment;
- identical operating-system interception semantics merely because supported static paths are qualified on Linux, macOS, and Windows;
- proof that a repository is secure merely because CI is green or a producer emits no finding.

Future learning/research work is candidate-only under the frozen authority contract; it cannot create canonical Findings, alter verification semantics, weaken kernel policy, mutate the evaluator judging its current candidate, or self-promote to trusted authority.

## Development and governance

Planning and implementation are governed by Spec Kit artifacts in `.specify/` and `specs/`. The project constitution is the highest repository-level authority, followed by the active specification/contracts, plan/tasks, and `AGENTS.md`.

Sentrdel's own dependency graph is part of the trusted computing base. Dependency admission, privileged build/proc-macro/native surfaces, advisory checks, source policy, and release gates are documented under `docs/security/` and `docs/third-party/`.

R1/R2/R3 remain local-useful without a cloud account, model provider, or external scanner. Optional integrations may improve coverage without acquiring independent judgment authority.
