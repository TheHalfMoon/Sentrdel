# Research — Sentrdel v0.1 Evidence + Guard Foundation

**Date:** 2026-08-24  
**Status:** RESEARCH_COMPLETE_AFTER_MAJOR_REVIEW  
**Scope:** Decisions needed to implement R1. Source adoption remains subject to exact commit/file/license qualification before copying donor source.

See also: `major-review-2026-08-24.md`.

## R0 — External adversarial review disposition

The independent cybersecurity architecture review returned **GO WITH MAJOR CHANGES**. R1 accepts the changes that improve truthfulness and delivery:

- Guard is environment/protocol control at seams Sentrdel can actually control, not fictional universal agent interception.
- The canonical graph is an evidence/property graph, not a home-grown universal CPG.
- Evidence and event schemas are first-class products.
- LLM reasoning is epistemically second-class.
- Verification is deferred and later constrained to bounded test execution.
- Business-logic security remains strategic but depends on R1's substrate.

## R0.1 — Fresh 2026 market review

Current products now cover much of the low-end category Sentrdel initially risked entering:

- Semgrep Guardian performs real-time security checks inside AI coding workflows using agent integrations/MCP/hooks/skills and publicly reports multi-million weekly scan volume with inline latency.
- GitHub automatically validates code created by third-party coding agents using CodeQL/advisory/secret capabilities.
- Codex Security and Claude Code Security provide contextual AI-led repository security analysis; Codex Security also emphasizes isolated validation/remediation.

**Decision:** Sentrdel's category is not "AI code scanner." It is the **open-source security evidence and control plane for the whole software project, from agent action to production**. The product must own independent evidence adjudication, proof/coverage truth, ASEL, provider-aware posture, security invariants, safe verification and local-first auditability.

## R1 — Trusted implementation language and exact toolchain

**Decision:** Rust for the trusted core.

**R1 implementation pin:** **Rust 1.98.0**.

**Rationale:** The project needs a small auditable distribution, deterministic resource control, safe parsing, concurrency, cross-platform CLI support and type-level separation between untrusted producer data and canonical security state. Rust 1.98.0 is current stable on the review date and is newer than Cargo security fixes introduced in the 1.96 line.

**Supply-chain consequence:** the August 2026 crates.io malicious-package incident demonstrates that build scripts and compromised publisher credentials are practical threats. Sentrdel's own dependencies with `build.rs`, proc macros, native compilation or downloaded binaries require elevated review.

**Rejected:** Python as core despite attractive donor code. Python donors may inform algorithms or remain external tools, but Sentrdel's canonical schemas, store, graph, policy, guard, review and CLI remain Rust.

## R2 — Workspace shape

**Decision:** Start with nine Rust crates:

1. `sentrdel-schema`
2. `sentrdel-store`
3. `sentrdel-graph`
4. `sentrdel-engine`
5. `sentrdel-policy`
6. `sentrdel-guard`
7. `sentrdel-review`
8. `sentrdel-verify` (schema/feature stub only in R1; no execution implementation)
9. `sentrdel-cli`

This matches trust boundaries without premature forge/IDE/benchmark fragmentation. Forge adapters and public SentrdelBench become later packages/repos. SARIF, ASEL and Security Pack protocols live in the versioned schema crate.

## R3 — Structural parsing and matching

**Decision:** Native Rust baseline with `tree-sitter` + `ast-grep-core`/language support.

Observed current ast-grep workspace metadata during review: version 0.45.1, MIT, Rust 1.88 minimum, tree-sitter 0.26.x.

**Use:** deterministic structural detectors, changed-code parsing, provider/framework detection, route/config discovery foundations.

**Do not claim:** compiler-resolved type/dataflow semantics from tree-sitter alone.

## R4 — Git implementation

**Decision:** Prefer `gix`/gitoxide for read-only repository discovery, object traversal and diff plumbing where qualified APIs are adequate.

Observed current `gix` package metadata: MIT OR Apache-2.0, Rust 1.85 minimum. APIs/features are broad and some evolve, so Sentrdel uses a minimal feature set and contract-tests every relied-upon behavior.

**Hard security constraints:**

- target repository hooks never execute;
- external diff/textconv/filter processes never execute during analysis;
- no submodule fetch;
- no credential-helper/network remote operation;
- no repository-controlled external executable may be invoked to "understand" Git state;
- any fallback external `git` command requires a separate explicit qualification and scrubbed environment.

## R5 — Policy engine

**Decision:** `regorus` remains the preferred in-process Rego evaluator, wrapped behind `sentrdel-policy`, with kernel invariants compiled into Rust.

**Minimum:** qualify/pin Regorus >=0.11.0; this release line includes protection against pathological deeply nested input that could otherwise exhaust the stack.

**Sentrdel wrapper requirements:**

- policy source byte cap;
- input/data depth and byte caps;
- tested supported Rego subset/builtin allowlist;
- compile/load outside the per-action hot path;
- bounded evaluation/work where feasible;
- failures at enforcement seams become UNDECIDABLE/fail-closed according to policy.

Kernel invariants are not Rego: evidence integrity, DENY monotonicity and core forbidden boundaries remain Rust-owned.

## R6 — MCP gateway

**Decision:** Use qualified `modelcontextprotocol/rust-sdk` (`rmcp`) model/protocol support but restrict **R1 to stdio MCP only** and own the hostile-input framing boundary.

Observed current SDK state during review: active Apache-2.0 rmcp 3.x line, Rust 1.88 minimum, support for modern MCP protocol revisions and conformance work.

Security review also found reasons not to trust transport defaults blindly:

- a historical Streamable HTTP DNS-rebinding issue required a security patch;
- a current/open stdio transport issue describes unbounded line buffering/memory-exhaustion risk;
- implicit protocol `LATEST`/Default semantics are insufficient for a security gateway when supported conformance versions evolve.

**R1 MCP requirements:**

- stdio only;
- Sentrdel-owned bounded line/frame reader with max frame and buffered-byte limits;
- explicit protocol-version negotiation/allowlist;
- byte/depth caps for tool descriptions, schemas, args and results;
- descriptions/results are untrusted data, never policy instructions;
- unsupported/invalid negotiation fails closed.

Remote/Streamable HTTP MCP is deferred to a later spec with host/DNS-rebinding, redirect, TLS, authentication and egress policy.

## R7 — Canonical store

**Decision:** SQLite via `rusqlite`, WAL mode where appropriate, plus BLAKE3 content addressing.

Rationale: single local file, mature recovery/audit tooling, inspectability, portability and deterministic migrations. The graph does not require a separate graph-database server.

**Secret rule:** discovered secret plaintext is never persisted by default. Do not persist a stable unkeyed digest derived solely from the secret value. Persist rule/type/location/redacted display and sanitized non-secret fingerprints instead.

## R8 — Security graph

**Decision:** thin property/evidence graph using SQLite persistence + `petgraph` in-process projections.

Canonical graph purpose: correlate claims and blast radius, not reimplement compiler semantics.

Initial node classes: project/file/symbol/reference/resource/dependency/workflow/provider/MCP server/tool/agent action/evidence/finding/invariant.

Initial edges: refs/calls (when producer-qualified), depends-on, reads/writes/flows (only with explicit producer provenance), affected-by, evidence-supports, evidence-contradicts, provider-detected, tool-invokes.

Every edge carries producer/provenance/confidence. Compiler/semantic edges imported later through SCIP or qualified engines may outrank heuristic edges without erasing provenance.

**Rejected:** Neo4j/Memgraph as base dependency; custom universal CPG.

## R9 — SCIP

**Decision:** design ingestion support in `sentrdel-graph`, but do not require every language indexer in base v0.1.

Compiler/language-server-derived definitions/references are the scalable route to semantic precision without implementing language semantics inside Sentrdel. Absence of an indexer is a graph-semantic coverage gap, not a clean result.

## R10 — Engine boundary

**Decision:** all external scanners implement:

`EngineManifest + bounded ProcessSpec -> EngineRun -> validated RawResult -> Evidence[] + CoverageRecord`

**Requirements:**

- argv arrays only, never shell strings;
- executable resolution from trusted user/system configuration, never arbitrary repository paths;
- deny-by-default/scrubbed child environment; do not inherit cloud/model/signing/SSH credentials by default;
- cwd/time/process/stdout/stderr caps;
- strict JSON/SARIF parsing;
- repository-relative path normalization;
- producer/version/input hashes recorded;
- non-zero/crash/timeout -> explicit coverage state;
- only reconciler creates Findings.

Base R1 functionality must not require an external scanner.

## R11 — Native baseline security producers

**Decision:** R1 natively provides a small, high-precision baseline rather than competing on rule count.

- secrets: Sentrdel-owned/qualified high-signal rule data; never persist values;
- structural code patterns: Sentrdel-owned ast-grep-core rules;
- dependency delta: supported lockfile parsing + OSV-compatible advisory source under explicit network policy with offline fixtures;
- GitHub Actions high-signal detector.

### GitHub Actions detector scope

At minimum detect/candidate-label changes involving:

- repository/workflow permission widening;
- `id-token: write`/OIDC-sensitive changes;
- secrets in untrusted PR paths;
- `pull_request_target` plus attacker-controlled checkout/execution;
- untrusted expression interpolation into shell/run;
- mutable action refs vs full commit-SHA pinning;
- self-hosted runners used with untrusted contributions;
- artifact/cache handoff changes where a trust boundary may have moved.

This is not complete workflow verification; coverage must say so.

## R12 — Optional LLM reasoning

**Decision:** provider-neutral adapter trait over HTTP/local endpoints; optional compile/runtime feature. No SDK becomes part of canonical security semantics.

Prefer extracted evidence/substrate and bounded code snippets over raw repository dumps.

Adapters can emit only `INFERENCE`/`HYPOTHESIS`. The Rust schema/deserializer makes epistemic escalation invalid.

## R13 — ASEL

**Decision:** Agent Security Event Log is a versioned open schema in `sentrdel-schema` from R1.

Envelope: version, sequence, timestamp, session, actor, kind, intent/target metadata, parameter/result digests, policy verdict, provenance, previous-event hash, event hash.

Privacy: raw prompts/tool content are not persisted by default; sensitive payloads are digested/redacted before append.

### Integrity semantics

A hash chain provides internal linkage and replay verification relative to a trusted head/checkpoint. It does not by itself prove that an attacker with full local write access did not replace or truncate both history and head.

R1 output therefore uses terms such as `chain-valid`, `integrity-linked` and `head hash`, not `tamper-proof`. Signing/remote attestation is later work.

## R14 — Finding lifecycle

**Decision:** two independent axes.

Epistemic: `DETECTED`, `CORROBORATED`, `CONTESTED`, `PROVEN`, `UNPROVEN`, `UNVERIFIABLE`.

Workflow: `NEW`, `TRIAGED_FIX_NOW`, `TRIAGED_DEFER`, `ACCEPTED`, `SUPPRESSED`, `FIX_PROPOSED`, `FIX_VERIFIED`, `FIX_REGRESSED`, `CLOSED`.

Risk acceptance requires owner, reason and expiry; automated LLM suppression is prohibited.

## R15 — Evidence epistemic precision

`FACT` is reserved for a directly observable bounded property, e.g. a literal/rule match, manifest field, lockfile entry or parsed configuration value. A producer must not encode a semantic security conclusion as FACT merely because detection was deterministic.

Where useful, Evidence separates:

- direct observation/basis;
- security interpretation/claim;
- producer authority/provenance.

Runtime/test measurement is OBSERVATION. Independent bounded reproduction is VERIFIED only under a later Verify authority.

## R16 — Security Packs and Supabase

**Decision after major review:** R1 defines pack contract/detection; **R2 is now the Supabase P0 Static/Posture Pack** rather than waiting until after a general business-logic slice.

A Security Pack contains manifest/version/provenance, detection rules, declared evidence capabilities/coverage dimensions and optional native/external requirements; it cannot create Findings or weaken policy.

### Supabase R2 offline/static target

Deterministic review of repository/migration/config/client evidence for:

- RLS enabled/missing-policy posture;
- grants and function EXECUTE exposure;
- SECURITY DEFINER/view/function and mutable search_path patterns;
- exposed schemas/sensitive-column indicators;
- service-role/secret-key browser/client exposure;
- Storage bucket/policy/public-listing/ownership signals;
- Auth/config posture that is statically observable.

Optional credentialed live posture is a separate explicit mode later. R3 business-logic/invariants then adds cross-layer tenant/authz reasoning.

## R17 — Donor project decisions

### Graphify-Labs/graphify

STUDY/ADAPT concepts selectively: confidence labels, incremental graph update, graph diff, affected/blast-radius traversal and reporting ergonomics. Do not run a second canonical graph or make its Python runtime a base dependency.

### vitali87/code-graph-rag

STUDY/ADAPT concepts: resource nodes, data-flow vocabulary, static/runtime edge merge, multi-language graph schema lessons and tracing evidence model. Do not adopt Python+Memgraph as trusted core or treat heuristic flow as verdict-quality fact.

### deepseek-ai/deepseek-harness

STUDY/ADAPT architecture: durable session events, pre/execute/post tool pipeline, monotonic guards, approvals and sandbox/capability seams. Do not fork/couple to its rapidly evolving runtime.

### continuedev/continue

Later integration reference for VS Code/JetBrains/CLI/diff/editor abstractions; do not fork the archived product wholesale.

Every source still needs exact file/commit/license qualification before reuse.

## R18 — Verification

No execution verification in R1. `sentrdel-verify` may exist only as a domain/feature placeholder if needed to keep schema boundaries stable.

R6 must independently specify authorization, isolation tiers, network default-deny, synthetic data, time/process/memory limits, mocked external services, evidence retention and platform support before executable verification lands.

## R19 — Performance architecture

Design for incremental work from the first implementation:

- content hashes for invalidation;
- diff-first review path;
- cache parse/rule results by `(file_hash, producer_version)`;
- SQLite WAL and bounded transactions;
- `rayon` for CPU-bound parse/rule work;
- `tokio` for bounded external/network I/O;
- background daemon deferred until CLI contracts stabilize.

## R20 — Licensing and source qualification

**Core license frozen:** **Apache-2.0**.

Before donor source/data reuse record upstream repository, exact commit/tag, exact source files/data, license/notices, transitive/embedded licensing, maintenance/security status, integration boundary, modifications and verification tests.

The license decision does not make every donor automatically compatible.

## R21 — Sentrdel's own dependency governance

Required for R1:

- committed lockfile after dependencies exist;
- `cargo-audit` + `cargo-deny` CI;
- dependency justification/source-qualification ledger;
- explicit attention to build scripts/proc macros/native/download behavior;
- root `SECURITY.md` defining Sentrdel's own scope, trust boundaries, invariants and known limitations.

`cargo-vet` is optional later for the trusted Sentrdel repository itself. It is not an analyzer to run inside arbitrary untrusted target repositories because Cargo metadata/config resolution may execute repository-controlled tooling.
