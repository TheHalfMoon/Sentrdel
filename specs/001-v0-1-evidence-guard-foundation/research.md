# Research — Sentrdel v0.1 Evidence + Guard Foundation

**Date:** 2026-08-24  
**Status:** RESEARCH_COMPLETE  
**Scope:** Decisions needed to plan R1. Source adoption remains subject to exact commit/file/license qualification before copying donor source.

## R0 — External adversarial review disposition

The independent cybersecurity architecture review returned **GO WITH MAJOR CHANGES**. R1 accepts the major changes that improve truthfulness and delivery:

- Guard is environment/protocol control at seams Sentrdel can actually control, not fictional universal agent interception.
- The canonical graph is an evidence/property graph, not a home-grown universal CPG.
- Evidence and event schemas are first-class products.
- LLM reasoning is epistemically second-class.
- Verification is deferred and later constrained to bounded test execution.
- Business-logic security remains strategic but depends on R1's substrate.

## R1 — Trusted implementation language

**Decision:** Rust for the trusted core.

**Rationale:** The product requires a small auditable distribution, deterministic resource control, safe parsing, concurrency, cross-platform CLI support, and strong type-level separation between untrusted producer data and canonical security state.

**Rejected:** Python as core despite attractive donor code. Python donors may inform algorithms or remain external tools, but Sentrdel's canonical schemas, store, graph, policy, guard, review, and CLI remain Rust.

**Initial Rust floor:** target Rust **1.88+** for R1 because current `ast-grep` workspace metadata and the official MCP Rust SDK require Rust 1.88. The exact MSRV MUST be pinned in `rust-toolchain.toml` during implementation and CI-tested.

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

**Rationale:** This matches trust boundaries without premature forge/IDE/benchmark fragmentation. Forge adapters and SentrdelBench become later packages/repos. SARIF, ASEL and Security Pack protocols live in the versioned schema crate.

## R3 — Structural parsing and matching

**Decision:** Native Rust baseline with `tree-sitter` + `ast-grep-core`/language support.

**Current qualification observation:** `ast-grep` is a Rust workspace under MIT, with `ast-grep-core` as a first-class crate; current repository metadata observed on 2026-08-24 shows workspace version 0.45.1, Rust 1.88, and tree-sitter 0.26.x.

**Use:** deterministic structural detectors, changed-code parsing, provider/framework detection, route/config discovery foundations.

**Do not claim:** compiler-resolved type/dataflow semantics from tree-sitter alone.

## R4 — Git implementation

**Decision:** Prefer `gix` (gitoxide) for read-only repository discovery, object traversal, status/diff plumbing where the required APIs prove adequate; permit a tightly scoped fallback or direct `git` subprocess only after qualification if a required operation is missing.

**Current qualification observation:** `gix` is the Rust library entry point for gitoxide and is licensed `MIT OR Apache-2.0`; observed current package metadata requires Rust 1.85. Its own documentation describes several subcrates/API surfaces as still evolving, so R1 MUST contract-test every Git operation Sentrdel relies on.

**Security rule:** target repository hooks are never executed by analysis. No string-built git shell commands.

## R5 — Policy engine

**Decision:** `regorus` as the preferred in-process Rego evaluator, wrapped behind `sentrdel-policy` and kernel invariants compiled into Rust.

**Current qualification observation:** Microsoft's Regorus is a cross-platform Rust Rego interpreter; observed latest release line includes 0.11.0 in July 2026. It is intended to track OPA/Rego semantics but does not support every builtin, so Sentrdel policy MUST use a tested supported subset.

**Why not ship OPA binary by default:** local-first single-binary UX and smaller external runtime surface.

**Kernel invariants are not Rego:** rules that protect Sentrdel evidence logging, action-scope DENY monotonicity, forbidden path/secret boundaries, and core enforcement integrity must remain Rust-owned and impossible for repository policy to override.

## R6 — MCP gateway

**Decision:** Build `sentrdel guard mcp` using the official `modelcontextprotocol/rust-sdk` (`rmcp`) after implementation-time conformance qualification.

**Current qualification observation:** the official Rust SDK is active, Tokio-based, Apache-2.0, and its current workspace metadata observed on 2026-08-24 is version 3.0.1 with Rust 1.88. MCP documentation currently classifies the Rust SDK as Tier 2. The SDK supports server/client roles and local/remote transports.

**Guard role:** Sentrdel acts as a gateway, inventories and hash-pins tool metadata where configured, treats descriptions/results as untrusted, evaluates policy before invocation, records ASEL events, and forwards only allowed/approved calls.

## R7 — Canonical store

**Decision:** SQLite via `rusqlite`, WAL mode where appropriate, plus BLAKE3 content addressing.

**Rationale:** single local file, mature recovery/audit tooling, inspectability, portability, deterministic migrations. The graph does not require a separate graph-database server.

**Stored objects:** Evidence, Findings, CoverageRecords, ASEL event chain metadata, ProjectProfile, policy/engine manifests, graph nodes/edges, source qualification metadata.

**Secret rule:** persist redacted identifiers/digests only, not discovered plaintext values by default.

## R8 — Security graph

**Decision:** thin property graph using SQLite persistence + `petgraph` in-process projections for algorithms.

**Canonical graph purpose:** correlate claims and blast radius, not reimplement compiler semantics.

**Initial node classes:** project/file/symbol/reference/resource/dependency/workflow/provider/MCP server/tool/agent action/evidence/finding/invariant.

**Initial edges:** refs/calls (when producer-qualified), depends-on, reads/writes/flows (only with explicit producer provenance), affected-by, evidence-supports, evidence-contradicts, provider-detected, tool-invokes.

Every edge MUST carry producer/provenance/confidence information. Compiler/semantic edges imported later through SCIP or qualified engines can outrank heuristic edges without erasing the latter's provenance.

**Rejected:** Neo4j/Memgraph as base dependency; custom universal CPG.

## R9 — SCIP

**Decision:** design ingestion support in `sentrdel-graph`, but do not require every language indexer in base v0.1.

**Rationale:** compiler/language-server-derived definitions/references are the scalable way to increase semantic precision without implementing language semantics inside Sentrdel.

**Coverage rule:** absence of an indexer is a graph-semantic coverage gap, not a clean result.

## R10 — Engine boundary

**Decision:** all external scanners implement the same conceptual contract:

`EngineManifest + bounded ProcessSpec -> EngineRun -> validated RawResult -> Evidence[] + CoverageRecord`

**Requirements:**

- argv arrays only, never shell strings;
- fixed executable resolution from user/system config, not repository-controlled arbitrary path;
- cwd boundaries;
- timeout/process/output-byte caps;
- strict JSON/SARIF parsing;
- repository-relative path normalization;
- producer/version/input hashes recorded;
- non-zero/crash/timeout -> explicit coverage state;
- only reconciler creates Findings.

**v0.1 external engine strategy:** base functionality must not require any external scanner. External adapters may be introduced behind feature/config gates after source qualification.

## R11 — Native baseline security producers

**Decision:** R1 should natively provide a small, high-precision baseline rather than compete on rule count.

Candidate baseline producers:

- secrets: qualify permissive Gitleaks-style rule data and/or write a small Sentrdel-owned high-signal ruleset; do not persist values;
- structural code patterns: Sentrdel-owned `ast-grep-core` rules for a small high-signal set;
- dependency delta: parse supported lockfiles and query a cached OSV-compatible advisory source through an explicit network policy; fixtures must support fully offline tests;
- CI security-sensitive change detector: identify workflow permission/secrets/OIDC/untrusted-PR/action-reference changes as evidence/candidates, without claiming full workflow security in R1.

## R12 — Optional LLM reasoning

**Decision:** provider-neutral adapter trait over HTTP/local endpoints; optional compile/runtime feature. No SDK becomes part of canonical security semantics.

**Input principle:** prefer extracted evidence/substrate and bounded code snippets over dumping the repository into a prompt.

**Output constraint:** adapters can only emit `INFERENCE`/`HYPOTHESIS` evidence. The Rust schema/deserializer MUST make invalid epistemic escalation impossible.

## R13 — ASEL

**Decision:** define Agent Security Event Log as a versioned open schema in `sentrdel-schema` from R1.

**Envelope:** version, sequence, timestamp, session, actor, kind, intent/target metadata, parameter/result digests, policy verdict, provenance, previous-event hash, event hash.

**Privacy:** raw prompts/tool content are not persisted by default. Sensitive payloads are digested/redacted before append.

**Tamper evidence:** chain event hashes; a session head hash can later be signed/attested.

## R14 — Finding lifecycle

**Decision:** two independent axes.

**Epistemic:** `DETECTED`, `CORROBORATED`, `CONTESTED`, `PROVEN`, `UNPROVEN`, `UNVERIFIABLE`.

**Workflow:** `NEW`, `TRIAGED_FIX_NOW`, `TRIAGED_DEFER`, `ACCEPTED`, `SUPPRESSED`, `FIX_PROPOSED`, `FIX_VERIFIED`, `FIX_REGRESSED`, `CLOSED`.

Risk acceptance requires owner, reason, expiry and future signature support. Automated LLM suppression is prohibited.

## R15 — Security Packs and Supabase

**Decision:** R1 defines only the pack contract and provider detection. Full provider analysis is R3.

A Security Pack contains:

- manifest/version/provenance;
- detection rules;
- declared evidence capabilities and coverage dimensions;
- optional native rules and/or external-engine requirements;
- no direct ability to create canonical Findings or weaken policy.

**Supabase P0 pack target for R3:** RLS, grants, exposed schemas, Auth/JWT boundaries, service-role usage/client exposure, Storage policies/buckets, migrations/functions/views/security-definer/search-path patterns, Edge Functions and relevant secrets/config.

## R16 — Donor project decisions

### Graphify-Labs/graphify

**Use:** STUDY/ADAPT concepts selectively: confidence labels, incremental graph update, graph diff, affected/blast-radius traversal, architecture-reporting ergonomics.

**Do not:** run a second canonical graph or make its Python runtime a base dependency.

**License note:** earlier live repository inspection found both Apache-2.0 and MIT license artifacts; exact file-level qualification is still mandatory before reuse.

### vitali87/code-graph-rag

**Use:** STUDY/ADAPT concepts: resource nodes, data-flow vocabulary, static/runtime edge merge, multi-language graph schema lessons, tracing evidence model.

**Do not:** adopt Python+Memgraph as trusted core or treat heuristic flow as verdict-quality fact.

**License note:** earlier live repository inspection found MIT at repository level; exact source qualification remains mandatory.

### deepseek-ai/deepseek-harness

**Use:** STUDY/ADAPT architecture: durable session events, pre/execute/post tool pipeline, monotonic guards, approvals, sandbox/capability seams.

**Do not:** fork the harness or couple Sentrdel to its rapidly evolving plugin runtime.

**License note:** earlier live repository inspection found MIT at repository level.

### continuedev/continue

**Use:** later integration reference for VS Code/JetBrains/CLI/diff/editor abstractions.

**Do not:** fork the archived product wholesale into R1.

**License note:** earlier live repository inspection found Apache-2.0 at repository level.

## R17 — Verification

**Decision:** no execution verification in R1. `sentrdel-verify` may exist only as a compile-time/domain placeholder if necessary to keep schema boundaries stable.

R5 must independently specify authorization, isolation tiers, network default-deny, synthetic data, time/process/memory limits, mocked external services, evidence retention, and platform support before executable verification lands.

## R18 — Performance architecture

**Decision:** design for incremental work from the first implementation.

- content hashes for file/parser invalidation;
- diff-first review path;
- cache parse/rule results by `(file_hash, producer_version)`;
- SQLite WAL and bounded transactions;
- `rayon` for CPU-bound parse/rule work;
- `tokio` for bounded external/network I/O;
- background daemon deferred until CLI contracts stabilize, but storage/protocol choices must not preclude it.

## R19 — Licensing and source qualification

**Decision:** do not copy donor source until the core license and source-adoption policy are frozen.

Before reuse record:

- upstream repository;
- exact commit/tag;
- exact source files/data;
- license + notices;
- transitive/embedded licensing where relevant;
- maintenance/security status;
- integration boundary;
- changes made;
- tests proving behavior/provenance.

This is a release/governance gate, not optional documentation.
