# Implementation Plan: Sentrdel v0.1 Evidence + Guard Foundation

**Branch:** `spec/001-v0-1-evidence-guard-foundation` | **Date:** 2026-08-24 | **Spec:** `specs/001-v0-1-evidence-guard-foundation/spec.md`  
**Major review:** `major-review-2026-08-24.md`

## Summary

Build the first useful Sentrdel release as a Rust-first local security evidence/control-plane foundation. The slice ships canonical evidence/finding/coverage/ASEL schemas, integrity-linked SQLite storage, diff-first high-signal review, a thin provenance-aware evidence graph, monotonic policy, a bounded **stdio-only** MCP guard gateway plus git-hook support, project/provider detection, plain-language explanations, and optional hypothesis-only LLM reasoning.

The design deliberately avoids a universal CPG, mandatory cloud services, mandatory external scanners, autonomous exploitation, remote MCP in R1, and premature IDE/provider breadth. Future A-to-Z Security Packs plug into the same evidence contract; Supabase is accelerated to the first dedicated post-R1 provider spec.

## Technical Context

**Language/Version:** **Rust 1.98.0 exact pin for R1**  
**Primary Dependencies:** `clap`, `serde`, `serde_json`, `schemars`, `tokio`, `rayon`, `thiserror`, `tracing`, `blake3`, `rusqlite`, `petgraph`, `tree-sitter`, `ast-grep-core`/qualified language crates, minimal-feature `gix`, `regorus >=0.11.0`, qualified `rmcp` protocol/model support, `regex`, `ignore`, `walkdir`, `moka` only where justified  
**Storage:** SQLite + content-addressed BLAKE3 objects; secret values excluded  
**Testing:** `cargo test`, contract/property/adversarial tests, fixture repositories, golden output where stable, fuzz/property tests for parsers/monotonicity/bounded framing where practical  
**Target Platform:** Review/init: Linux, macOS, Windows. Guard enforcement fidelity is seam-specific and MUST be reported. R1 MCP gateway is stdio only.  
**Project Type:** Rust CLI/workspace security tool  
**Performance Goals:** warm native diff review <5s p95 for <2k changed LOC; broader 100k LOC warm review <30s; MCP guard policy <50ms p95 excluding downstream tool/human time  
**Constraints:** local-first; no required cloud/model/external scanner; no target build/install/Cargo execution during analysis; no shell-string subprocesses; child environments scrubbed/allowlisted; missing engines become coverage gaps; LLM cannot become fact/verifier/policy authority  
**Scale/Scope:** small developer repos through ~100k LOC initial benchmark, larger monorepos via incremental/diff-first design

## Constitution Check

| Principle | Gate | Plan status |
|---|---|---|
| Rust Trusted Core | Security-critical core lives in Rust; external tools behind bounded contracts | PASS |
| Evidence Before Verdict | FACT is direct observation only; Findings reconciled; epistemic classes explicit | PASS |
| Vendor-Neutral, Local-First | CLI/stdio MCP/git seams; no mandatory vendor/cloud | PASS |
| Honest/Monotonic Guardrails | Fidelity + absorbing DENY + fail-closed undecidable | PASS |
| Safe Verification | Execution verification excluded from R1 | PASS |
| A-to-Z through Packs | Pack contract + detection now; Supabase R2 posture next | PASS |
| Reuse Mature Infrastructure | Qualified Rust-native foundations + clean external engine boundary | PASS |
| FP/False-Block/Latency Quality | release metrics specified and testable | PASS |
| Sentrdel Secures Itself | hostile repo/engine/MCP/model/dependency inputs bounded and typed | PASS |
| Spec Kit Governance | bounded R1 slice under spec-of-specs + major review applied | PASS |

**Gate result:** PASS. No constitutional exception is required for R1.

## Architecture

```text
                          sentrdel-cli
                               |
            +------------------+------------------+
            |                  |                  |
        review/init          guard             explain
            |                  |                  |
    sentrdel-review      sentrdel-guard      reconciled state
            |                  |
            +--------+---------+
                     |
             sentrdel-policy
                     |
        +------------+------------+
        |            |            |
 sentrdel-graph  sentrdel-engine  sentrdel-store
        |            |            |
        +------------+------------+
                     |
              sentrdel-schema

External producers --> sentrdel-engine --> validated Evidence
MCP stdio client --> bounded Sentrdel framing --> guard/policy --> MCP server
Git/diff/native producers --> review/graph --> Evidence
Only reconciler --> Finding
```

### Trust boundaries

1. **Repository boundary:** paths/files/config/git metadata are untrusted; no target tools execute to interpret them.
2. **Engine boundary:** executable identity, child environment and output are untrusted/bounded.
3. **MCP boundary:** framing, descriptions, schemas, arguments, results and server identity are untrusted and byte/depth bounded.
4. **LLM boundary:** output is untrusted INFERENCE/HYPOTHESIS only.
5. **Policy boundary:** repo policy cannot widen user/core policy; Regorus inputs/policies are size/depth bounded.
6. **Persistence boundary:** secrets are removed before storage; hash chains are integrity-linked relative to trusted heads, not claimed tamper-proof.
7. **Dependency/build boundary:** Sentrdel's own build scripts/proc macros/native/download dependencies are privileged supply-chain code and require qualification.

## Project Structure

```text
.
├── Cargo.toml
├── Cargo.lock                  # once dependencies exist
├── rust-toolchain.toml         # 1.98.0
├── README.md
├── LICENSE                     # Apache-2.0
├── SECURITY.md
├── AGENTS.md
├── deny.toml
├── .cargo/config.toml
├── .specify/
│   └── memory/constitution.md
├── specs/
│   ├── 000-sentrdel-roadmap/
│   └── 001-v0-1-evidence-guard-foundation/
├── crates/
│   ├── sentrdel-schema/
│   ├── sentrdel-store/
│   ├── sentrdel-graph/
│   ├── sentrdel-engine/
│   ├── sentrdel-policy/
│   ├── sentrdel-guard/
│   ├── sentrdel-review/
│   ├── sentrdel-verify/
│   └── sentrdel-cli/
├── rules/
│   ├── structural/
│   ├── secrets/
│   └── providers/
├── fixtures/
│   ├── repos/
│   ├── engines/
│   ├── mcp/
│   └── policies/
├── schemas/
├── docs/
│   ├── architecture/
│   ├── security/
│   └── third-party/
└── tests/
    ├── contract/
    ├── integration/
    ├── adversarial/
    └── benchmark/
```

## Crate Responsibilities

### `sentrdel-schema`

Versioned Evidence, Finding, CoverageRecord, ASEL, PolicyDecision/Fidelity, Engine/Pack/Profile and graph interchange types + JSON Schema generation. No subprocess/filesystem mutation/network/policy evaluation.

**Epistemic invariant:** FACT represents only direct bounded observations. Producer security interpretations remain INFERENCE/HYPOTHESIS unless stronger authority exists.

### `sentrdel-store`

SQLite migrations, content-addressed Evidence, Finding projections/history, coverage/profiles, ASEL chain/head verification, transactional APIs and redaction-before-persist boundary.

**Secret invariant:** no discovered plaintext secret and no stable unkeyed digest derived solely from the secret value is persisted by default.

### `sentrdel-graph`

Stable property/evidence graph identities, provenance/confidence, SQLite mapping, petgraph projections, graph diff, reverse blast radius and optional SCIP ingestion. No universal AST/CFG/type duplication.

### `sentrdel-engine`

Only crate allowed to spawn external evidence engines. Owns Engine trait, executable manifest resolution, argv-only subprocesses, **scrubbed/allowlisted environment**, cwd/time/process/output bounds, strict result adapters, path normalization, failure→Coverage mapping and parallel orchestration.

### `sentrdel-policy`

Rust kernel invariants, monotonic composition, bounded Regorus adapter, ALLOW/ASK/DENY/UNDECIDABLE lattice and repository-config narrowing validation. Kernel invariants cannot be overridden by Rego.

### `sentrdel-guard`

ASEL append API, **bounded stdio MCP gateway**, explicit MCP protocol-version negotiation, MCP server/tool inventory/hashes, preflight policy, scoped approvals, git-hook installation contract and fidelity reporting.

Remote/Streamable HTTP MCP and PATH shims are deferred from R1.

### `sentrdel-review`

Safe repository/profile detection, non-executing Git diff selection, native producers, structural rules, secret evidence, dependency/advisory deltas, CI-sensitive changes, pack detection/dispatch, evidence correlation/reconciliation, explanations and optional reasoner.

Git analysis must not execute hooks, external diff/textconv/filter drivers, submodule fetches, credential helpers or network operations.

### `sentrdel-verify`

R1 domain/feature boundary only. No sandbox execution, exploit logic, network probes or VERIFIED producer.

### `sentrdel-cli`

`init`, `review`, `explain`, `guard mcp`, `guard install-git-hooks`, evidence diagnostics/chain verification. Stable human + JSON behavior and exit codes.

## Data Flow — Review

```text
git diff / bounded project files
      |
      +--> structural/security producers --------+
      +--> dependency delta/advisory producer ---+--> Evidence[]
      +--> CI-sensitive change producer ---------+
      +--> optional external Engine producers ---+
      +--> project/provider detectors -----------+--> Coverage + Profile
                                                  |
                                                  v
                                             Evidence Store
                                                  |
                                                  v
                                        Evidence Graph / Correlator
                                                  |
                                                  v
                                               Findings
                                                  |
                                           CLI decision/output
```

## Data Flow — MCP Guard

```text
agent MCP client
      |
      v
bounded stdio framing
      |
      v
explicit protocol negotiation
      |
      v
normalize event --> kernel invariants --> composed bounded policy
      |                                      |
      |                              ALLOW / ASK / DENY /
      |                                 UNDECIDABLE
      v                                      |
ASEL append <---------------------------------+
      |
      +--> forward only if policy permits --> real stdio MCP server
      |
      +<-- bounded untrusted result ----------+
      v
ASEL result event --> client
```

## Phase 0 — Governance and source controls

- Apache-2.0 core license is frozen.
- Create source/dependency qualification policy and ledger.
- Add root `SECURITY.md` and `AGENTS.md` before feature implementation.
- Pin Rust 1.98.0; commit lockfile after dependency resolution.
- Establish cargo-audit/cargo-deny and elevated checks for build.rs/proc-macro/native/download dependencies.
- Define Security Pack/Engine/Evidence/CLI contracts before provider breadth.

## Phase 1 — Foundational trusted substrate

- workspace/toolchain/CI/lints/deny configuration;
- schema/store/content addressing/redaction;
- evidence/ASEL/finding/coverage types;
- graph primitives/provenance;
- Rust kernel + bounded Regorus;
- scrubbed external engine runner;
- bounded stdio framing primitives needed by Guard.

**Blocking gate:** no user-story implementation until schema/store/policy/engine/graph/CLI contracts pass tests.

## Phase 2 — US1 Review

- read-only Git diff with no repository execution surfaces;
- native structural parsing/matching;
- high-signal secret/structural/dependency/GitHub Actions producers;
- expanded Actions candidates: permissions, OIDC, pull_request_target, untrusted shell interpolation, action pinning, self-hosted runner/trust handoffs;
- Evidence correlation + Findings;
- plain-language output and coverage gaps.

## Phase 3 — US2 Guard

- qualified rmcp protocol/model integration;
- Sentrdel-owned bounded stdio framing;
- explicit protocol negotiation;
- tool inventory/hash model;
- pre-invocation policy;
- ASEL linked events and chain/head verification;
- approvals/deny/undecidable;
- git-hook installation with PARTIAL fidelity.

## Phase 4 — US3 Init / project profile

- bounded traversal;
- language/ecosystem/CI/MCP/provider detection;
- Security Pack manifest/coverage dimensions;
- Supabase detection fixture without security verdict claims.

## Phase 5 — US4 Explain

Three-tier finding rendering, evidence/provenance subtree and evidence-linked remediation guidance.

## Phase 6 — US5 Optional reasoner

Provider-neutral trait; explicit local/remote config; strict INFERENCE/HYPOTHESIS output; hostile-repo/prompt fixtures; deterministic path never depends on a model.

## Phase 7 — Hardening and release qualification

- FP/false-block/latency/resource benchmark gates;
- Linux/macOS/Windows base CI;
- self-security/dependency/license/source-qualification gates;
- malformed MCP/engine/repo/policy adversarial tests;
- Spec Kit final consistency pass and implementation closeout.

## Error and Coverage Semantics

A review is not internally a boolean secure/insecure. It contains findings by action/severity/proof, coverage dimensions, producer failures/unavailable states and policy decisions where applicable.

CLI distinguishes success/no block, security block, usage/config error, incomplete/undecidable analysis and internal failure according to the CLI contract.

## Testing Strategy

### Unit

Schema validity, hashing/canonicalization, secret redaction, graph identity/traversal, policy lattice, Regorus caps, MCP bounded framing/version negotiation, engine parsers, project detectors.

### Contract

JSON schema round-trip, ASEL chain/head integrity, Engine/Pack authority boundaries, LLM authority, CLI envelope, scrubbed engine environment and MCP protocol bounds.

### Integration

Fixture git repos, stdio MCP fixture client/server, git hooks, offline advisories, Supabase-detected-but-not-covered fixture.

### Adversarial

- prompt injection in source/MCP descriptions/results;
- oversized/malformed MCP frame and slow/unterminated stdio input;
- malformed/oversized engine JSON;
- subprocess environment secret canaries;
- path traversal/symlink/confusable filenames;
- hostile Git external diff/textconv/filter/submodule/network config;
- repo policy trying to weaken kernel invariants;
- Regorus deep/oversized policy/input;
- DENY downgrade attempts;
- event-chain replacement/truncation semantics relative to trusted head;
- large diff/blob caps.

## Source Adoption and Dependency Controls

No donor source/rules enter implementation until a ledger records exact origin/license/security boundary. Concepts may be independently reimplemented when appropriate. Every external engine remains evidence-only.

Sentrdel-owned dependencies are also supply-chain inputs. `build.rs`, proc macros, native libraries and download-at-build patterns require explicit justification.

## Complexity Tracking

| Potential complexity | Why needed | Simpler alternative rejected because |
|---|---|---|
| Nine-crate workspace | isolates trust boundaries | one crate makes authority boundaries implicit |
| Evidence + Finding separation | epistemic discipline/correlation | scanner result = finding recreates noise |
| SQLite + petgraph | local auditability + algorithms | graph server breaks local single-tool UX |
| Rego + Rust kernel | extensibility + non-overridable invariants | Rego-only kernel is too mutable |
| Sentrdel-owned stdio framing | hostile MCP input needs strict memory bounds independent of SDK transport defaults | delegating framing blindly violates guard threat model |

## Post-Major-Review Constitution Re-check

**PASS.** Rust 1.98.0, Apache-2.0, stdio-only bounded MCP, dependency/build-script hardening, precise integrity language and accelerated Supabase roadmap strengthen rather than expand R1 unsafely. No universal CPG, remote MCP, executable verification, live provider credential access or broad provider implementation has re-entered R1.
