# Implementation Plan: Sentrdel v0.1 Evidence + Guard Foundation

**Branch:** `spec/001-v0-1-evidence-guard-foundation` | **Date:** 2026-08-24 | **Spec:** `specs/001-v0-1-evidence-guard-foundation/spec.md`

## Summary

Build the first useful Sentrdel release as a Rust-first local security judgment and guardrail foundation. The slice ships canonical evidence/finding/coverage/ASEL schemas, a tamper-evident SQLite store, diff-first high-signal review, a thin provenance-aware evidence graph, monotonic policy, an MCP guard gateway plus git-hook support, project/provider detection, plain-language explanations, and optional hypothesis-only LLM reasoning.

The design deliberately avoids a universal CPG, mandatory cloud services, mandatory external scanners, autonomous exploitation, and premature IDE/provider breadth. Future Supabase and A-to-Z provider packs plug into the same Security Pack evidence contract rather than bypassing the trusted core.

## Technical Context

**Language/Version:** Rust 1.88+ initially; pin exact toolchain during setup  
**Primary Dependencies:** `clap`, `serde`, `serde_json`, `schemars`, `tokio`, `rayon`, `thiserror`, `tracing`, `blake3`, `rusqlite`, `petgraph`, `tree-sitter`, `ast-grep-core`/language crates, `gix`, `regorus`, official MCP `rmcp`, `regex`, `ignore`, `walkdir`, `moka` as justified  
**Storage:** SQLite + content-addressed BLAKE3 objects  
**Testing:** `cargo test`, contract/property tests, fixture repositories, snapshot/golden output where stable, fuzz/property tests for parsers/monotonicity where practical  
**Target Platform:** Review/init: Linux, macOS, Windows. Guard enforcement fidelity is seam-specific and MUST be reported.  
**Project Type:** Rust CLI/workspace security tool  
**Performance Goals:** warm native diff review <5s p95 for <2k changed LOC; broader 100k LOC warm review <30s; MCP guard policy <50ms p95 excluding downstream tool/human time  
**Constraints:** local-first; no required cloud/model/external scanner; no target build/install execution during analysis; no shell-string subprocesses; missing engines become coverage gaps; LLM cannot become fact/verifier/policy authority  
**Scale/Scope:** developer repositories from small projects to ~100k LOC initial benchmark, with architecture designed for larger monorepos via incremental/diff-first operation

## Constitution Check

| Principle | Gate | Plan status |
|---|---|---|
| Rust Trusted Core | Security-critical core lives in Rust; external tools behind bounded contracts | PASS |
| Evidence Before Verdict | Evidence immutable; Findings reconciled; epistemic classes explicit | PASS |
| Vendor-Neutral, Local-First | CLI/MCP/git seams; no mandatory vendor/cloud | PASS |
| Honest/Monotonic Guardrails | Enforcement fidelity + absorbing DENY + fail-closed undecidable | PASS |
| Safe Verification | Execution verification excluded from R1 | PASS |
| A-to-Z through Packs | Pack contract + provider detection now; full packs later | PASS |
| Reuse Mature Infrastructure | Rust-native foundations and external engine contract; provenance gate | PASS |
| FP/False-Block/Latency Quality | release metrics specified and testable | PASS |
| Sentrdel Secures Itself | untrusted repo/engine/MCP/model inputs bounded and typed | PASS |
| Spec Kit Governance | bounded R1 slice under spec-of-specs | PASS |

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
MCP clients/tools  --> sentrdel-guard  --> ASEL + PolicyDecision
Git/diff/native producers --> review/graph --> Evidence
Only reconciler --> Finding
```

### Trust boundaries

1. **Repository boundary:** all paths/files/config/git metadata are untrusted.
2. **Engine boundary:** external executable and its output are untrusted.
3. **MCP boundary:** tool descriptions, arguments, results and server identity are untrusted.
4. **LLM boundary:** output is untrusted hypothesis/inference only.
5. **Policy boundary:** repo policy cannot widen user/core policy.
6. **Persistence boundary:** secrets are redacted before storage; hashes/provenance make history tamper-evident.

## Project Structure

```text
.
├── Cargo.toml
├── rust-toolchain.toml
├── README.md
├── LICENSE                     # founder freeze required before donor source copy/release
├── deny.toml
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
├── schemas/                    # generated/published JSON schemas
├── docs/
│   ├── architecture/
│   ├── security/
│   └── third-party/
└── tests/
    ├── contract/
    ├── integration/
    └── adversarial/
```

**Structure Decision:** one Rust workspace with nine bounded crates. No separate web/forge/IDE project in R1.

## Crate Responsibilities

### `sentrdel-schema`

Owns versioned types and schema generation for:

- Evidence / EpistemicClass
- Finding / epistemic + workflow axes
- CoverageRecord
- ASEL Event
- PolicyDecision / EnforcementFidelity
- EngineManifest / EngineRun metadata
- SecurityPackManifest
- ProjectProfile
- graph interchange types
- SARIF ingestion mapping interfaces

No subprocesses, filesystem mutation, network calls or policy evaluation.

### `sentrdel-store`

Owns:

- SQLite schema/migrations;
- BLAKE3 content addressing;
- immutable Evidence persistence;
- Finding projections/history;
- coverage/project profiles;
- ASEL chain persistence/head hashes;
- transactional APIs;
- redaction-before-persist boundary.

### `sentrdel-graph`

Owns:

- stable graph node/edge identities;
- provenance/confidence per edge;
- SQLite persistence mapping;
- in-process `petgraph` projections;
- changed-symbol/edge diff;
- reverse blast-radius traversal;
- optional SCIP ingestion contract;
- no universal AST/CFG/type duplication.

### `sentrdel-engine`

The only crate allowed to spawn external evidence engines. Owns:

- Engine trait;
- executable/manifest resolution;
- argv-only subprocess construction;
- cwd/time/process/output bounds;
- stdout/stderr capture limits;
- strict result adapters;
- path normalization;
- failure -> CoverageRecord mapping;
- parallel orchestration.

### `sentrdel-policy`

Owns:

- kernel invariants in Rust;
- policy composition;
- Regorus adapter;
- ALLOW/ASK/DENY/UNDECIDABLE lattice;
- monotonic evaluation and proof of DENY non-downgrade;
- repository config narrowing validation.

### `sentrdel-guard`

Owns:

- ASEL append API;
- MCP gateway;
- MCP server/tool inventory and metadata hashes;
- policy preflight for MCP invocation;
- approval state machine;
- git hook installation/handler contract;
- enforcement fidelity reporting.

PATH shims are architecture-ready but MAY be deferred if they would compromise v0.1 quality.

### `sentrdel-review`

Owns:

- repository/project profile detection;
- git diff selection;
- native producer orchestration;
- structural rule evaluation;
- secret candidate generation/redaction;
- dependency-delta/advisory evidence;
- CI-sensitive change evidence;
- Security Pack detection/dispatch contract;
- evidence correlation/reconciliation;
- finding explanation model;
- optional reasoner trait.

### `sentrdel-verify`

R1 owns only domain types/feature boundary needed to avoid future schema churn. No sandbox execution, exploit logic, network probes or `FIX_VERIFIED` producer is implemented in R1.

### `sentrdel-cli`

Owns user surface:

- `sentrdel init`
- `sentrdel review`
- `sentrdel explain <id>`
- `sentrdel guard mcp`
- `sentrdel guard install-git-hooks`
- `sentrdel evidence ...` diagnostics as needed

CLI errors use human-readable diagnostics plus stable exit codes documented in the CLI contract.

## Data Flow

### Review

```text
git diff / project files
      |
      +--> native structural/security producers ----+
      +--> dependency delta/advisory producer ------+--> Evidence[]
      +--> CI-sensitive change producer ------------+
      +--> optional external Engine producers ------+
      +--> project/provider detectors --------------+--> Coverage + Profile
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

### MCP Guard

```text
agent MCP client
      |
      v
Sentrdel gateway --> normalize event --> kernel invariants --> composed policy
      |                                      |
      |                              ALLOW / ASK / DENY /
      |                                 UNDECIDABLE
      v                                      |
ASEL append <---------------------------------+
      |
      +--> forward only if policy permits --> real MCP server
      |
      +<-- untrusted result ------------------+
      v
ASEL result event --> client
```

## Phase 0 — Governance and contracts

- Freeze repository license before donor source copy/release.
- Create third-party/source-qualification policy and ledger format.
- Implement schema crate first and publish generated JSON schemas in-tree.
- Define exit-code and CLI behavior contract.
- Define Security Pack contract before provider-specific implementation.

## Phase 1 — Foundational trusted substrate

- Rust workspace/toolchain/CI/lints/deny configuration.
- Store + migrations + content addressing + redaction.
- Evidence/ASEL/finding/coverage types and property tests.
- Graph primitives and provenance.
- Policy kernel + monotonic composition.
- Engine runner boundary.

**Blocking gate:** no user-story implementation until schema/store/policy/engine contracts pass unit/contract/adversarial tests.

## Phase 2 — US1 Review

- Git diff reader without hook execution.
- Native structural parsing/matching.
- High-signal secret/structural/dependency/CI producers.
- Evidence correlation + findings.
- plain-language primary output.
- coverage-gap reporting.

## Phase 3 — US2 Guard

- Official Rust MCP SDK integration behind Sentrdel adapter.
- tool inventory/hash model.
- pre-invocation policy.
- ASEL chained events.
- approval/deny/undecidable behavior.
- git-hook installation and fidelity labeling.

## Phase 4 — US3 Init / project profile

- bounded repository traversal;
- language/ecosystem/CI/MCP/provider detection;
- Security Pack manifest and coverage matrix;
- Supabase detection fixture without security verdict claims.

## Phase 5 — US4 Explain

- three-tier finding rendering;
- `sentrdel explain` evidence subtree/provenance;
- remediation guidance linked to evidence, not LLM authority.

## Phase 6 — US5 Optional reasoner

- provider-neutral trait;
- local/remote explicit config;
- strict output schema restricted to inference/hypothesis;
- prompt-injection adversarial fixtures;
- no dependency of deterministic review on reasoner availability.

## Phase 7 — Hardening and release qualification

- benchmark fixtures and release gates for FP, false-block, latency and resource use;
- cross-platform CI for base review/init;
- cargo-audit/cargo-deny/SBOM/release provenance planning;
- threat-model validation against malicious repositories, scanner outputs and MCP payloads;
- Spec Kit consistency analysis before implementation closeout.

## Error and Coverage Semantics

A review outcome is not a boolean `secure/insecure` internally. It contains:

- findings by action/severity/proof status;
- coverage dimensions;
- producer failures/timeouts/unavailable states;
- policy decision where applicable.

CLI exit behavior MUST distinguish at least:

- success/no blocking finding;
- blocking security decision;
- usage/configuration error;
- analysis incomplete/undecidable according to command policy;
- unexpected internal failure.

Exact numeric codes are frozen in `contracts/cli-contract.md` before implementation.

## Testing Strategy

### Unit

- schema validation and invalid-state rejection;
- hashing/stable serialization;
- redaction;
- graph identity/traversal;
- policy lattice/monotonicity;
- engine result parsers;
- project detectors.

### Contract

- JSON schemas round-trip;
- ASEL chain integrity;
- Engine adapters cannot bypass canonical evidence;
- Security Pack cannot create Findings;
- LLM result cannot deserialize as FACT/VERIFIED producer authority;
- CLI exit codes and machine-readable output.

### Integration

- fixture git repos with changed vulnerable/clean diffs;
- MCP gateway fixture client/server;
- git hooks;
- offline dependency advisory fixtures;
- Supabase-detected-but-not-covered fixture.

### Adversarial

- prompt injection in source/MCP tool description/result;
- malformed/oversized engine JSON;
- path traversal/symlink/confusable filenames;
- repo config attempting to weaken kernel invariants;
- plugin/policy trying to downgrade DENY;
- event-chain tampering;
- huge diff/blob timeout/cap behavior.

## Source Adoption Controls

No donor code or rules enter implementation until a ledger entry records exact origin and license. Concepts may be reimplemented independently when appropriate. External engine support uses clean process/protocol boundaries and never grants the engine verdict authority.

## Complexity Tracking

| Potential complexity | Why needed | Simpler alternative rejected because |
|---|---|---|
| Nine-crate workspace | isolates trust boundaries and prevents subprocess/policy/store authority leakage | one crate would make security boundaries implicit and hard to test |
| Evidence + Finding separation | preserves epistemic discipline and multi-producer correlation | treating scanner results as findings recreates noisy scanner behavior |
| SQLite + in-memory petgraph | local auditability + graph algorithms without server dependency | graph DB violates simple local-first distribution; custom DB is unnecessary |
| Rego + Rust kernel invariants | user-extensible policy without allowing policy to override core protections | Rust-only policies are less extensible; Rego-only kernel is too mutable |

## Post-Design Constitution Re-check

PASS. The design remains inside all constitutional boundaries. `sentrdel-verify` is intentionally non-executable in R1; full provider security remains in roadmap slices; no CPG or universal-agent-interception claim has re-entered scope.
