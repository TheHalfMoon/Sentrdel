# Implementation Plan: Sentrdel v0.1 Evidence + Guard Foundation

**Branch:** `spec/001-v0-1-evidence-guard-foundation` | **Date:** 2026-08-24 | **Spec:** `specs/001-v0-1-evidence-guard-foundation/spec.md`  
**Major review:** `major-review-2026-08-24.md`  
**Evaluation/learning amendment:** `implementation-amendment-002-evaluation-learning.md`  
**Roadmap Plan of Record:** `../000-sentrdel-roadmap/improvement-plan-2026-08-26.md`

## Summary

Build the first useful Sentrdel release as a Rust-first local security evidence/control-plane foundation. The slice ships canonical evidence/finding/coverage/ASEL schemas, integrity-linked SQLite storage, diff-first high-signal review, a thin provenance-aware evidence graph, monotonic policy, a bounded **stdio-only** MCP guard gateway plus git-hook support, project/provider detection, plain-language explanations, optional hypothesis-only LLM reasoning, and a minimal immutable evaluation substrate that measures quality before detector breadth grows.

The design deliberately avoids a universal CPG, mandatory cloud services, mandatory external scanners, autonomous exploitation, remote MCP in R1, premature IDE/provider breadth, hidden self-learning authority, and autonomous promotion of learned security rules. Future A-to-Z Security Packs plug into the same evidence contract; Supabase is accelerated to the first dedicated post-R1 provider spec. A later dedicated roadmap slice may implement controlled continuous security research, but R1 only establishes authority-safe contracts and evaluation foundations.

## Technical Context

**Language/Version:** **Rust 1.98.0 exact pin for R1**  
**Primary Dependencies:** `clap`, `serde`, `serde_json`, `schemars`, `tokio`, `rayon`, `thiserror`, `tracing`, `sha2`, `rusqlite`, `petgraph`, `tree-sitter`, `ast-grep-core`/qualified language crates, minimal-feature `gix`, `regorus >=0.11.0`, qualified `rmcp` protocol/model support, `regex`, `ignore`, `walkdir`, `moka` only where justified  
**Storage:** SQLite + domain-separated SHA-256 content-addressed objects under `implementation-amendment-001-hashing.md`; secret values excluded  
**Testing:** `cargo test`, contract/property/adversarial tests, fixture repositories, golden output where stable, protected benchmark/holdout separation, fuzz/property tests for parsers/monotonicity/bounded framing where practical  
**Target Platform:** Review/init: Linux, macOS, Windows. Guard enforcement fidelity is seam-specific and MUST be reported. R1 MCP gateway is stdio only.  
**Project Type:** Rust CLI/workspace security tool  
**Performance Goals:** warm native diff review <5s p95 for <2k changed LOC; broader 100k LOC warm review <30s; MCP guard policy <50ms p95 excluding downstream tool/human time  
**Constraints:** local-first; no required cloud/model/external scanner; no target build/install/Cargo execution during analysis; no shell-string subprocesses; child environments scrubbed/allowlisted; MCP server children deny ambient credential inheritance by default; missing engines become coverage gaps; LLM cannot become fact/verifier/policy authority; research/learning candidates cannot self-promote or mutate the evaluator that judges them  
**Scale/Scope:** small developer repos through ~100k LOC initial benchmark, larger monorepos via incremental/diff-first design

## Constitution Check

| Principle | Gate | Plan status |
|---|---|---|
| Rust Trusted Core | Security-critical core lives in Rust; external tools behind bounded contracts | PASS |
| Evidence Before Verdict | FACT is direct observation only; Findings reconciled; feedback/memory/learning remain lower-authority context/candidates | PASS |
| Vendor-Neutral, Local-First | CLI/stdio MCP/git seams; no mandatory vendor/cloud | PASS |
| Honest/Monotonic Guardrails | Fidelity + absorbing DENY + fail-closed undecidable + untrusted instruction authority separation | PASS |
| Safe Verification | Execution verification excluded from R1 | PASS |
| A-to-Z through Packs | Pack contract + detection now; Supabase R2 posture next | PASS |
| Reuse Mature Infrastructure | Qualified Rust-native foundations + clean external engine boundary | PASS |
| FP/False-Block/Latency Quality | immutable evaluation core moves before detector breadth | PASS |
| Sentrdel Secures Itself | hostile repo/engine/MCP/model/dependency inputs bounded; MCP ambient credentials denied; repository self-security moves forward | PASS |
| Spec Kit Governance | bounded R1 slice under spec-of-specs + binding amendments applied | PASS |

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

Evaluation and future controlled learning are separated from judgment authority:

```text
Trusted Judgment Plane
Evidence -> Reconciler -> Finding -> Policy/Guard/Verify
                   ^
                   | approved artifacts only
             Promotion Firewall
                   ^
                   | candidate only
Research/Learning Plane -> candidate rules/packs/fixtures/heuristics
                   |
                   v
Immutable Evaluation Plane -> regression/dev/protected-holdout corpora
```

R1 builds only the minimum Evaluation Plane contracts/harness and candidate-authority boundaries. It does not authorize autonomous learning-plane production mutation.

### Trust boundaries

1. **Repository boundary:** paths/files/config/git metadata are untrusted; no target tools execute to interpret them.
2. **Engine boundary:** executable identity, child environment and output are untrusted/bounded.
3. **MCP boundary:** framing, descriptions, schemas, arguments, results and server identity are untrusted and byte/depth bounded; Sentrdel-launched MCP children receive a deny-by-default environment and no ambient developer credentials.
4. **LLM boundary:** output is untrusted INFERENCE/HYPOTHESIS only.
5. **Policy boundary:** repo policy cannot widen user/core policy; Regorus inputs/policies are size/depth bounded.
6. **Persistence boundary:** secrets are removed before storage; hash chains are integrity-linked relative to trusted heads, not claimed tamper-proof.
7. **Dependency/build boundary:** Sentrdel's own build scripts/proc macros/native/download dependencies are privileged supply-chain code and require qualification.
8. **Context/instruction boundary:** repository text, issue/PR text, MCP content, logs, browser/tool content, engine output and model output are data/context unless an explicit authority contract says otherwise; reading content does not grant credential or policy authority.
9. **Evaluation boundary:** candidate-generation logic cannot mutate the evaluator, metric definitions, or protected-holdout labels used to judge its current candidate.
10. **Learning/promotion boundary:** future research automation proposes candidate artifacts only; trusted-core authority and production promotion remain independently governed.

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

**Epistemic invariant:** FACT represents only direct bounded observations. Producer security interpretations remain INFERENCE/HYPOTHESIS unless stronger authority exists. Future feedback, security-memory and context-provenance contracts remain explicitly bounded below canonical truth authority.

### `sentrdel-store`

SQLite migrations, content-addressed Evidence, Finding projections/history, coverage/profiles, ASEL chain/head verification, transactional APIs and redaction-before-persist boundary.

**Secret invariant:** no discovered plaintext secret and no stable unkeyed digest derived solely from the secret value is persisted by default.

### `sentrdel-graph`

Stable property/evidence graph identities, provenance/confidence, SQLite mapping, petgraph projections, graph diff, reverse blast radius and optional SCIP ingestion. No universal AST/CFG/type duplication. Graph diff is also the substrate for later change-relative finding state and security-memory invalidation.

### `sentrdel-engine`

Only crate allowed to spawn external evidence engines. Owns Engine trait, executable manifest resolution, argv-only subprocesses, **scrubbed/allowlisted environment**, cwd/time/process/output bounds, strict result adapters, path normalization, failure→Coverage mapping and parallel orchestration.

### `sentrdel-policy`

Rust kernel invariants, monotonic composition, bounded Regorus adapter, ALLOW/ASK/DENY/UNDECIDABLE lattice and repository-config narrowing validation. Kernel invariants cannot be overridden by Rego.

### `sentrdel-guard`

ASEL append API, **bounded stdio MCP gateway**, explicit MCP protocol-version negotiation, MCP server/tool inventory/hashes, preflight policy, scoped approvals, git-hook installation contract and fidelity reporting.

Any MCP server process launched or managed by Sentrdel receives a **deny-by-default/scrubbed environment**. Cloud/model/forge/signing/SSH/database/provider-admin credentials are absent unless an explicit capability and user policy authorize them. Credential-canary tests are required.

Remote/Streamable HTTP MCP and PATH shims are deferred from R1.

### `sentrdel-review`

Safe repository/profile detection, non-executing Git diff selection, native producers, structural rules, secret evidence, dependency/advisory deltas, CI-sensitive changes, pack detection/dispatch, evidence correlation/reconciliation, explanations and optional reasoner.

Git analysis must not execute hooks, external diff/textconv/filter drivers, submodule fetches, credential helpers or network operations.

Review should progressively expose change-relative context (`NEW`, `PRE_EXISTING`, `WORSENED`, `MITIGATED`, `MOVED`, `REINTRODUCED`, `UNCERTAIN`) only where stable identity/diff evidence supports it.

### `sentrdel-verify`

R1 domain/feature boundary only. No sandbox execution, exploit logic, network probes or VERIFIED producer.

### `sentrdel-cli`

`init`, `review`, `explain`, `guard mcp`, `guard install-git-hooks`, evidence diagnostics/chain verification. Stable human + JSON behavior and exit codes.

## Evaluation and Controlled-Learning Authority

R1's benchmark core is part of security architecture, not a reporting afterthought.

The minimum R1 evaluator records explicit metric dimensions rather than one opaque score: precision, known-ground-truth misses/recall, clean-PR false positives, coverage completeness, deterministic replay, evidence/provenance completeness, latency/resource behavior, and later guard false-block/latency dimensions.

The corpus has public regression, development, and protected-holdout classes. Candidate-generation logic cannot read protected expected outputs.

Future Research/Learning automation is candidate-only. It may propose rules, pack checks, graph heuristics, fixtures, fuzz targets or remediation text, but cannot create canonical Findings, mint FACT/VERIFIED authority, weaken kernel policy, change verification semantics, alter the evaluator judging its current candidate, or self-promote to ACTIVE.

Full learning/memory implementation requires later dedicated specs. R1 only freezes the boundaries needed for safe future evolution.

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
                                                  |
                                                  v
                                        SentrdelBench evaluation
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
      +--> forward only if policy permits --> scrubbed-env MCP server
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

## Phase 1B — Evaluation and self-security gate

Immediately after `T032`-`T036`, before broad US1 detector growth:

- freeze SentrdelBench Core metric/evaluator contracts;
- establish public regression, development-evaluation and protected-holdout corpus separation;
- capture a deterministic baseline before producer proliferation;
- move `cargo-audit`/`cargo-deny` and privileged dependency checks forward where practical;
- establish protected `main` repository policy with canonical required checks;
- record exact self-security state rather than inferring it from CI success.

This phase does not implement autonomous learning. It creates the evaluator and governance that future improvements must beat.

## Phase 2 — US1 Review

Start with a vertical steel thread under SentrdelBench before broad detector count:

`safe diff -> changed-secret producer + GitHub Actions producer -> Evidence -> reconciler -> Finding -> graph context -> sentrdel review -> benchmark`

Then continue the complete US1 scope:

- read-only Git diff with no repository execution surfaces;
- native structural parsing/matching;
- high-signal secret/structural/dependency/GitHub Actions producers;
- expanded Actions candidates: permissions, OIDC, pull_request_target, untrusted shell interpolation, action pinning, self-hosted runner/trust handoffs;
- Evidence correlation + Findings;
- change-relative/temporal classification only where stable identity/diff evidence supports it;
- plain-language output and coverage gaps.

## Phase 3 — US2 Guard

- qualified rmcp protocol/model integration;
- Sentrdel-owned bounded stdio framing;
- explicit protocol negotiation;
- deny-by-default MCP child environment and credential-canary qualification;
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

- expand the early SentrdelBench Core into complete R1 FP/false-block/latency/resource release gates;
- Linux/macOS/Windows base CI;
- self-security/dependency/license/source-qualification gates;
- malformed MCP/engine/repo/policy adversarial tests;
- Spec Kit final consistency pass and implementation closeout.

## Error and Coverage Semantics

A review is not internally a boolean secure/insecure. It contains findings by action/severity/proof, coverage dimensions, producer failures/unavailable states and policy decisions where applicable.

CLI distinguishes success/no block, security block, usage/config error, incomplete/undecidable analysis and internal failure according to the CLI contract.

## Testing Strategy

### Unit

Schema validity, hashing/canonicalization, secret redaction, graph identity/traversal, policy lattice, Regorus caps, MCP bounded framing/version negotiation, engine parsers, project detectors, benchmark metric determinism and candidate-authority ceilings.

### Contract

JSON schema round-trip, ASEL chain/head integrity, Engine/Pack authority boundaries, LLM authority, CLI envelope, scrubbed engine environment, scrubbed MCP-server environment, MCP protocol bounds, immutable evaluator/run identity, and protected-holdout isolation.

### Integration

Fixture git repos, stdio MCP fixture client/server, git hooks, offline advisories, Supabase-detected-but-not-covered fixture, end-to-end vertical review benchmark fixtures.

### Adversarial

- prompt/instruction injection in source/MCP descriptions/results and other untrusted context;
- oversized/malformed MCP frame and slow/unterminated stdio input;
- MCP child credential inheritance canaries;
- malformed/oversized engine JSON;
- subprocess environment secret canaries;
- path traversal/symlink/confusable filenames;
- hostile Git external diff/textconv/filter/submodule/network config;
- repo policy trying to weaken kernel invariants;
- Regorus deep/oversized policy/input;
- DENY downgrade attempts;
- learning/candidate attempt to alter evaluator or upgrade its own authority;
- event-chain replacement/truncation semantics relative to trusted head;
- large diff/blob caps.

### Evaluation

Every benchmark run records evaluator version/digest, corpus revision, candidate/baseline identity, machine metadata where performance matters, and explicit metric dimensions. No current-candidate logic may mutate the evaluator or protected expected outputs.

## Source Adoption and Dependency Controls

No donor source/rules enter implementation until a ledger records exact origin/license/security boundary. Concepts may be independently reimplemented when appropriate. Every external engine remains evidence-only.

Sentrdel-owned dependencies are also supply-chain inputs. `build.rs`, proc macros, native libraries and download-at-build patterns require explicit justification.

Research inspiration such as `karpathy/autoresearch` or Hermes learning/skills systems is concept-only until source qualification. Sentrdel may adopt iterative experimentation and inspectable reusable-knowledge patterns, but not their authority assumptions: security candidates remain lower authority than the trusted core and independently evaluated before promotion.

## Complexity Tracking

| Potential complexity | Why needed | Simpler alternative rejected because |
|---|---|---|
| Nine-crate workspace | isolates trust boundaries | one crate makes authority boundaries implicit |
| Evidence + Finding separation | epistemic discipline/correlation | scanner result = finding recreates noise |
| SQLite + petgraph | local auditability + algorithms | graph server breaks local single-tool UX |
| Rego + Rust kernel | extensibility + non-overridable invariants | Rego-only kernel is too mutable |
| Sentrdel-owned stdio framing | hostile MCP input needs strict memory bounds independent of SDK transport defaults | delegating framing blindly violates guard threat model |
| Scrubbed MCP child environment | MCP processes can carry high authority through inherited credentials | ambient developer environment silently grants capabilities unrelated to the approved tool action |
| Evaluation/Research plane split | future automatic improvement must not grade or promote itself | one self-modifying loop can optimize the benchmark, weaken authority, or learn unsafe suppressions |
| Protected holdout | prevents candidate generation from tuning directly to all known expected outputs | fully visible benchmarks can reward benchmark gaming rather than generalizable security judgment |

## Post-Amendment Constitution Re-check

**PASS.** Rust 1.98.0, Apache-2.0, stdio-only bounded MCP, dependency/build-script hardening, precise integrity language, accelerated Supabase roadmap, immutable evaluation, candidate-only learning authority, instruction provenance, and MCP credential isolation strengthen rather than expand R1 unsafely. No universal CPG, remote MCP, executable verification, autonomous trusted-core learning, live provider credential access or broad provider implementation has re-entered R1.
