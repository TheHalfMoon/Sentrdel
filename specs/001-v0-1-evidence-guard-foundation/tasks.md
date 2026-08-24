# Tasks: Sentrdel v0.1 Evidence + Guard Foundation

**Input:** constitution, `major-review-2026-08-24.md`, `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, `contracts/`, `quickstart.md`  
**Status:** TASKS_COMPLETE_PENDING_FINAL_ANALYZE

## Format

`- [ ] T### [P?] [US#?] Description with exact paths`

`[P]` means safely parallel after prerequisites. `[US#]` maps to a user story.

---

## Phase 1 — Governance and Workspace Setup

**Purpose:** Establish project authority, secure Rust workspace, self-supply-chain policy, source-reuse controls, and repository security guidance before implementation breadth.

- [ ] T001 Verify the founder-frozen **Apache-2.0** core license in `LICENSE` and create `docs/third-party/POLICY.md` defining compatibility/adoption rules; donor source/data still requires per-source qualification.
- [ ] T002 Create the **Rust 1.98.0** nine-crate workspace in `Cargo.toml`, `rust-toolchain.toml`, and `crates/*/Cargo.toml`; commit `Cargo.lock` as soon as dependency resolution exists.
- [ ] T003 [P] Configure workspace fmt/clippy/test profiles in `Cargo.toml`, `.cargo/config.toml`, and crate roots so `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` are canonical gates.
- [ ] T004 [P] Add dependency/license/advisory policy in `deny.toml` and `docs/security/dependency-policy.md`; require explicit justification/elevated review for `build.rs`, proc macros, native code, downloaded artifacts, credential/network behavior and other privileged dependencies.
- [ ] T005 [P] Create `docs/third-party/source-qualification-ledger.md` using `SourceQualificationRecord`; record initial STUDY/ADAPT entries for Graphify, code-graph-rag, DeepSeek Harness and Continue without copying source.
- [ ] T006 [P] Create fixture/test skeleton under `fixtures/repos/`, `fixtures/engines/`, `fixtures/mcp/`, `fixtures/policies/`, `tests/contract/`, `tests/integration/`, `tests/adversarial/`, and `tests/benchmark/`.
- [ ] T007 Add root `AGENTS.md` and `SECURITY.md`: no unqualified donor source, no live exploitation, no target build/install/Cargo execution during analysis, no weakening contracts; SECURITY.md defines system scope, threat boundaries, invariants, reportability and known limitations and is context—not executable authority.

**Checkpoint:** Empty workspace builds with exact toolchain; governance/self-security gates are explicit.

---

## Phase 2 — Foundational Trusted Substrate

**Purpose:** Blocking prerequisites. No user-story implementation starts until these contracts are green.

### Canonical schema

- [ ] T008 Implement schema-version and canonical serialization primitives in `crates/sentrdel-schema/src/version.rs` and `canonical.rs` with deterministic hashing tests.
- [ ] T009 [P] Implement `Evidence`, `ProducerKind`, `EpistemicClass`, `ConfidenceBand`, direct `observation`, optional `security_interpretation`, subjects and locations in `crates/sentrdel-schema/src/evidence.rs`; tests must reject semantic conclusions mislabeled as LLM/unauthorized FACT.
- [ ] T010 [P] Implement `Finding`, severity, two-axis lifecycle, `AcceptedRisk`, and transition validation in `crates/sentrdel-schema/src/finding.rs` with lifecycle tests.
- [ ] T011 [P] Implement `CoverageRecord`, coverage states and provider coverage dimensions in `crates/sentrdel-schema/src/coverage.rs`; failure/unavailable/detection-only cannot masquerade as secure/covered posture.
- [ ] T012 [P] Implement ASEL envelope, actors, event kinds, hash-link fields, session-integrity result, `PolicyDecision`, verdict and `EnforcementFidelity` in `crates/sentrdel-schema/src/asel.rs` and `policy.rs`.
- [ ] T013 [P] Implement `ProjectProfile`, provider/framework records, `SecurityPackManifest`, `EngineManifest`, and `EngineRun` schema types in `project.rs`, `pack.rs`, `engine.rs`, including pack coverage modes and engine environment allowlist.
- [ ] T014 Generate/check versioned JSON Schemas into `schemas/v1/` and add round-trip/unknown-authority contract tests.
- [ ] T015 Restrict reasoner public API so LLM adapters can construct only INFERENCE/HYPOTHESIS Evidence; add compile/runtime contract tests.

### Store and integrity

- [ ] T016 Implement SQLite connection/migrations/WAL and migration tests in `crates/sentrdel-store/`.
- [ ] T017 [P] Implement BLAKE3 content-addressed Evidence persistence and immutable lookup APIs with idempotency tests.
- [ ] T018 [P] Implement Finding projection/history, CoverageRecord, ProjectProfile, EngineRun and manifest persistence.
- [ ] T019 Implement redaction-before-persist boundary and tests proving discovered secret plaintext **and stable unkeyed secret-value-only digests** never appear in SQLite/export/log/snapshot fixtures.
- [ ] T020 Implement ASEL append/hash-link store, computed head, event count and optional trusted-head comparison in `crates/sentrdel-store/src/asel.rs`; tests distinguish available-chain consistency from externally trusted checkpoint validation.

### Policy kernel

- [ ] T021 Implement normalized action digest and `ALLOW < ASK < DENY` lattice plus UNDECIDABLE handling.
- [ ] T022 Implement Rust-owned kernel invariants for workspace/evidence/enforcement integrity.
- [ ] T023 Qualify/pin **Regorus >=0.11.0** and integrate behind `sentrdel-policy`: policy/input byte+depth caps, tested builtin/subset allowlist, precompiled policy path and bounded failure semantics; add deep/oversized adversarial fixtures.
- [ ] T024 Implement monotonic policy composition and repository-policy narrowing validation.
- [ ] T025 Add property/adversarial tests proving no ordering can downgrade kernel DENY or turn policy-evaluation failure into silent ALLOW.

### Engine boundary

- [ ] T026 Implement `Engine` trait, request/limits/result types and adapter registry.
- [ ] T027 Implement the only allowed external-engine process runner using argv arrays, trusted executable resolution, bounded cwd/time/stdout/stderr, and **deny-by-default/scrubbed child environment with explicit allowlist**.
- [ ] T028 Implement strict raw-result/SARIF adapter boundary and repo-relative location normalization.
- [ ] T029 Add malformed JSON, flood, timeout, non-zero, missing executable, out-of-root path and inherited-secret canary fixtures/tests; prove cloud/model/signing/SSH credentials are absent by default.
- [ ] T030 Prove every engine termination path emits explicit CoverageRecord state.

### Evidence graph

- [ ] T031 Implement stable graph node/edge identities, provenance and confidence-source types.
- [ ] T032 [P] Implement SQLite graph persistence mapping.
- [ ] T033 [P] Implement `petgraph` projection, reverse reachability/blast radius and graph-diff primitives with deterministic fixtures.
- [ ] T034 Define SCIP ingestion interface/coverage without mandatory indexer; no semantic certainty without producer provenance.

### Foundational CLI envelope

- [ ] T035 Implement stable CLI exit codes/JSON envelope from `contracts/cli-contract.md` with contract tests.
- [ ] T036 Wire DI/bootstrap across schema/store/graph/engine/policy without review/guard feature behavior yet.

**Foundational Checkpoint:** schema/store/policy/engine/graph/CLI contracts pass.

---

## Phase 3 — US1: Review an AI-generated change

**Goal:** High-signal evidence-backed diff review across coding-agent vendors.

- [ ] T037 [US1] Implement read-only Git discovery/diff using minimal qualified `gix` features; explicitly disable/avoid hooks, external diff/textconv/filter drivers, submodule fetch, credential helpers and network remotes; fixtures cover hostile config, rename/delete/binary/shallow repos.
- [ ] T038 [P] [US1] Implement bounded repository/file view and path normalization with symlink/confusable/oversized tests; target Cargo/npm/pip metadata commands are never run.
- [ ] T039 [P] [US1] Integrate tree-sitter/`ast-grep-core` native producer framework and Sentrdel-owned rule format.
- [ ] T040 [P] [US1] Implement deliberately small high-signal structural rule set + positive/negative fixtures.
- [ ] T041 [P] [US1] Implement changed-secret producer with redacted Evidence; persist only rule/type/location/redacted display/sanitized non-secret fingerprints.
- [ ] T042 [P] [US1] Implement supported lockfile dependency-delta parser + offline advisory fixture provider without executing package managers.
- [ ] T043 [P] [US1] Add optional OSV-compatible lookup/cache respecting `--no-network`; tests remain offline-capable.
- [ ] T044 [P] [US1] Implement GitHub Actions high-signal producer covering permission widening, OIDC/id-token, secrets in untrusted PR paths, `pull_request_target`, untrusted expression→shell interpolation, mutable action refs vs SHA pinning, self-hosted/untrusted runner changes and trust-sensitive artifact/cache handoffs.
- [ ] T045 [US1] Implement Evidence fingerprint/correlation/reconciliation into canonical Findings, preserving observations, interpretations, provenance and contradictions.
- [ ] T046 [US1] Connect changed symbols/reverse reachability to Finding context without unsupported semantic claims.
- [ ] T047 [US1] Implement review coverage matrix aggregation so absent/failed producers are visible.
- [ ] T048 [US1] Implement `sentrdel review` human/JSON output using frozen CLI contract.
- [ ] T049 [US1] Add E2E clean/vulnerable/contradictory/missing-engine/hostile-repo tests proving deterministic producers ignore repository instructions and hidden execution configs.

---

## Phase 4 — US2: Guard controllable agent actions

**Goal:** True vendor-neutral **bounded stdio MCP** enforcement + integrity-linked ASEL + honest partial git hooks.

- [ ] T050 [US2] Qualify/pin rmcp 3.x protocol/model support but implement Sentrdel-owned **bounded stdio framing/reader** and explicit protocol-version negotiation/allowlist in `crates/sentrdel-guard/src/mcp/protocol.rs`; do not use remote/Streamable HTTP or blindly rely on SDK Default/LATEST semantics.
- [ ] T051 [P] [US2] Implement MCP server/tool inventory and bounded description/schema hashes; cap metadata bytes/depth before storage/policy/reasoning.
- [ ] T052 [US2] Implement stdio gateway normalization, pre-invocation policy, scoped approval and forwarding with max frame/buffer/args/result limits and fail-closed protocol errors.
- [ ] T053 [US2] Persist ASEL discovery/invocation/approval/denial/tool-result events; expose computed session head/event count and optional expected-head verification without claiming local chain is tamper-proof.
- [ ] T054 [P] [US2] Detect instruction-shaped/untrusted tool descriptions/results as Evidence/candidate telemetry without letting payload text alter policy.
- [ ] T055 [US2] Implement `sentrdel guard mcp` CLI with ENFORCED fidelity for proxied stdio path and chain/head summary.
- [ ] T056 [P] [US2] Implement safe git-hook install/composition/uninstall metadata without overwriting unrelated hooks.
- [ ] T057 [US2] Implement hook-install CLI with PARTIAL fidelity warning.
- [ ] T058 [US2] Add fixture stdio MCP client/server and E2E guard tests covering ALLOW/ASK/DENY/UNDECIDABLE, malicious descriptions/results, giant/unterminated frames, buffer caps, unsupported versions, ASEL verification and no remote HTTP support.

---

## Phase 5 — US3: Initialize and understand coverage

- [ ] T059 [P] [US3] Implement bounded language/ecosystem detection using files/config only.
- [ ] T060 [P] [US3] Implement CI/MCP config detection without reading secret values or opening remote MCP connections.
- [ ] T061 [US3] Implement Security Pack registry/manifest validation; packs emit Evidence/Coverage only and declare DETECTION/STATIC_POSTURE/LIVE_POSTURE/BUSINESS_LOGIC/RUNTIME dimensions.
- [ ] T062 [P] [US3] Implement **Supabase detection only** with positive/negative fixtures; R1 output explicitly marks static posture NOT_IMPLEMENTED/PARTIAL and points to roadmap R2 without making a verdict.
- [ ] T063 [P] [US3] Implement generic provider/framework detection extension points without deep Firebase/cloud/payment analysis.
- [ ] T064 [US3] Implement ProjectProfile persistence and coverage matrix.
- [ ] T065 [US3] Implement `sentrdel init` human/JSON output including explicit pack coverage dimensions.
- [ ] T066 [US3] Add integration/adversarial init tests: symlink/oversized/weakening config, hostile `.cargo/config.toml`, Supabase detection-without-verdict.

---

## Phase 6 — US4: Explain findings

- [ ] T067 [P] [US4] Implement three-tier presentation with actor/capability/object impact sentence.
- [ ] T068 [P] [US4] Implement Evidence/provenance graph subtree query.
- [ ] T069 [US4] Implement `sentrdel explain <finding-id>` human/JSON modes.
- [ ] T070 [US4] Add golden/contract tests proving explanation cannot mutate canonical severity/proof/workflow state.

---

## Phase 7 — US5: Optional hypothesis-only LLM reasoning

- [ ] T071 [US5] Implement provider-neutral optional reasoner trait + bounded evidence/substrate request model.
- [ ] T072 [P] [US5] Implement local HTTP/Ollama-compatible adapter behind feature/config gate.
- [ ] T073 [P] [US5] Implement generic explicit remote HTTP adapter without provider SDK authority; whole-repo upload prohibited by default.
- [ ] T074 [US5] Strictly map reasoner output to INFERENCE/HYPOTHESIS Evidence.
- [ ] T075 [US5] Add prompt-injection authority tests proving no suppression, FACT/VERIFIED escalation, authoritative severity downgrade or kernel-policy downgrade.
- [ ] T076 [US5] Wire `--reason`/`--no-network` without deterministic review dependence on a model.

---

## Phase 8 — Release Hardening and Cross-Cutting Quality

- [ ] T077 Build reproducible R1 benchmark harness for clean/vulnerable PRs, false positives, latency, memory, guard false-block, MCP malformed-input scenarios; public SentrdelBench remains roadmap R9.
- [ ] T078 Add release gate failing if clean-PR FP exceeds 1 per 5 clean PRs for gated rules.
- [ ] T079 [P] Add warm review latency target (<5s p95 <2k changed LOC; <30s broader target) with benchmark-machine metadata.
- [ ] T080 [P] Add MCP in-process policy latency target (<50ms p95 excluding downstream/human/framing wait) plus bounded-frame memory tests.
- [ ] T081 Add cross-platform GitHub Actions CI for fmt/clippy/test/base contracts on Linux/macOS/Windows; guard tests truthfully platform/seam-qualified.
- [ ] T082 Add self-security CI: `cargo-audit`, `cargo-deny`, source/dependency qualification validation, Rust 1.98.0 pin/lockfile checks, malicious-package denylist/advisory refresh path, and checks that privileged dependencies are documented. `cargo-vet`, if later used, is only for the trusted Sentrdel workspace and never run against arbitrary target repos.
- [ ] T083 [P] Document R1 threat model/trust boundaries in `docs/security/threat-model.md` and keep root `SECURITY.md` aligned.
- [ ] T084 [P] Document architecture/Evidence/ASEL including trusted-head limitations and stdio MCP scope.
- [ ] T085 Update README with implemented/verified capabilities and explicit non-claims; Supabase deep pack, remote MCP and Verify remain roadmap only.
- [ ] T086 Run final Spec Kit consistency analysis against constitution + major review + spec/plan/contracts/tasks and record repairs in `analysis.md`.
- [ ] T087 Run implementation closeout: workspace tests/lints/adversarial suite/benchmarks, no secret canary persistence, no inherited engine credentials, no unqualified donor/privileged dependency, exact results in `implementation-closeout.md`.

---

## Dependencies

```text
Phase 1 Governance/workspace
    |
    v
Phase 2 Trusted substrate
    |
    +--------------------+----------------------+
    |                    |                      |
    v                    v                      v
US1 Review            US2 Guard              US3 Init
    |                    |                      |
    +----------+---------+----------------------+
               |
               v
           US4 Explain
               |
               v
        US5 Optional reasoner
               |
               v
       Release hardening
```

US1/US2/US3 may proceed in parallel after Phase 2. US4 depends on Findings/store. US5 is optional/last among features. Release hardening depends on in-scope stories.

## Implementation Strategy

1. Secure workspace/schema/store/policy/process boundaries first.
2. Ship Review as first externally useful capability.
3. Ship bounded stdio MCP Guard as first genuine vendor-neutral enforcement seam.
4. Ship Init/provider detection with honest coverage; Supabase static posture follows immediately in roadmap R2.
5. Explain; then optional reasoner; then release only if quality/security gates pass.

## Explicitly Deferred to Later Specs

- Supabase RLS/Auth/Storage/Edge Function **static posture implementation** (now roadmap R2; detection only in R1);
- Supabase/general cross-layer business logic/invariants (R3);
- Firebase/Auth/Stripe/cloud/deployment pack breadth;
- remote/Streamable HTTP MCP;
- sandboxed verification/exploit-condition execution;
- auto-fix application;
- eBPF/runtime enforcement;
- VS Code/Cursor/JetBrains/GitHub App integrations;
- universal CPG/compiler implementation;
- broad scanner/rule-count expansion.
