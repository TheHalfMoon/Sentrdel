# Tasks: Sentrdel v0.1 Evidence + Guard Foundation

**Input:** constitution, `major-review-2026-08-24.md`, `implementation-amendment-002-evaluation-learning.md`, `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, `contracts/`, `quickstart.md`, `../000-sentrdel-roadmap/improvement-plan-2026-08-26.md`  
**Status:** IMPLEMENTATION_IN_PROGRESS

## Format

`- [ ] T### [P?] [US#?] Description with exact paths`

`[P]` means safely parallel after prerequisites. `[US#]` maps to a user story.

**Task ID stability:** T001-T087 retain their original IDs. Tasks added by the 2026-08-26 evaluation amendment use T088+ and are inserted at their actual execution point; document position + dependency notes define execution order, not numeric sorting alone.

---

## Phase 1 — Governance and Workspace Setup

**Purpose:** Establish project authority, secure Rust workspace, self-supply-chain policy, source-reuse controls, and repository security guidance before implementation breadth.

- [x] T001 Verify the founder-frozen **Apache-2.0** core license in `LICENSE` and create `docs/third-party/POLICY.md` defining compatibility/adoption rules; donor source/data still requires per-source qualification.
- [x] T002 Create the **Rust 1.98.0** nine-crate workspace in `Cargo.toml`, `rust-toolchain.toml`, and `crates/*/Cargo.toml`; commit `Cargo.lock` as soon as dependency resolution exists.
- [x] T003 [P] Configure workspace fmt/clippy/test profiles in `Cargo.toml`, `.cargo/config.toml`, and crate roots so `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` are canonical gates.
- [x] T004 [P] Add dependency/license/advisory policy in `deny.toml` and `docs/security/dependency-policy.md`; require explicit justification/elevated review for `build.rs`, proc macros, native code, downloaded artifacts, credential/network behavior and other privileged dependencies.
- [x] T005 [P] Create `docs/third-party/source-qualification-ledger.md` using `SourceQualificationRecord`; record initial STUDY/ADAPT entries for Graphify, code-graph-rag, DeepSeek Harness and Continue without copying source.
- [x] T006 [P] Create fixture/test skeleton under `fixtures/repos/`, `fixtures/engines/`, `fixtures/mcp/`, `fixtures/policies/`, `tests/contract/`, `tests/integration/`, `tests/adversarial/`, and `tests/benchmark/`.
- [x] T007 Add root `AGENTS.md` and `SECURITY.md`: no unqualified donor source, no live exploitation, no target build/install/Cargo execution during analysis, no weakening contracts; SECURITY.md defines system scope, threat boundaries, invariants, reportability and known limitations and is context—not executable authority.

**Checkpoint:** Empty workspace builds with exact toolchain; governance/self-security gates are explicit.

---

## Phase 2 — Foundational Trusted Substrate

**Purpose:** Blocking prerequisites. No user-story implementation starts until these contracts are green.

### Canonical schema

- [x] T008 Implement schema-version and canonical serialization primitives in `crates/sentrdel-schema/src/version.rs` and `canonical.rs` with deterministic hashing tests.
- [x] T009 [P] Implement `Evidence`, `ProducerKind`, `EpistemicClass`, `ConfidenceBand`, direct `observation`, optional `security_interpretation`, subjects and locations in `crates/sentrdel-schema/src/evidence.rs`; tests must reject semantic conclusions mislabeled as LLM/unauthorized FACT.
- [x] T010 [P] Implement `Finding`, severity, two-axis lifecycle, `AcceptedRisk`, and transition validation in `crates/sentrdel-schema/src/finding.rs` with lifecycle tests.
- [x] T011 [P] Implement `CoverageRecord`, coverage states and provider coverage dimensions in `crates/sentrdel-schema/src/coverage.rs`; failure/unavailable/detection-only cannot masquerade as secure/covered posture.
- [x] T012 [P] Implement ASEL envelope, actors, event kinds, hash-link fields, session-integrity result, `PolicyDecision`, verdict and `EnforcementFidelity` in `crates/sentrdel-schema/src/asel.rs` and `policy.rs`.
- [x] T013 [P] Implement `ProjectProfile`, provider/framework records, `SecurityPackManifest`, `EngineManifest`, and `EngineRun` schema types in `project.rs`, `pack.rs`, `engine.rs`, including pack coverage modes and engine environment allowlist.
- [x] T014 Generate/check versioned JSON Schemas into `schemas/v1/` and add round-trip/unknown-authority contract tests.
- [x] T015 Restrict reasoner public API so LLM adapters can construct only INFERENCE/HYPOTHESIS Evidence; add compile/runtime contract tests.

**Implementation checkpoint (2026-08-24):** T001–T007 are canonical in bootstrap commit `4bb988afa21b18a67e9ba5692b458d05dc2efbf2`. T008–T015 are canonical in schema-substrate merge `c60ed8610643406dea0c3298eb1eb83520f0d7be`. R1 canonical IDs use domain-separated SHA-256 under `implementation-amendment-001-hashing.md`.

### Store and integrity

- [x] T016 Implement SQLite connection/migrations/WAL and migration tests in `crates/sentrdel-store/`.
- [x] T017 [P] Implement **SHA-256** content-addressed Evidence persistence and immutable lookup APIs with idempotency tests, using the canonical profile frozen by `implementation-amendment-001-hashing.md`.
- [x] T018 [P] Implement Finding projection/history, CoverageRecord, ProjectProfile, EngineRun and manifest persistence.
- [x] T019 Implement redaction-before-persist boundary and tests proving discovered secret plaintext **and stable unkeyed secret-value-only digests** never appear in SQLite/export/log/snapshot fixtures.
- [x] T020 Implement ASEL append/hash-link store, computed head, event count and optional trusted-head comparison in `crates/sentrdel-store/src/asel.rs`; tests distinguish available-chain consistency from externally trusted checkpoint validation.

### Policy kernel

- [x] T021 Implement normalized action digest and `ALLOW < ASK < DENY` lattice plus UNDECIDABLE handling.
- [x] T022 Implement Rust-owned kernel invariants for workspace/evidence/enforcement integrity.
- [x] T023 Qualify/pin **Regorus >=0.11.0** and integrate behind `sentrdel-policy`: policy/input byte+depth caps, tested builtin/subset allowlist, precompiled policy path and bounded failure semantics; add deep/oversized adversarial fixtures.
- [x] T024 Implement monotonic policy composition and repository-policy narrowing validation.
- [x] T025 Add property/adversarial tests proving no ordering can downgrade kernel DENY or turn policy-evaluation failure into silent ALLOW.

### Engine boundary

- [x] T026 Implement `Engine` trait, request/limits/result types and adapter registry.
- [x] T027 Implement the only allowed external-engine process runner using argv arrays, trusted executable resolution, bounded cwd/time/stdout/stderr, and **deny-by-default/scrubbed child environment with explicit allowlist**.
- [x] T028 Implement strict raw-result/SARIF adapter boundary and repo-relative location normalization.
- [x] T029 Add malformed JSON, flood, timeout, non-zero, missing executable, out-of-root path and inherited-secret canary fixtures/tests; prove cloud/model/signing/SSH credentials are absent by default.
- [x] T030 Prove every engine termination path emits explicit CoverageRecord state.

### Evidence graph

- [x] T031 Implement stable graph node/edge identities, provenance and confidence-source types.
- [x] T032 [P] Implement SQLite graph persistence mapping.
- [x] T033 [P] Implement `petgraph` projection, reverse reachability/blast radius and graph-diff primitives with deterministic fixtures.
- [x] T034 Define SCIP ingestion interface/coverage without mandatory indexer; no semantic certainty without producer provenance.

### Foundational CLI envelope

- [x] T035 Implement stable CLI exit codes/JSON envelope from `contracts/cli-contract.md` with contract tests.
- [x] T036 Wire DI/bootstrap across schema/store/graph/engine/policy without review/guard feature behavior yet.

**Foundational Checkpoint:** schema/store/policy/engine/graph/CLI contracts pass.

### Evaluation + self-security interposed gate — amendment 002

**Purpose:** Establish how Sentrdel proves quality before detector breadth. These tasks execute after T036 and before T037. They do not authorize autonomous learning or trusted-core self-modification.

- [x] T088 Define the R1 **SentrdelBench Core** evaluator/metric contract in `docs/security/evaluation-contract.md` and benchmark fixture conventions in `tests/benchmark/README.md`; record explicit precision, known-ground-truth miss/recall, clean-PR FP, coverage, provenance completeness, deterministic replay, latency/resource and later guard false-block dimensions without collapsing security quality into one opaque score.
- [x] T089 Implement the minimal executable benchmark-core harness and machine-readable run record using trusted Rust test code under `crates/sentrdel-review/tests/` plus `tests/benchmark/`; every run identifies evaluator version/digest, corpus revision, baseline/candidate identity and machine metadata where performance is measured.
- [x] T090 Separate benchmark corpora into public regression, development-evaluation and protected-holdout classes; public/base tests MUST NOT depend on private holdout data, and candidate-generation logic MUST NOT receive protected expected outputs. Document holdout promotion semantics in `docs/security/evaluation-contract.md`.
- [x] T091 Move self-security dependency gates forward: add/qualify `cargo-audit` + `cargo-deny` CI for the trusted Sentrdel workspace, validate source/dependency qualification and privileged dependency declarations, and keep target repositories outside these Cargo execution paths.
- [x] T092 Configure and record protected `main` repository rules/branch policy requiring the canonical applicable CI checks before merge; document exact ruleset/check names and limitations in `docs/security/repository-governance.md`. CI success alone MUST NOT be described as branch protection.
- [x] T095 [P] Freeze authority-safe future-learning/context contracts in `contracts/context-learning-authority.md`: untrusted context does not become privileged instruction; feedback/memory remain context rather than FACT/VERIFIED; research automation is candidate-only and cannot alter evaluator/holdout/kernel/reconciler/verification/release authority for its current candidate. General-purpose Security Memory/Learning implementation remains deferred.

**Evaluation Gate Checkpoint:** T088-T092 and T095 are green; a deterministic benchmark baseline exists before broad detector growth; `main` governance state is explicitly recorded; no self-learning capability is implied.

---

## Phase 3 — US1: Review an AI-generated change

**Goal:** High-signal evidence-backed diff review across coding-agent vendors.

**Quality strategy:** Build the first vertical steel thread under SentrdelBench (`safe diff -> secret + GitHub Actions high-signal producers -> Evidence -> reconciler -> Finding -> graph context -> review output -> benchmark`) before optimizing for rule count.

- [x] T037 [US1] Implement read-only Git discovery/diff using minimal qualified `gix` features; explicitly disable/avoid hooks, external diff/textconv/filter drivers, submodule fetch, credential helpers and network remotes; fixtures cover hostile config, rename/delete/binary/shallow repos.
- [x] T038 [P] [US1] Implement bounded repository/file view and path normalization with symlink/confusable/oversized tests; target Cargo/npm/pip metadata commands are never run.
- [x] T039 [P] [US1] Integrate tree-sitter/`ast-grep-core` native producer framework and Sentrdel-owned rule format.
- [x] T040 [P] [US1] Implement deliberately small high-signal structural rule set + positive/negative fixtures.
- [x] T041 [P] [US1] Implement changed-secret producer with redacted Evidence; persist only rule/type/location/redacted display/sanitized non-secret fingerprints.
- [x] T042 [P] [US1] Implement supported lockfile dependency-delta parser + offline advisory fixture provider without executing package managers.
- [x] T043 [P] [US1] Add optional OSV-compatible lookup/cache respecting `--no-network`; tests remain offline-capable.
- [x] T044 [P] [US1] Implement GitHub Actions high-signal producer covering permission widening, OIDC/id-token, secrets in untrusted PR paths, `pull_request_target`, untrusted expression→shell interpolation, mutable action refs vs SHA pinning, self-hosted/untrusted runner changes and trust-sensitive artifact/cache handoffs.
- [x] T045 [US1] Implement Evidence fingerprint/correlation/reconciliation into canonical Findings, preserving observations, interpretations, provenance and contradictions.
- [x] T046 [US1] Connect changed symbols/reverse reachability to Finding context without unsupported semantic claims; where stable identity/diff evidence exists, preserve enough prior/current state for later temporal classifications without inventing causality.
- [x] T047 [US1] Implement review coverage matrix aggregation so absent/failed producers are visible.
- [x] T048 [US1] Implement `sentrdel review` human/JSON output using frozen CLI contract.
- [x] T049 [US1] Add E2E clean/vulnerable/contradictory/missing-engine/hostile-repo tests proving deterministic producers ignore repository instructions and hidden execution configs; run the vertical steel-thread cases through SentrdelBench and record baseline deltas.

---

## Phase 4 — US2: Guard controllable agent actions

**Goal:** True vendor-neutral **bounded stdio MCP** enforcement + integrity-linked ASEL + honest partial git hooks.

- [x] T093 [US2] Before MCP server forwarding, implement the Sentrdel-owned stdio MCP **child-process environment boundary**: deny ambient environment inheritance by default; explicitly allow only minimal normalized process requirements and user-authorized server capabilities; prove cloud/model/forge/signing/SSH/database/provider-admin credential canaries are absent by default.
- [x] T050 [US2] Qualify/pin rmcp 3.x protocol/model support but implement Sentrdel-owned **bounded stdio framing/reader** and explicit protocol-version negotiation/allowlist in `crates/sentrdel-guard/src/mcp/protocol.rs`; do not use remote/Streamable HTTP or blindly rely on SDK Default/LATEST semantics.
- [x] T051 [P] [US2] Implement MCP server/tool inventory and bounded description/schema hashes; cap metadata bytes/depth before storage/policy/reasoning.
- [x] T052 [US2] Implement stdio gateway normalization, pre-invocation policy, scoped approval and forwarding with max frame/buffer/args/result limits and fail-closed protocol errors; forwarding uses the T093 scrubbed environment/capability boundary.
- [x] T053 [US2] Persist ASEL discovery/invocation/approval/denial/tool-result events; expose computed session head/event count and optional expected-head verification without claiming local chain is tamper-proof.
- [x] T054 [P] [US2] Detect instruction-shaped/untrusted tool descriptions/results as Evidence/candidate telemetry without letting payload text alter policy; MCP content remains data unless an explicit trusted authority contract says otherwise.
- [x] T055 [US2] Implement `sentrdel guard mcp` CLI with ENFORCED fidelity for proxied stdio path and chain/head summary.
- [x] T056 [P] [US2] Implement safe git-hook install/composition/uninstall metadata without overwriting unrelated hooks.
- [x] T057 [US2] Implement hook-install CLI with PARTIAL fidelity warning.
- [ ] T058 [US2] Add fixture stdio MCP client/server and E2E guard tests covering ALLOW/ASK/DENY/UNDECIDABLE, malicious descriptions/results, giant/unterminated frames, buffer caps, unsupported versions, credential-inheritance canaries, ASEL verification and no remote HTTP support.

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

- [ ] T077 **Expand** the T088-T090 SentrdelBench Core into the complete reproducible R1 release benchmark for clean/vulnerable PRs, false positives, latency, memory, guard false-block, MCP malformed-input and authority-boundary scenarios; public large-scale SentrdelBench remains roadmap R9.
- [ ] T078 Add release gate failing if clean-PR FP exceeds 1 per 5 clean PRs for gated rules.
- [ ] T079 [P] Add warm review latency target (<5s p95 <2k changed LOC; <30s broader target) with benchmark-machine metadata.
- [ ] T080 [P] Add MCP in-process policy latency target (<50ms p95 excluding downstream/human/framing wait) plus bounded-frame memory tests.
- [ ] T081 Add cross-platform GitHub Actions CI for fmt/clippy/test/base contracts on Linux/macOS/Windows; guard tests truthfully platform/seam-qualified.
- [ ] T082 Complete self-security CI beyond the early T091 gate: source/dependency qualification validation, Rust 1.98.0 pin/lockfile checks, malicious-package denylist/advisory refresh path, privileged dependency documentation and release-grade policy. `cargo-vet`, if later used, is only for the trusted Sentrdel workspace and never run against arbitrary target repos.
- [ ] T083 [P] Document R1 threat model/trust boundaries in `docs/security/threat-model.md` and keep root `SECURITY.md` aligned, including context/instruction authority and MCP credential inheritance boundaries.
- [ ] T084 [P] Document architecture/Evidence/ASEL including trusted-head limitations, stdio MCP scope, evaluation-plane limits, and candidate-only future learning authority.
- [ ] T085 Update README with implemented/verified capabilities and explicit non-claims; Supabase deep pack, remote MCP, Verify, general Security Memory and autonomous Research/Learning remain roadmap only.
- [ ] T086 Run final Spec Kit consistency analysis against constitution + major review + implementation amendments + spec/plan/contracts/tasks and record repairs in `analysis.md`.
- [ ] T087 Run implementation closeout: workspace tests/lints/adversarial suite/benchmarks, no secret canary persistence, no inherited engine/MCP credentials, no unqualified donor/privileged dependency, protected-main governance state recorded, exact results in `implementation-closeout.md`.

---

## Dependencies

```text
Phase 1 Governance/workspace
    |
    v
Phase 2 Trusted substrate (through T036)
    |
    v
Evaluation + self-security gate (T088-T092, T095)
    |
    +--------------------+----------------------+
    |                    |                      |
    v                    v                      v
US1 Review            US2 Guard              US3 Init
(vertical first)      (T093 before T050)         |
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

US1/US2/US3 may proceed in parallel only after the Evaluation Gate Checkpoint. US1 should prove the benchmarked vertical steel thread before detector breadth. T093 is a US2 blocking prerequisite before T050-T058 forwarding behavior. US4 depends on Findings/store. US5 is optional/last among features. Release hardening depends on in-scope stories and expands rather than invents the benchmark/self-security foundations.

## Implementation Strategy

1. Secure workspace/schema/store/policy/process boundaries first and finish T032-T036.
2. Establish SentrdelBench Core + protected evaluation semantics + repository self-security before detector proliferation.
3. Ship Review as the first externally useful capability, starting with one benchmarked vertical steel thread before broad rule count.
4. Ship bounded stdio MCP Guard as the first genuine vendor-neutral enforcement seam, with deny-by-default child credential inheritance before forwarding.
5. Ship Init/provider detection with honest coverage; Supabase static posture follows immediately in roadmap R2.
6. Explain; then optional reasoner; then release only if quality/security gates pass.
7. Full Security Memory, producer reliability, signed/revocable community pack distribution, temporal project-wide security intelligence, and continuous Research/Learning require later dedicated specs as mapped in the roadmap Plan of Record.

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
- broad scanner/rule-count expansion;
- general-purpose Project Security Memory and memory-driven suppression;
- full context/instruction provenance integration across every forge/browser/IDE channel;
- automatic producer reliability weighting as authority;
- signed community pack marketplace/distribution lifecycle;
- autonomous Security Research/Learning Plane, automatic candidate promotion, or trusted-core self-modification.
