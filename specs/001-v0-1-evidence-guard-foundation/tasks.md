# Tasks: Sentrdel v0.1 Evidence + Guard Foundation

**Input:** `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, `contracts/`, `quickstart.md`  
**Status:** TASKS_COMPLETE_PENDING_ANALYZE

## Format

`- [ ] T### [P?] [US#?] Description with exact paths`

- `[P]` means the task can run in parallel with other tasks in the same phase when prerequisites are satisfied.
- `[US#]` maps to the user story in `spec.md`.
- Setup/foundational/polish tasks do not require a story tag.

---

## Phase 1 — Governance and Workspace Setup

**Purpose:** Establish repository authority, Rust workspace, dependency/security policy, and source-reuse controls before implementation breadth.

- [ ] T001 Record the founder-frozen core license in `LICENSE` and document compatibility/adoption rules in `docs/third-party/POLICY.md`; do not copy donor source/data before this task is complete.
- [ ] T002 Create the Rust 1.88+ workspace and nine crate members in root `Cargo.toml`, `rust-toolchain.toml`, and `crates/*/Cargo.toml` exactly as defined by `plan.md`.
- [ ] T003 [P] Configure workspace lint/format/test profiles in `Cargo.toml`, `.cargo/config.toml`, and crate roots so `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test --workspace` are canonical gates.
- [ ] T004 [P] Add dependency/license/advisory policy in `deny.toml` and CI-facing documentation in `docs/security/dependency-policy.md`.
- [ ] T005 [P] Create `docs/third-party/source-qualification-ledger.md` with the `SourceQualificationRecord` fields from `data-model.md` and initial STUDY/ADAPT entries for Graphify, code-graph-rag, DeepSeek Harness, and Continue without copying their source.
- [ ] T006 [P] Create fixture/test directory skeleton under `fixtures/repos/`, `fixtures/engines/`, `fixtures/mcp/`, `fixtures/policies/`, `tests/contract/`, `tests/integration/`, and `tests/adversarial/`.
- [ ] T007 Add `AGENTS.md` with implementation authority boundaries: no donor source copy without qualification, no live exploitation, no target build/install execution during analysis, no weakening constitution/spec/contracts.

**Checkpoint:** Workspace can compile empty crates; governance gates are explicit.

---

## Phase 2 — Foundational Trusted Substrate

**Purpose:** Blocking prerequisites for every user story. No user-story implementation begins until these contracts are green.

### Canonical schema

- [ ] T008 Implement schema-version and canonical serialization primitives in `crates/sentrdel-schema/src/version.rs` and `crates/sentrdel-schema/src/canonical.rs` with deterministic hashing tests in `crates/sentrdel-schema/tests/canonical.rs`.
- [ ] T009 [P] Implement `Evidence`, `ProducerKind`, `EpistemicClass`, `ConfidenceBand`, subjects and locations in `crates/sentrdel-schema/src/evidence.rs` with invalid-authority tests in `crates/sentrdel-schema/tests/evidence_authority.rs`.
- [ ] T010 [P] Implement `Finding`, severity, two-axis lifecycle, `AcceptedRisk`, and transition validation in `crates/sentrdel-schema/src/finding.rs` with lifecycle tests in `crates/sentrdel-schema/tests/finding_lifecycle.rs`.
- [ ] T011 [P] Implement `CoverageRecord` and coverage states in `crates/sentrdel-schema/src/coverage.rs` with tests proving failure/unavailable cannot masquerade as covered in `crates/sentrdel-schema/tests/coverage.rs`.
- [ ] T012 [P] Implement ASEL envelope, actors, event kinds, hash-link fields, `PolicyDecision`, verdict and `EnforcementFidelity` in `crates/sentrdel-schema/src/asel.rs` and `crates/sentrdel-schema/src/policy.rs`.
- [ ] T013 [P] Implement `ProjectProfile`, provider/framework detection records, `SecurityPackManifest`, `EngineManifest`, and `EngineRun` schema types in `crates/sentrdel-schema/src/project.rs`, `pack.rs`, and `engine.rs`.
- [ ] T014 Generate/check versioned JSON Schemas into `schemas/v1/` from `crates/sentrdel-schema/src/schema_export.rs` and add contract tests in `tests/contract/schema_roundtrip.rs`.
- [ ] T015 Add type-level/public-API restrictions so the LLM reasoner adapter can construct only INFERENCE/HYPOTHESIS evidence in `crates/sentrdel-schema/src/reasoner.rs` with compile/runtime contract tests in `tests/contract/reasoner_authority.rs`.

### Store and integrity

- [ ] T016 Implement SQLite connection, migrations, WAL configuration, and migration tests in `crates/sentrdel-store/src/db.rs`, `crates/sentrdel-store/migrations/`, and `crates/sentrdel-store/tests/migrations.rs`.
- [ ] T017 [P] Implement BLAKE3 content-addressed Evidence persistence and immutable lookup APIs in `crates/sentrdel-store/src/evidence.rs` with idempotency tests.
- [ ] T018 [P] Implement Finding projection/history, CoverageRecord, ProjectProfile, EngineRun and manifest persistence in `crates/sentrdel-store/src/findings.rs`, `coverage.rs`, `project.rs`, and `engine.rs`.
- [ ] T019 Implement secret-redaction-before-persist boundary in `crates/sentrdel-store/src/redaction.rs` and add canary tests proving plaintext never appears in SQLite/export/log fixtures in `tests/adversarial/secret_persistence.rs`.
- [ ] T020 Implement ASEL append-only event chain and head verification in `crates/sentrdel-store/src/asel.rs` with tamper tests in `tests/adversarial/asel_tamper.rs`.

### Policy kernel

- [ ] T021 Implement normalized action digest and the `ALLOW < ASK < DENY` lattice plus `UNDECIDABLE` handling in `crates/sentrdel-policy/src/decision.rs`.
- [ ] T022 Implement Rust-owned kernel invariant interface and initial workspace/evidence-integrity policy invariants in `crates/sentrdel-policy/src/kernel.rs`.
- [ ] T023 Integrate Regorus behind `crates/sentrdel-policy/src/rego.rs` using a tested supported Rego subset and policy fixtures in `fixtures/policies/`.
- [ ] T024 Implement monotonic policy composition and repository-policy narrowing validation in `crates/sentrdel-policy/src/compose.rs` and `config.rs`.
- [ ] T025 Add property/adversarial tests proving no policy/plugin ordering can downgrade a kernel DENY in `tests/adversarial/policy_monotonicity.rs`.

### Engine boundary

- [ ] T026 Implement `Engine` trait, request/limits/result types, and adapter registry in `crates/sentrdel-engine/src/lib.rs`, `request.rs`, and `registry.rs`.
- [ ] T027 Implement the only allowed external process runner using argv arrays, bounded environment/cwd/time/stdout/stderr in `crates/sentrdel-engine/src/process.rs`.
- [ ] T028 Implement strict raw-result/SARIF adapter boundary and repository-relative location normalization in `crates/sentrdel-engine/src/adapters/`.
- [ ] T029 Add malformed JSON, output flood, timeout, non-zero, missing executable, and out-of-root path fixtures/tests in `fixtures/engines/` and `tests/adversarial/engine_boundary.rs`.
- [ ] T030 Prove every engine termination path emits explicit CoverageRecord state in `tests/contract/engine_coverage.rs`.

### Evidence graph

- [ ] T031 Implement stable graph node/edge identities, provenance and confidence-source types in `crates/sentrdel-graph/src/model.rs`.
- [ ] T032 [P] Implement SQLite graph persistence mapping in `crates/sentrdel-graph/src/store.rs`.
- [ ] T033 [P] Implement `petgraph` projection, reverse reachability/blast-radius traversal, and graph-diff primitives in `crates/sentrdel-graph/src/query.rs` and `diff.rs` with deterministic fixtures.
- [ ] T034 Define SCIP ingestion interface and coverage behavior without making an indexer mandatory in `crates/sentrdel-graph/src/scip.rs` and tests in `crates/sentrdel-graph/tests/scip_coverage.rs`.

### Foundational CLI envelope

- [ ] T035 Implement stable CLI exit-code and JSON envelope types from `contracts/cli-contract.md` in `crates/sentrdel-cli/src/exit.rs` and `output.rs` with contract tests in `tests/contract/cli_envelope.rs`.
- [ ] T036 Wire dependency injection/bootstrap across schema/store/graph/engine/policy in `crates/sentrdel-cli/src/runtime.rs` without adding review/guard command behavior yet.

**Foundational Checkpoint:** schema/store/policy/engine/graph/CLI contracts pass; implementation may advance to user stories.

---

## Phase 3 — User Story 1: Review an AI-generated change

**Goal:** High-signal, evidence-backed, diff-first review that works locally regardless of coding-agent vendor.

**Independent test:** fixture diff containing changed secret, vulnerable structural pattern, known dependency advisory fixture and CI-sensitive change yields correct Evidence/Findings/Coverage and blocking exit behavior.

- [ ] T037 [US1] Implement read-only repository discovery and diff/base selection without target hook execution using qualified `gix` APIs in `crates/sentrdel-review/src/git.rs`; add rename/delete/binary/shallow fixtures in `fixtures/repos/git-diffs/`.
- [ ] T038 [P] [US1] Implement bounded repository/file view and path normalization in `crates/sentrdel-review/src/project_view.rs` with symlink/path-confusable/oversized tests in `tests/adversarial/repo_input.rs`.
- [ ] T039 [P] [US1] Integrate tree-sitter/`ast-grep-core` native producer framework in `crates/sentrdel-review/src/producers/structural.rs` and create Sentrdel-owned rule format under `rules/structural/`.
- [ ] T040 [P] [US1] Implement a deliberately small high-signal structural rule set and positive/negative fixtures under `rules/structural/` and `fixtures/repos/structural/`.
- [ ] T041 [P] [US1] Implement native changed-secret producer with redacted Evidence in `crates/sentrdel-review/src/producers/secrets.rs` and Sentrdel-owned/qualified rule data under `rules/secrets/`.
- [ ] T042 [P] [US1] Implement supported lockfile dependency-delta parser and offline advisory fixture provider in `crates/sentrdel-review/src/producers/dependencies/` and `fixtures/repos/dependencies/`.
- [ ] T043 [P] [US1] Add optional OSV-compatible advisory lookup/cache adapter respecting `--no-network` in `crates/sentrdel-review/src/advisories/` with fully offline contract tests.
- [ ] T044 [P] [US1] Implement CI security-sensitive change producer for GitHub Actions workflow permissions/secrets/OIDC/untrusted-PR/action-reference changes in `crates/sentrdel-review/src/producers/ci.rs` with fixtures under `fixtures/repos/github-actions/`.
- [ ] T045 [US1] Implement Evidence fingerprinting/correlation/reconciliation into canonical Findings in `crates/sentrdel-review/src/reconcile.rs`, retaining independent provenance and contradictions.
- [ ] T046 [US1] Connect changed symbols and graph reverse reachability to finding context without claiming unsupported semantic edges in `crates/sentrdel-review/src/blast_radius.rs`.
- [ ] T047 [US1] Implement review coverage matrix aggregation in `crates/sentrdel-review/src/coverage.rs` so absent/failed producers are visible.
- [ ] T048 [US1] Implement `sentrdel review` command and human/JSON output in `crates/sentrdel-cli/src/commands/review.rs` using the frozen exit-code contract.
- [ ] T049 [US1] Add end-to-end clean/vulnerable/contradictory/missing-engine review tests in `tests/integration/review.rs` and adversarial prompt/comment fixtures proving deterministic producers are unaffected by repository instructions.

**Checkpoint US1:** useful offline review works before guard/provider breadth.

---

## Phase 4 — User Story 2: Guard controllable agent actions

**Goal:** Vendor-neutral MCP enforcement + tamper-evident ASEL + honest partial git-hook guardrails.

**Independent test:** fixture MCP calls exercise ALLOW, ASK, kernel DENY, UNDECIDABLE and malicious tool-result cases; DENY cannot be downgraded.

- [ ] T050 [US2] Qualify/pin the official `rmcp` dependency and implement MCP protocol adapter boundary in `crates/sentrdel-guard/src/mcp/protocol.rs` with version/conformance fixtures.
- [ ] T051 [P] [US2] Implement MCP server/tool inventory and description/schema content hashes in `crates/sentrdel-guard/src/mcp/inventory.rs`.
- [ ] T052 [US2] Implement MCP gateway request normalization, pre-invocation policy, scoped approval and forwarding in `crates/sentrdel-guard/src/mcp/gateway.rs`.
- [ ] T053 [US2] Persist ASEL discovery/invocation/approval/denial/tool-result events around the gateway in `crates/sentrdel-guard/src/events.rs`.
- [ ] T054 [P] [US2] Implement instruction-shaped/untrusted tool-description/result detection as Evidence/candidate telemetry without allowing payload text to alter policy in `crates/sentrdel-guard/src/mcp/untrusted_content.rs`.
- [ ] T055 [US2] Implement `sentrdel guard mcp` CLI and enforced-fidelity reporting in `crates/sentrdel-cli/src/commands/guard_mcp.rs`.
- [ ] T056 [P] [US2] Implement safe git-hook installation/composition/uninstall metadata in `crates/sentrdel-guard/src/git_hooks.rs` without overwriting unrelated hooks.
- [ ] T057 [US2] Implement `sentrdel guard install-git-hooks` CLI with `PARTIAL` fidelity warning in `crates/sentrdel-cli/src/commands/guard_hooks.rs`.
- [ ] T058 [US2] Add fixture MCP client/server and end-to-end guard tests in `fixtures/mcp/` and `tests/integration/mcp_guard.rs` covering malicious descriptions/results and ASEL chain verification.

**Checkpoint US2:** Sentrdel can truthfully enforce MCP calls it proxies and honestly label local hook limitations.

---

## Phase 5 — User Story 3: Initialize and understand coverage

**Goal:** Safe stack/provider detection and Security Pack contract without premature provider security claims.

**Independent test:** Next.js+Supabase fixture reports Supabase detected and deep pack not implemented/covered; Rust/Python/mixed fixtures produce deterministic profiles.

- [ ] T059 [P] [US3] Implement bounded language/ecosystem detection in `crates/sentrdel-review/src/detect/languages.rs` and `ecosystems.rs` using file/config evidence only.
- [ ] T060 [P] [US3] Implement CI and MCP configuration detection in `crates/sentrdel-review/src/detect/ci.rs` and `mcp.rs` without reading secret values.
- [ ] T061 [US3] Implement Security Pack registry/manifest validation in `crates/sentrdel-review/src/packs/registry.rs`; packs may emit Evidence/Coverage only.
- [ ] T062 [P] [US3] Implement Supabase provider **detection only** in `crates/sentrdel-review/src/packs/supabase/detect.rs` using config/migrations/package signals and create positive/negative fixtures under `fixtures/repos/providers/supabase/`.
- [ ] T063 [P] [US3] Implement generic provider/framework detection extension points in `crates/sentrdel-review/src/detect/providers.rs` without adding deep Firebase/cloud/payment analysis.
- [ ] T064 [US3] Implement ProjectProfile persistence and coverage matrix generation in `crates/sentrdel-review/src/profile.rs`.
- [ ] T065 [US3] Implement `sentrdel init` human/JSON output in `crates/sentrdel-cli/src/commands/init.rs` including explicit `NOT_IMPLEMENTED/PARTIAL` provider-pack coverage.
- [ ] T066 [US3] Add integration/adversarial initialization tests in `tests/integration/init.rs` and `tests/adversarial/init_repo.rs` covering symlinks, oversized paths/config, weakening repo config and Supabase detection-without-verdict.

**Checkpoint US3:** users know what Sentrdel sees and what it does not yet protect.

---

## Phase 6 — User Story 4: Explain findings

**Goal:** Make evidence rigor usable by non-security developers.

**Independent test:** stored finding renders novice impact, practitioner narrative and full evidence chain without mutating state.

- [ ] T067 [P] [US4] Implement three-tier finding presentation model in `crates/sentrdel-review/src/explain.rs` with actor/capability/object impact sentence requirements.
- [ ] T068 [P] [US4] Implement evidence/provenance graph subtree query for a Finding in `crates/sentrdel-graph/src/explain.rs`.
- [ ] T069 [US4] Implement `sentrdel explain <finding-id>` in `crates/sentrdel-cli/src/commands/explain.rs` with human and JSON detail modes.
- [ ] T070 [US4] Add golden/contract tests in `tests/contract/explain_output.rs` proving explanation cannot change canonical severity/proof/workflow state.

---

## Phase 7 — User Story 5: Optional hypothesis-only LLM reasoning

**Goal:** Contextual reasoning without model authority over security truth.

**Independent test:** hostile source/MCP text instructing the model to suppress/verify a finding cannot produce an authoritative state change.

- [ ] T071 [US5] Implement provider-neutral optional reasoner trait and bounded evidence/substrate request model in `crates/sentrdel-review/src/reasoner/mod.rs`.
- [ ] T072 [P] [US5] Implement local HTTP/Ollama-compatible adapter behind feature/config gate in `crates/sentrdel-review/src/reasoner/local.rs`.
- [ ] T073 [P] [US5] Implement generic explicitly configured remote HTTP adapter interface without provider SDK authority in `crates/sentrdel-review/src/reasoner/remote.rs`; never upload whole repo by default.
- [ ] T074 [US5] Add strict reasoner output validation/mapping to INFERENCE/HYPOTHESIS Evidence in `crates/sentrdel-review/src/reasoner/map.rs`.
- [ ] T075 [US5] Add prompt-injection/adversarial authority tests in `tests/adversarial/reasoner_injection.rs` proving no suppression, FACT/VERIFIED escalation, or kernel-policy downgrade.
- [ ] T076 [US5] Wire `--reason` and `--no-network` behavior into `crates/sentrdel-cli/src/commands/review.rs` without making deterministic review depend on a model.

---

## Phase 8 — Release Hardening and Cross-Cutting Quality

- [ ] T077 Build a reproducible local R1 benchmark harness under `tests/benchmark/` for clean/vulnerable PR fixtures, false positives, latency, memory and guard false-block scenarios; keep public SentrdelBench as roadmap R8.
- [ ] T078 Add release-gate test/report that fails qualification if clean-PR FP exceeds 1 per 5 clean PRs for gated rules in `tests/benchmark/release_gate.rs`.
- [ ] T079 [P] Add warm review latency benchmark target (<5s p95 for <2k changed LOC reference fixture; <30s broader warm target) in `tests/benchmark/review_perf.rs` with benchmark-machine metadata.
- [ ] T080 [P] Add MCP guard decision latency benchmark target (<50ms p95 excluding downstream/human time) in `tests/benchmark/guard_perf.rs`.
- [ ] T081 Add cross-platform GitHub Actions CI for fmt/clippy/test/base review-init contracts on Linux/macOS/Windows in `.github/workflows/ci.yml`; enforcement-specific tests may be platform-qualified but must not be mislabeled.
- [ ] T082 Add Sentrdel self-security CI gates in `.github/workflows/security.yml` for dependency/license/advisory checks and source-qualification validation.
- [ ] T083 [P] Document R1 threat model and trust boundaries in `docs/security/threat-model.md` based on constitution/research/adversarial tests.
- [ ] T084 [P] Document architecture and evidence/ASEL concepts in `docs/architecture/overview.md`, `docs/architecture/evidence.md`, and `docs/architecture/asel.md`.
- [ ] T085 Update root `README.md` with only implemented/verified R1 capabilities and explicit roadmap/non-claims; do not advertise future Supabase deep pack, verification or universal guard as shipped.
- [ ] T086 Run the full Spec Kit consistency/analyze pass against constitution, spec, plan, contracts and tasks; record findings/repairs in `specs/001-v0-1-evidence-guard-foundation/analysis.md`.
- [ ] T087 Run implementation closeout qualification: workspace tests/lints, adversarial suite, benchmark release gates, no secret canary persistence, no unqualified donor source, and record exact results in `specs/001-v0-1-evidence-guard-foundation/implementation-closeout.md`.

---

## Dependencies

```text
Phase 1 Setup
    |
    v
Phase 2 Foundational substrate
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

- US1/US2/US3 may proceed in parallel after Phase 2 if separate files/owners are used.
- US4 depends on canonical findings/store and is best completed after US1 reconciliation exists.
- US5 depends on canonical evidence/reconciliation but must remain optional.
- Release hardening depends on all in-scope user stories.

## Parallel Execution Examples

### Foundational

After T008 canonical primitives:

- T009 Evidence, T010 Findings, T011 Coverage, T012 ASEL/Policy, T013 Project/Pack/Engine schemas can proceed in parallel.
- After DB T016: T017 evidence persistence and T018 other projections can proceed in parallel while T019 redaction is developed against the persistence boundary.
- T031 graph model allows T032 persistence and T033 query/diff work in parallel.

### User stories

After Phase 2:

- US1 producer tasks T039–T044 can run in parallel after project-view/git interfaces are stable.
- US2 inventory T051 and git-hook T056 can run in parallel with MCP protocol T050; gateway T052 waits for protocol + policy.
- US3 language/ecosystem T059, CI/MCP T060 and Supabase detector T062 can run in parallel after pack/profile schema exists.

## Implementation Strategy

### MVP-first

The first externally useful checkpoint is US1 after the foundational substrate. Do not delay `sentrdel review` waiting for provider packs, IDEs, full graph semantics, verification, or runtime enforcement.

### Incremental value

1. **Schema/store/policy integrity first** — prove Sentrdel can represent truth safely.
2. **Review second** — every agent can benefit immediately.
3. **MCP Guard third** — first genuine vendor-neutral enforcement seam.
4. **Init/provider detection** — establishes honest A-to-Z coverage map.
5. **Explain** — turns rigor into usable judgment.
6. **Optional reasoner** — adds context only after authority boundaries are proven.
7. **Hardening** — release only if FP/false-block/security/performance gates pass.

## Explicitly Deferred to Later Specs

Do not create implementation tasks in R1 for:

- full Supabase RLS/Auth/Storage/Edge Function security pack;
- Firebase or broad cloud/payment packs;
- sandboxed verification/exploit-condition execution;
- auto-fix application;
- eBPF/runtime enforcement;
- VS Code/Cursor/JetBrains/GitHub App integrations;
- universal CPG/compiler implementations;
- broad scanner/rule-count expansion.
