# Tasks: Supabase P0 Static/Posture Pack

**Input:** Constitution, R1 canonical contracts, R2 `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, `contracts/static-posture-contract.md`, `checklists/implementation-readiness.md`.  
**Status:** IMPLEMENTATION_READY — R2 planning is canonical; proceed in task order.

## Format

`- [ ] R2-T### [P?] Description`

`[P]` means safely parallel only after all stated prerequisites.

---

## Phase 0 — Canonical planning gate

- [x] R2-T001 Canonicalize the complete R2 Spec Kit planning slice on protected `main`: exact-head applicable CI, clean review state, expected-head merge, post-merge protected-main evidence, then close the final item in `checklists/implementation-readiness.md`. **Blocks every product implementation task below.**

**Checkpoint:** R2 planning and readiness are canonical. No product code changes occur before this checkpoint.

---

## Phase 1 — Provider contract and benchmark fixtures

- [x] R2-T002 Add the versioned Supabase R2 Security Pack manifest and provider coverage dimension constants using existing R1 `SecurityPackManifest`/Coverage contracts; no Finding or policy override capability.
- [x] R2-T003 [P] Create positive/negative/adversarial fixture repository matrix under `fixtures/repos/r2-supabase/` for RLS, grants, policies, SECURITY DEFINER/search_path, Storage, Auth config, Edge Function auth, key authority contexts, malformed/oversized/dynamic SQL, ambiguous migration order, and secret canaries.
- [x] R2-T004 [P] Extend SentrdelBench corpus metadata for R2 supported scope, expected Evidence groups, clean cases, explicit coverage-gap cases, and authority assertions before release-gating rules are added.

**Checkpoint:** provider manifest and ground-truth fixture/evaluation contracts exist before parser/rule breadth.

---

## Phase 2 — Bounded migration and SQL substrate

- [x] R2-T005 Implement canonical Supabase migration discovery/order from bounded repository paths; reject ambiguous duplicate order keys and never execute migrations.
- [x] R2-T006 Implement bounded SQL tokenizer/statement splitter with explicit caps for bytes, statements, tokens/nesting, and diagnostics; hostile comments/strings/dollar quoting cannot cause unbounded behavior.
- [x] R2-T007 Implement the supported SQL statement model for schemas/relations, RLS enable/disable, policies, grants/revokes, functions/security attributes, and minimal view/exposure attributes required by R2.
- [x] R2-T008 Implement deterministic repository-derived posture state reduction with per-property statement provenance and first-class UNKNOWN state.
- [x] R2-T009 Add parser/state adversarial tests proving unsupported security-relevant SQL and malformed/bounded rejection reduce coverage instead of producing clean posture; dynamic SQL is never executed or semantically invented.

**Checkpoint:** R2 can safely derive only its declared repository state subset with deterministic replay and visible parser gaps.

---

## Phase 3 — Database and Storage static posture

- [x] R2-T010 Implement conservative API/exposed-schema evidence from repository-visible Supabase configuration/defaults only where the contract proves it; unknown hosted exposure remains UNKNOWN.
- [x] R2-T011 Implement RLS posture producer for API-relevant relations, keeping direct RLS observations separate from security interpretation and final live-state claims.
- [x] R2-T012 [P] Implement supported policy posture/delta producer, including policy removal/widening observations without pretending to solve arbitrary SQL boolean equivalence.
- [x] R2-T013 [P] Implement supported GRANT/REVOKE posture for API-facing roles; grants remain an independent control from RLS/policies.
- [x] R2-T014 Implement SECURITY DEFINER/search_path/schema/execute-grant posture producer; SECURITY DEFINER alone is not labeled exploitable.
- [x] R2-T015 [P] Map supported Storage authorization policy SQL through the same relation/policy evidence substrate with Storage-specific subjects/coverage.
- [x] R2-T016 Add positive/negative/correlation tests proving RLS, grants, policies, function authority, and Storage Evidence preserve independent provenance and reconcile only through the existing R1 reconciler.

---

## Phase 4 — Config, key authority, Auth, and Edge Functions

- [x] R2-T017 Implement bounded allowlisted `supabase/config.toml` parser with explicit size/depth/collection limits; unknown security-relevant configuration degrades affected coverage.
- [x] R2-T018 Implement Supabase key authority classification for modern publishable/secret and legacy anon/service-role classes while routing secret material through the R1 redaction-before-persist boundary.
- [x] R2-T019 Implement conservative source execution-context classification for browser/client, server, Edge Function, test/fixture, and UNKNOWN contexts using bounded repository evidence only.
- [x] R2-T020 Implement elevated secret/service-role key-in-client-context producer with negative fixtures proving backend/Edge Function use is not automatically a finding.
- [x] R2-T021 Implement bounded repository-visible Auth/API configuration posture checks frozen by the R2 contract; unsupported hosted-only settings remain visible coverage gaps.
- [x] R2-T022 Implement Edge Function authorization posture for platform JWT/auth verification and supported explicit replacement authorization patterns; disabled verification alone is a signal, not unconditional vulnerability.
- [x] R2-T023 Add secret-persistence, prompt/instruction-authority, malformed config/source, and no-network/no-target-execution adversarial tests for all Phase 4 paths.

---

## Phase 5 — R1 integration and developer output

- [x] R2-T024 Replace R1 Supabase `NOT_IMPLEMENTED` static posture handoff with the R2 pack orchestration while preserving compatible detection behavior and explicit LIVE_POSTURE/BUSINESS_LOGIC/RUNTIME gaps.
- [x] R2-T025 Register R2 provider Evidence/Coverage in `sentrdel review` and `sentrdel init` without adding a provider-specific Finding bypass.
- [ ] R2-T026 Extend `sentrdel explain` provider context so R2 Findings show static provenance, affected Supabase object/control layer, and explicit non-live limitation.
- [ ] R2-T027 Add E2E fixture repositories proving review/init/explain deterministic behavior across safe, vulnerable, contradictory/unknown, unsupported syntax, and hostile repository cases.

---

## Phase 6 — Evaluation, self-security, and release hardening

- [ ] R2-T028 Run/promote the initial release-gating R2 rule set through SentrdelBench: active clean-PR FP threshold, zero known misses in declared fixture scope, deterministic replay, explicit coverage, authority assertions, and provider-specific evidence quality.
- [ ] R2-T029 Add R2 latency/resource benchmarks with machine metadata and caps; regression gates must not weaken existing R1 review targets without an explicit spec amendment.
- [ ] R2-T030 Run dependency/source governance; if no dependency was added, prove the locked graph remains qualified; if one was added, require exact qualification/privileged-surface records before merge.
- [ ] R2-T031 Run Linux/macOS/Windows supported-path qualification and adversarial no-network/no-execution/secret canaries; platform limitations remain explicit coverage.
- [ ] R2-T032 Update README/threat model/architecture/provider coverage documentation to describe implemented R2 static posture and preserve non-claims for live posture and R3 business logic.
- [ ] R2-T033 Run final R2 Spec Kit consistency analysis against Constitution, roadmap, R1 contracts, R2 spec/plan/contracts/tasks and record repairs in `analysis.md`.
- [ ] R2-T034 Run R2 implementation closeout: exact workspace/tests/lints/benchmarks, secret canaries, no provider/target execution, coverage truth, dependency qualification, protected-main governance, and exact results in `implementation-closeout.md`.
- [ ] R2-T035 Canonicalize R2 closeout and mark all R2 tasks complete only after exact-head applicable CI, clean review, expected-head merge, post-merge protected-main evidence, and confirmation that no task remains open.

---

## Dependencies

```text
R2-T001 canonical planning/readiness
        |
        v
R2-T002..T004 contracts + fixtures + benchmark ground truth
        |
        v
R2-T005..T009 bounded SQL/migration substrate
        |
        +---------------------------+
        |                           |
        v                           v
R2-T010..T016 DB/Storage      R2-T017..T023 config/key/Auth/Edge
        |                           |
        +-------------+-------------+
                      |
                      v
               R2-T024..T027 integration
                      |
                      v
               R2-T028..T035 hardening/closeout
```

Database/Storage and config/key/Auth/Edge work may run in parallel only after the bounded SQL/migration substrate and ground-truth fixture contracts are canonical enough for their inputs. Integration waits for both branches of posture work.

## Implementation discipline

- One task or tightly coupled atomic task group per implementation PR unless the canonical task dependencies make a combined PR safer.
- Every security-boundary change carries tests in the same PR.
- No task may weaken R1 Evidence, redaction, coverage, policy, target-execution, or dependency gates.
- No release-gating rule is promoted solely because it detects more cases; precision, known misses, authority correctness, coverage truth, and resource behavior are mandatory.
- No live Supabase access, provider-admin credential use, SQL execution, or R3 business-logic implementation is authorized by this task list.
