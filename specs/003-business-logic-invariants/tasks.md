# Tasks: Business-Logic Substrate + Invariants

**Input:** Constitution, roadmap, completed R1/R2 contracts, R3 `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`, `contracts/business-logic-contract.md`, `contracts/project-invariant-contract.md`, and `checklists/implementation-readiness.md`.  
**Status:** IMPLEMENTATION_READY — R3-T001 planning/readiness evidence is proven; product implementation may begin only after this status-canonicalization change completes its own protected-main qualification and governance proof.

## Format

`- [ ] R3-T### [P?] Description`

`[P]` means safely parallel only after all stated prerequisites are canonical.

---

## Phase 0 — Canonical planning gate

- [x] **R3-T001** Canonicalize the complete R3 Spec Kit planning slice on protected `main`: exact-head applicable CI, clean independent review, zero unresolved conversations, guarded expected-head merge, post-merge required CI, live repository-governance proof, then separately canonicalize the final implementation-readiness gates and this task checkbox. **Blocks every product implementation task below until this status-canonicalization change is itself canonical and post-merge proven.**

**Checkpoint:** R3 planning/readiness evidence is complete and roadmap status may be `implementation-ready`. No product code or dependency adoption occurs until this status-canonicalization change itself completes exact-head qualification, guarded merge, post-merge CI and live governance proof.

---

## Phase 1 — Contracts, ground truth, and evaluation metadata

- [x] **R3-T002** Add the versioned R3 business-logic Security Pack/coverage manifest using existing R1 pack and canonical `CROSS_LAYER_BUSINESS_LOGIC`/`BUSINESS_LOGIC` coverage contracts; outputs remain Evidence + Coverage only with no Finding/policy override capability.
- [x] **R3-T003** [P] Create synthetic fixture repository matrix under a dedicated R3 fixture namespace covering safe/unsafe/unknown Express, Next.js, Supabase Edge and Supabase data-operation paths for tenant binding, privileged role checks, protected-property mutation, elevated-client boundaries, malformed/dynamic source, unsupported framework behavior and secret/no-execution canaries.
- [x] **R3-T004** [P] Extend SentrdelBench corpus metadata for the frozen R3 supported scope, expected direct/cross-layer Evidence groups, clean cases, explicit coverage gaps, authority assertions and protected-holdout eligibility before release-gating detector breadth.
- [x] **R3-T005** Freeze and implement the bounded internal cross-layer IR from `data-model.md`: stable route/actor/guard/value/data/client/link/path/invariant identities, provenance, UNKNOWN semantics, deterministic ordering and resource caps; no public schema widening unless separately justified.
- [x] **R3-T006** Freeze the tightening-only built-in/project invariant evaluator contract and validation fixtures proving repository declarations cannot suppress Evidence, waive Findings, lower severity, widen authority, impersonate built-in/kernel invariants or execute content.

**Checkpoint:** ground truth, cross-layer identities and authority ceilings are canonical before framework detector breadth.

---

## Phase 2 — Bounded structural extraction

- [x] **R3-T007** Qualify the TypeScript grammar dependency candidate only if required for the declared adapter scope: record exact upstream repository/ref/package/checksum/license/features, `build.rs`/`cc`/native/generated/proc-macro/download/network/credential surfaces, lockfile closure and privileged-dependency entries; run Self Security. If qualification does not complete safely, do not adopt the dependency and preserve narrower honest language coverage.
- [x] **R3-T008** Extend the structural registry only for the language support canonical after R3-T007, preserving Sentrdel-owned rules, malformed-syntax failure, deterministic match ordering, document/rule/pattern caps and no repository-provided grammar/rule execution.
- [x] **R3-T009** Implement bounded route extraction for the frozen initial adapters: Express-style method/path/callback chains, Next.js App Router Route Handlers, Next.js Pages API routes and supported Supabase Edge Function handlers; unsupported dynamic registration/middleware becomes explicit coverage.
- [x] **R3-T010** Implement supported actor/auth context extraction for request-controlled inputs, authenticated user/tenant/role sources, constants and UNKNOWN; static auth-call recognition never claims runtime identity validity.
- [x] **R3-T011** Implement typed guard extraction for authentication, role/function authorization, tenant/ownership/object membership, property allowlisting and elevated-client boundaries with explicit supported dominance/link scope.
- [x] **R3-T012** Implement bounded value-origin derivation with hard depth/fan-in caps; supported assignments/parameters/destructuring/member access may link values, while unsupported dynamic expressions terminate in UNKNOWN rather than lexical name equivalence.
- [x] **R3-T013** Implement the frozen Supabase JavaScript data-operation subset for relation/resource identity, read/insert/update/upsert/delete/RPC observations, supported filters, selected/mutated fields and broad request-controlled mutation objects; no query execution or hosted-state claims.
- [x] **R3-T014** Add positive/negative/adversarial extraction tests for malformed syntax, dynamic middleware/routes/queries/properties, oversized documents/match counts/derivations, generated/unsupported source and instruction-shaped repository content; every unsupported security-relevant area degrades coverage.

**Checkpoint:** R3 can extract only its declared local semantics safely and deterministically before cross-layer correlation or invariant verdicts.

---

## Phase 3 — Graph, semantic links, and cross-layer correlation

- [x] **R3-T015** Map validated R3 observations onto the existing thin `sentrdel-graph` only where existing stable node/relation vocabulary is semantically valid; preserve provenance/confidence separation and graph/path caps; do not create a second graph runtime or universal CPG.
- [x] **R3-T016** Add bounded inter-file linking using safe local import/callback relationships and optional already-qualified SCIP references; semantic-index absence/ambiguity remains explicit linking coverage and never a clean fallback.
- [x] **R3-T017** Implement deterministic bounded route → actor/guard/value → data-operation/provider-client correlation with stable path identities, link basis/confidence metadata and UNKNOWN/PARTIAL propagation; cap graph nodes/edges/depth/candidate paths/diagnostics.
- [x] **R3-T018** Integrate canonical R2 Supabase Evidence/Coverage as supporting inputs for RLS/policy/grant/key/client/static-context correlation while preserving R2 identities, provenance, static-vs-live limitations and the fact that elevated authority can bypass ordinary RLS semantics.
- [x] **R3-T019** Implement monotonic business-logic coverage aggregation for routes, actor identity, guards, value origins, data operations, local/semantic linking, R2 correlation, project invariants and invariant evaluation; an empty Finding set cannot erase partial/failed/unsupported dimensions.
- [x] **R3-T020** Add cross-layer correlation tests proving safe and unsafe paths remain distinguishable, ambiguous links do not satisfy invariants, graph confidence cannot upgrade epistemic authority, R2 static posture cannot become hosted truth and path-cap exhaustion fails visible.

**Checkpoint:** bounded cross-layer paths and coverage are trustworthy enough for invariant evaluation.

---

## Phase 4 — Built-in and project security invariants

- [x] **R3-T021** Implement tenant/object-binding invariant evaluation for the declared adapter/data-operation scope: request-selected user/tenant-owned resources require a supported authenticated actor/tenant relationship on the covered path; UNKNOWN linking cannot satisfy the invariant.
- [x] **R3-T022** Implement privileged function/role authorization invariants for supported admin/destructive/elevated routes/actions, requiring supported guard dominance/linkage rather than route naming or a lexical role string elsewhere.
- [ ] **R3-T023** Implement protected-property mutation invariants for supported broad request-controlled writes and explicit protected properties; safe explicit allowlists and dynamic/unknown field sets remain distinguishable.
- [ ] **R3-T024** Implement elevated provider-client application-boundary invariants for supported service-role/secret client use; elevated authority is contextual and escalates only with a supported risky request/guard/data path.
- [ ] **R3-T025** Implement the bounded project invariant loader/evaluator only under `contracts/project-invariant-contract.md`: versioned structured data, hard size/count/path/field caps, tightening-only semantics, built-in ID namespace separation, no suppressions/waivers/severity/risk acceptance/authority grants/executable content, and built-in analysis continues on malformed config.
- [ ] **R3-T026** Map invariant/path observations and interpretations to canonical Evidence/Coverage through runtime-owned producer authority; preserve direct-observation versus security-interpretation wording and existing reconciler-only Finding creation.

**Checkpoint:** initial invariant families are implemented with fail-visible uncertainty and unchanged judgment authority.

---

## Phase 5 — Developer-facing integration

- [ ] **R3-T027** Integrate R3 Evidence/Coverage into `sentrdel review` with deterministic changed-path prioritization and route/guard/data/invariant context without changing reconciler or policy authority.
- [ ] **R3-T028** Integrate R3 capability/profile/coverage discovery into `sentrdel init` or the existing project profile surface without representing unsupported frameworks as covered.
- [ ] **R3-T029** Extend `sentrdel explain` so R3 Findings can show the bounded supported route → guard/actor → data/client → invariant chain, R2 supporting Evidence and explicit static/coverage limitations; graph metadata is explanation context, not verdict authority.
- [ ] **R3-T030** Add E2E fixture repositories proving deterministic review/init/explain behavior across safe, vulnerable, contradictory/unknown, unsupported framework/semantic-link and hostile repository/project-invariant cases.

---

## Phase 6 — Evaluation, self-security, and canonical closeout

- [ ] **R3-T031** Run/promote the initial release-gating R3 invariant set through SentrdelBench: active clean-case FP threshold, declared-scope known-miss/recall gate, deterministic replay, explicit coverage/provenance, authority assertions, protected-holdout rules where applicable and cross-layer explanation correctness.
- [ ] **R3-T032** Add R3 latency/resource qualification with machine metadata and hard path/parser/graph/invariant caps; regressions cannot weaken existing review ceilings without an explicit spec amendment.
- [ ] **R3-T033** Run final dependency/source governance: prove unchanged qualified graph if no dependency was added, or exact qualification/privileged-surface/lockfile records for any adopted TypeScript grammar or other dependency; Self Security must pass on the exact candidate head.
- [ ] **R3-T034** Run Linux/macOS/Windows supported-path qualification and adversarial no-network/no-target-execution/project-invariant-authority/secret canaries; platform/language/framework limitations remain explicit coverage.
- [ ] **R3-T035** Update README, threat model and architecture/provider/coverage documentation to describe implemented R3 cross-layer static business-logic analysis and preserve non-claims for live provider posture, target execution, runtime exploitability, universal CPG and unsupported framework semantics.
- [ ] **R3-T036** Run final R3 Spec Kit consistency analysis against Constitution, roadmap, R1/R2 authority, R3 spec/clarification/research/plan/data-model/contracts/readiness/tasks and implemented behavior; record/repair only evidence-backed drift in `analysis.md`.
- [ ] **R3-T037** Run R3 implementation closeout: exact workspace/tests/lints/benchmarks, authority/secret/no-execution canaries, coverage truth, dependency qualification, cross-platform evidence and protected-main governance; record exact results in `implementation-closeout.md` without broadening claims.
- [ ] **R3-T038** Canonicalize R3 closeout and mark all R3 tasks complete only after exact-head applicable CI, clean independent review, zero unresolved conversations, guarded expected-head merge, post-merge required CI, live protected-main governance proof and confirmation that no R3 task remains open.

---

## Dependencies

```text
R3-T001 canonical planning/readiness
        |
        v
R3-T002..T006 contracts + fixtures + IR + evaluation ground truth
        |
        v
R3-T007..T014 bounded language/route/actor/guard/value/data extraction
        |
        v
R3-T015..T020 graph/link/correlation + R2 integration + coverage
        |
        v
R3-T021..T026 invariant families + Evidence mapping
        |
        v
R3-T027..T030 developer integration + E2E
        |
        v
R3-T031..T038 benchmark/hardening/closeout
```

Parallel work is permitted only where marked and only after shared contracts/prerequisites are canonical. Do not split coupled security-boundary changes in a way that leaves an authority path untested.

## Implementation discipline

- One task or tightly coupled atomic task group per implementation PR unless canonical dependencies make a combined PR safer.
- Every security-boundary change carries positive/negative/adversarial tests in the same PR.
- Every new commit invalidates earlier exact-head CI/review qualification for merge eligibility.
- No dependency enters before its explicit qualification task is canonical.
- No project declaration may weaken built-in analysis or judgment authority.
- No rule/invariant becomes release-gating solely because it detects more cases.
- No ordinary R3 path executes target/provider code or receives provider-admin credentials.
- No R3 Evidence claims runtime exploitability, actual cross-tenant access, or hosted truth without separately authorized stronger evidence.
- The existing reconciler remains the only canonical Finding authority.
