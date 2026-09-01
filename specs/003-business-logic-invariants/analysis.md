# Spec Kit Consistency Analysis: R3 Business-Logic Substrate + Invariants

**Date:** 2026-09-01  
**Scope:** Initial R3 planning slice before any product implementation.  
**Status:** CONSISTENT_PENDING_CANONICAL_PLANNING_GATE

## Canonical basis

- canonical planning baseline: `2d7b632ae745c4fda1bbd4e2ed3b7a3e119c5734`
- `.specify/memory/constitution.md` version `1.0.1`
- `AGENTS.md`
- `specs/000-sentrdel-roadmap/roadmap.md`
- `specs/000-sentrdel-roadmap/improvement-plan-2026-08-26.md`
- completed R1 Evidence + Guard Foundation authority/contracts
- completed R2 Supabase Static/Posture specification, contracts, task ledger, consistency and implementation closeout
- canonical Evidence/Coverage/reconciler/policy/kernel/graph/SCIP/SentrdelBench contracts
- R3 `spec.md`, `clarification-closeout.md`, `research.md`, `plan.md`, `data-model.md`
- R3 `contracts/business-logic-contract.md`
- R3 `contracts/project-invariant-contract.md`
- R3 `checklists/implementation-readiness.md`
- R3 `tasks.md`

## Result

The initial R3 planning slice is internally consistent with the Constitution, roadmap direction, completed R1/R2 authority model and existing trusted/evaluation substrate.

R3 is explicitly a **static, bounded cross-layer analysis and invariant slice**. It does not authorize target/provider execution, live-provider credentials, runtime exploitability proof, universal CPG construction, direct Finding creation, project suppressions or unqualified dependency adoption.

Product implementation remains blocked by R3-T001 until the initial planning PR and a separate planning-gate closeout are canonical on protected `main` with exact-head CI, independent review, guarded expected-head merge and post-merge governance proof.

## Roadmap reconciliation found during planning

### R3-A001 — stale R2 status / missing R3 sub-spec

**Finding:** At planning baseline `2d7b632ae745c4fda1bbd4e2ed3b7a3e119c5734`, the roadmap still marks R2 as `implementation-ready` even though Spec 002's canonical task ledger is `COMPLETE` through R2-T035. The R3 row remains `planned` with no sub-spec path despite R3 now entering its mandatory specification lifecycle.

**Risk:** A literal executor could treat completed R2 as the active implementation frontier or fail to identify the newly active R3 planning authority.

**Repair in this planning PR:**

- change R2 status from `implementation-ready` to `complete`;
- change R3 status from `planned` to `planning`;
- set R3 sub-spec to `specs/003-business-logic-invariants/`.

The repair does **not** mark R3 implementation-ready. That transition is reserved for the separately qualified R3-T001 planning-gate closeout after this initial planning slice is canonical.

## Authority consistency

### Rust trusted core

PASS. Planned route/actor/guard/value/data extraction, path correlation and invariant evaluation remain Rust-owned. External/project input remains data.

### Evidence Before Verdict

PASS. R3 producers emit Evidence/Coverage only. The existing reconciler remains the sole canonical Finding authority.

### Local-first / vendor-neutral

PASS. Base R3 requires no hosted provider, provider credential, target application runtime, database, browser or network service.

### Safe verification boundary

PASS. R3 does not execute target tests/apps/databases/provider tools to resolve ambiguity. Runtime/fix verification stays in separately specified Safe Verification authority.

### Honest coverage

PASS. Unsupported framework/language/middleware/query/identity/link semantics and resource-cap exhaustion remain explicit coverage/UNKNOWN state rather than implicit security.

### Graph authority

PASS. R3 reuses the existing thin `sentrdel-graph`, preserves `UNIVERSAL_CPG = false`, and keeps graph confidence below Evidence epistemic authority.

### R2 integration

PASS. R2 RLS/policy/grant/key/static Evidence is supporting input only. R3 preserves R2 provenance/static-vs-live limitations and does not treat RLS as sufficient application authorization, especially under elevated service-role authority.

### Project invariant authority

PASS. Project declarations are tightening-only requirements. Suppression, waiver, severity reduction, accepted risk, execution, credential/provider/network authority, policy/kernel/reconciler override and FACT/VERIFIED declaration are forbidden.

### Dependency governance

PASS. No TypeScript grammar or other dependency is authorized by planning. R3-T007 requires exact qualification before any candidate enters the build/trusted parser path; failure retains narrower honest coverage.

### Evaluation plane

PASS. R3 reuses SentrdelBench Core and freezes fixtures/expected Evidence/Coverage before release-gating breadth. Authority violations/hidden coverage remain disqualifying regardless of recall improvement.

## Cross-artifact consistency matrix

| Topic | Constitution/Roadmap | R1/R2 authority | R3 Spec/Clarification | R3 Plan/Model/Contracts | Tasks/Readiness | Result |
|---|---|---|---|---|---|---|
| Static/offline base mode | yes | yes | yes | yes | yes | CONSISTENT |
| No target/provider execution | yes | yes | yes | yes | yes | CONSISTENT |
| Reconciler-only Finding authority | yes | yes | yes | yes | yes | CONSISTENT |
| Explicit business-logic coverage | yes | yes | yes | yes | yes | CONSISTENT |
| Route/actor/guard/data separation | yes | compatible | yes | yes | yes | CONSISTENT |
| RLS/grants/application auth remain distinct | yes | yes | yes | yes | yes | CONSISTENT |
| Elevated client contextual, not automatically vulnerable | yes | yes | yes | yes | yes | CONSISTENT |
| UNKNOWN/unsupported never secure | yes | yes | yes | yes | yes | CONSISTENT |
| Existing graph only / no universal CPG | yes | yes | yes | yes | yes | CONSISTENT |
| SCIP optional and coverage-aware | yes | yes | yes | yes | yes | CONSISTENT |
| Project invariants tightening-only | yes | compatible | yes | yes | yes | CONSISTENT |
| No new dependency pre-authorized | yes | yes | yes | yes | yes | CONSISTENT |
| Benchmark before breadth | yes | yes | yes | yes | yes | CONSISTENT |
| Runtime/live exploitability excluded | yes | yes | yes | yes | yes | CONSISTENT |
| Two-stage canonical planning gate | yes | established precedent | yes | yes | yes | CONSISTENT |

## Design risk review

### Risk: framework breadth masquerades as semantic coverage

Mitigation: explicit adapter allowlists, per-surface coverage, positive/negative/unknown fixtures, dynamic behavior lowers coverage.

### Risk: false identity joins produce false tenant-isolation conclusions

Mitigation: explicit `ValueOrigin`/actor identities, supported derivation/link basis, lexical name equality rejected as proof.

### Risk: role/auth checks elsewhere in code are treated as dominating the operation

Mitigation: typed guards plus supported dominance/link scope are required to satisfy a path invariant.

### Risk: project declarations become a suppression channel

Mitigation: separate tightening-only contract, built-in namespace separation, forbidden suppression/waiver/severity/risk/authority fields, built-ins continue on malformed config.

### Risk: TypeScript need bypasses supply-chain governance

Mitigation: isolated R3-T007 qualification gate; no adoption if qualification is incomplete.

### Risk: static analysis claims exploitability

Mitigation: direct observation/security interpretation separation, explicit non-goals and Evidence wording contract; runtime authority remains separate.

## Planning readiness verdict

All **design/taskability** checklist items are satisfied. The only unchecked items are intentionally external/canonical gates:

1. initial planning PR exact-head qualification/review/merge/post-merge governance proof;
2. separate R3-T001 planning-gate closeout exact-head qualification/review/merge/post-merge governance proof.

No R3 product implementation is authorized before both are complete.

## Final verdict

**CONSISTENT_PENDING_CANONICAL_PLANNING_GATE**

The planning slice may proceed to exact-head repository qualification and independent review. This verdict does not authorize R3-T002 or later implementation tasks until R3-T001 is separately canonicalized after the initial planning merge.
