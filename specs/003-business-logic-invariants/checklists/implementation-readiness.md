# Implementation Readiness Checklist — R3 Business-Logic Substrate + Invariants

**Date:** 2026-09-01  
**Gate:** Product implementation MUST NOT start until every blocking item is checked and the complete planning slice plus R3-T001 planning closeout are canonical on protected `main`.

## Scope and authority

- [x] R3 has a bounded cross-layer authorization goal distinct from R2 static posture, credentialed live posture, R6 Safe Verification, and runtime enforcement.
- [x] Base mode is offline/static and deterministic.
- [x] Provider credentials, hosted-provider connections and target/runtime execution are excluded.
- [x] R1 Evidence/Coverage/reconciler/policy/kernel/redaction contracts remain authoritative.
- [x] R2 Supabase posture is supporting static evidence and cannot become live truth through R3 correlation.
- [x] R3 producers emit Evidence/Coverage only; direct Finding construction remains forbidden.
- [x] Universal CPG construction and a second canonical graph runtime are excluded.
- [x] Project invariant declarations are tightening-only and cannot suppress/widen authority.

## Specification quality

- [x] Tenant/object isolation has independent acceptance scenarios.
- [x] Function/role authorization has independent acceptance scenarios.
- [x] Protected-property mutation has independent acceptance scenarios.
- [x] Elevated provider-client authority has independent acceptance scenarios.
- [x] Project-declared invariant behavior has independent authority constraints.
- [x] Unsupported/dynamic semantics explicitly reduce coverage.
- [x] Runtime exploitability/live-provider non-claims are explicit.
- [x] Success criteria include precision/misses, provenance, coverage, determinism, authority and resource/no-execution gates.

## Research quality

- [x] Current R1/R2 structural, graph, SCIP, pack, coverage and benchmark substrate is documented.
- [x] Current OWASP object/property/function authorization semantics are recorded as research input.
- [x] Current Supabase grants/RLS/elevated-authority semantics are recorded without granting live-provider authority.
- [x] Current Express/Next route semantics inform bounded adapters without becoming runtime authority.
- [x] TypeScript grammar is recorded only as a dependency candidate, not pre-authorized.
- [x] Rejected alternatives include universal CPG, target execution, live-provider truth, regex-only verdicts and suppression-capable project configuration.

## Design quality

- [x] Constitution Check is PASS with no exception.
- [x] Cross-layer IR is defined before rule breadth.
- [x] Route, actor, guard, value-origin, data-operation, link/path, provider-client and invariant concepts are separated.
- [x] Stable identity/provenance and UNKNOWN semantics are explicit.
- [x] Existing `sentrdel-graph` is reused with graph confidence below epistemic authority.
- [x] Optional SCIP semantics remain coverage-aware.
- [x] Graph/path/parser/invariant resource caps are mandatory.
- [x] RLS/grants/application guards/elevated client authority remain independent layers.
- [x] No new public schema or dependency is assumed necessary without implementation evidence.

## Contract quality

- [x] Allowed and forbidden R3 inputs/actions are explicit.
- [x] Adapter and TypeScript dependency boundaries are explicit.
- [x] Actor/identity equivalence rules are conservative.
- [x] Guard scope/dominance requirements are explicit.
- [x] Data-operation observations do not claim execution.
- [x] R2 integration preserves static provenance and live-state non-claims.
- [x] Project invariant allowed/forbidden authority is explicit.
- [x] Project invariant malformed/unknown behavior cannot disable built-ins.
- [x] Determinism and benchmark promotion gates are explicit.

## Evaluation and self-security

- [x] SentrdelBench Core is reused rather than replaced.
- [x] Fixture/ground-truth contracts precede release-gating breadth.
- [x] Authority violations and hidden coverage gaps remain disqualifying even if detection improves.
- [x] New dependency adoption requires exact source/version/license/build/privileged qualification.
- [x] Cross-platform and no-network/no-target-execution qualification are planned before closeout.

## Taskability

- [x] Work is decomposed into planning, contracts/fixtures, extraction, correlation, invariants, integration/evaluation and closeout phases.
- [x] TypeScript grammar qualification is isolated before any dependency use.
- [x] Each security boundary change can carry focused positive/negative/adversarial tests.
- [x] Built-in invariant families can be implemented after extraction/correlation substrate is canonical.
- [x] Project invariant configuration is sequenced after built-in substrate and its authority contract.
- [x] Final closeout can reuse exact-head CI, independent review, expected-head merge and protected-main governance proof.

## Canonical gates

- [x] Initial R3 planning PR is exact-head qualified, independently review-clean, merged with expected-head protection, and post-merge governance is proven on protected `main`.
- [x] R3-T001 planning-gate closeout is separately exact-head qualified, independently review-clean, expected-head merged, and post-merge governance is proven; the task ledger and roadmap may now mark R3 implementation-ready.

Evidence for the initial planning gate is recorded in `../planning-gate-evidence.md`. Evidence for the separately proven R3-T001 closeout is recorded in `../planning-closeout-evidence.md`.

All planning/readiness evidence that must precede this status transition is complete. The status-canonicalization candidate that marks these records complete must still pass its own exact-head CI, clean independent review, zero unresolved conversations, guarded expected-head merge, post-merge required/Cross-platform CI and live repository-governance proof before R3-T002 begins.
