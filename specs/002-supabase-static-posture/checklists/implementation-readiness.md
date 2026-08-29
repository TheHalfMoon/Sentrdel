# Implementation Readiness Checklist — R2 Supabase Static Posture

**Date:** 2026-08-29  
**Gate:** Product implementation MUST NOT start until every blocking item is checked and the planning slice is canonical on protected `main`.

## Scope and authority

- [x] R2 has a bounded provider-specific goal distinct from R3 business logic and later live posture.
- [x] Offline/static base mode is explicit.
- [x] Provider credentials and network access are excluded from base R2.
- [x] Target SQL/provider/package/build execution is forbidden.
- [x] R1 Evidence/Coverage/reconciler/redaction contracts remain authoritative.
- [x] STATIC_POSTURE and LIVE_POSTURE are explicitly separated.
- [x] Secret plaintext and value-only stable secret hashes remain forbidden in persistence.

## Specification quality

- [x] User stories have independent tests.
- [x] RLS/grant/policy/SECURITY DEFINER/key/Storage/Auth/Edge Function scope is defined.
- [x] Ambiguous/unsupported syntax semantics are fail-visible rather than clean-by-default.
- [x] Success criteria include precision, misses, authority, determinism, and secret/no-execution canaries.
- [x] Non-goals prevent live-provider and business-logic scope creep.

## Design quality

- [x] Constitution Check is PASS with no exception.
- [x] Migration ordering and repository-derived-state limitations are explicit.
- [x] Narrow SQL supported-subset strategy is defined.
- [x] Data model preserves UNKNOWN and statement provenance.
- [x] RLS, grants, policies, function authority, and exposure remain separate properties.
- [x] Edge Function disabled-JWT configuration is contextual rather than an unconditional vulnerability.
- [x] Modern publishable/secret and legacy anon/service-role authority classes are represented.
- [x] Coverage dimensions are defined.
- [x] No new dependency is pre-authorized.

## Contract quality

- [x] Allowed and forbidden inputs/actions are explicit.
- [x] Parser/resource caps are mandatory.
- [x] Unsupported security-relevant syntax degrades coverage.
- [x] Provider cannot construct canonical Findings.
- [x] Evidence secret/redaction rules are explicit.
- [x] Determinism and benchmark promotion rules are explicit.

## Taskability

- [x] Work can be decomposed into contracts/fixtures, parser/state, database posture, key/config/Edge posture, integration, benchmark, and closeout phases.
- [x] Each security boundary change can receive targeted tests before integration.
- [x] Implementation ordering can avoid detector breadth before parser/coverage correctness.
- [x] Final closeout can reuse protected-main exact-head CI and governance evidence discipline established in R1.

## Remaining gate

- [x] Planning PR is exact-head qualified, review-clean, merged with expected-head protection, and proven canonical on protected `main`.

Until the remaining gate is satisfied, no R2 product implementation is authorized.
