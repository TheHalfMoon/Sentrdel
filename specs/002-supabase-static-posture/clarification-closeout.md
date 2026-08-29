# Clarification Closeout: Supabase P0 Static/Posture Pack

**Date:** 2026-08-29  
**Status:** CLOSED_FOR_PLANNING

## Frozen decisions

1. **Base mode is offline/static only.** No Supabase project connection, database connection, dashboard/API access, provider credentials, or network requirement.
2. **Repository-derived posture is not live truth.** Every conclusion must expose static provenance and separate LIVE_POSTURE coverage.
3. **No target tooling execution.** Supabase CLI, Postgres, psql, migration runners, package managers, build scripts, Edge Functions, hooks, and repository helpers are not analysis primitives.
4. **R1 contracts remain authoritative.** R2 emits Evidence/Coverage; only the R1 reconciler creates Findings. R2 cannot bypass secret redaction, policy, storage, canonicalization, or benchmark gates.
5. **P0 database checks are bounded.** Initial scope includes RLS state, policies, grants/revokes for API-facing roles, SECURITY DEFINER/search_path posture, and exposed-schema-related repository evidence where statically supportable.
6. **Storage/Auth/Edge Functions are P0 but narrow.** Only repository-visible high-signal policy/configuration checks enter R2. Full hosted configuration and business-logic authorization move to later slices.
7. **Modern and legacy key classes are supported semantically.** Publishable/anon are low-authority classes; secret/service-role are elevated classes. Key plaintext must never persist.
8. **`verify_jwt=false` is a signal, not an automatic vulnerability.** Supported explicit replacement authorization can prevent escalation; otherwise coverage/uncertainty remains visible.
9. **Unsupported syntax is visible.** Dynamic SQL, unsupported DDL/TOML/code patterns, ambiguous migration order, and incomplete history must not silently produce a clean posture.
10. **No new dependency is pre-authorized.** Any parser/dependency addition must follow existing qualification and privileged-dependency policy.
11. **R3 boundary:** cross-layer tenant isolation, route-to-policy business logic, and executable invariants are not R2.
12. **Release quality:** R2 checks must join SentrdelBench incrementally and satisfy active false-positive, authority, deterministic replay, and resource gates before release-gating promotion.

## Resolved ambiguities

### What does “exposed schema” mean offline?

R2 may use repository-visible Supabase configuration and conservative defaults only where the contract explicitly defines them. If the effective hosted Data API schema exposure cannot be proven from repository inputs, the analysis reports uncertainty rather than assuming dashboard state.

### Does missing RLS always mean a finding?

No. A high-confidence RLS finding requires enough repository evidence to establish an API-relevant relation and repository-derived final RLS state within the supported subset. Otherwise emit lower-authority Evidence/coverage.

### Does SECURITY DEFINER always mean a finding?

No. SECURITY DEFINER is privileged posture. Unsafe search_path, exposed callable placement, broad grants, or other supported combinations determine escalation.

### Can R2 read `.env` files?

R2 may identify risky committed secret-file paths and route discovered values through the existing secret producer/redaction boundary, but provider-posture logic must not persist raw values or treat secret contents as configuration authority.

### Can R2 use provider documentation as runtime authority?

No. Upstream documentation informs reviewed rule semantics. The versioned Sentrdel rule/pack contract and repository tests remain canonical runtime behavior.

## Planning gate

No unresolved clarification blocks planning. Product implementation remains blocked until `plan.md`, required contracts/design, implementation-readiness checklist, `tasks.md`, and consistency analysis are complete and canonical.
