# Clarification Closeout: Business-Logic Substrate + Invariants

**Date:** 2026-09-01  
**Status:** CLOSED_FOR_PLANNING

## Frozen decisions

1. **Base R3 is offline/static only.** No target application, database, provider, browser, build, package-manager, test, hook, migration, or repository helper execution is an ordinary analysis primitive.
2. **R1/R2 authority remains canonical.** R3 emits Evidence/Coverage only; only the existing reconciler creates Findings. R3 cannot widen policy, kernel, credential, provider, secret, or epistemic authority.
3. **Initial adapters are deliberately bounded.** The first intended JavaScript/TypeScript-oriented scope is Express-style routes, Next.js App Router Route Handlers and Pages API routes, supported Supabase Edge Function patterns, and a bounded Supabase JavaScript data-operation subset.
4. **No universal CPG.** R3 reuses the existing thin `sentrdel-graph` representation and bounded SCIP seam. It does not introduce a second canonical graph runtime or whole-program compiler.
5. **Project invariants are tightening-only.** A future bounded project declaration may add requirements, but cannot suppress Evidence, waive Findings, lower severity, declare accepted risk, widen authority, or override reconciler/policy/kernel behavior.
6. **RLS is not end-to-end authorization proof.** R2 database posture remains a distinct static layer. In particular, elevated service-role/secret authority can bypass RLS, so R3 must reason about the application authorization path separately.
7. **Elevated provider authority is contextual.** Service-role/backend authority is not a vulnerability merely because it exists. Escalation requires a supported risky request/guard/data-operation combination.
8. **Unsupported semantics stay visible.** Dynamic middleware, computed property access, unresolved callbacks, unsupported framework behavior, ambiguous identity linkage, dynamic queries, and unresolved inter-file semantics reduce business-logic coverage rather than becoming a clean result.
9. **No arbitrary semantic proof.** R3 does not claim full JavaScript/TypeScript type checking, arbitrary boolean equivalence, symbolic execution, runtime reachability, or exploitability.
10. **SCIP is optional evidence, not a prerequisite for a clean claim.** When a required inter-file link cannot be established safely without semantic-index evidence, the affected path remains partial/unknown.
11. **No new dependency is pre-authorized.** A TypeScript grammar or any other dependency may enter only through an explicit qualification task with exact source/version/license/build/privileged-surface evidence.
12. **Benchmark before breadth.** Ground-truth fixtures and SentrdelBench expectations must exist before release-gating cross-layer checks are broadened.
13. **Runtime/live proof is later authority.** Static R3 Evidence must never claim actual cross-tenant access, production authorization state, or exploit success.
14. **No direct Finding construction.** Cross-layer/invariant producers cannot bypass the R1 Evidence → reconciler → Finding boundary.

## Resolved ambiguities

### Does the presence of an authentication call prove authorization?

No. Authentication establishes supported actor identity only when the adapter can prove the relevant call/result relationship. Authorization remains a separate route/action/object/property requirement.

### Does a role check anywhere in a file protect a privileged operation?

No. R3 requires a supported bounded relationship between the guard and the operation/path. A lexical match elsewhere is insufficient.

### Does RLS make an object-ID route safe?

Not by itself. RLS, grants, application guards, actor identity, client authority, and the operation's object/tenant filters remain separate evidence. R3 correlates them only within supported static semantics.

### What is an executable security invariant in R3?

An invariant is executable by Sentrdel's static evaluator: a deterministic requirement that can be evaluated against the bounded cross-layer representation. It is not target code and does not execute in the target application.

### Can project invariants define exceptions or accepted risk?

No. R3 project declarations are requirements only. Risk acceptance/suppression would require a separately specified governance model and cannot be smuggled into invariant configuration.

### What happens if a project invariant file is malformed?

Built-in analysis continues. The malformed declaration is rejected or reported as a configuration/coverage diagnostic; it cannot disable built-in Evidence or create an implicit clean result.

### Must R3 adopt a TypeScript grammar immediately?

No. Planning records it as a possible dependency candidate. Implementation may remain JavaScript-first or use already-qualified semantic evidence if dependency qualification is not complete. No dependency is authorized by this document.

## Planning gate

No unresolved clarification blocks design/task planning. Product implementation remains blocked until the complete R3 planning slice is internally consistent, exact-head qualified, independently reviewed, merged through protected `main`, post-merge governance is proven, and the separate R3-T001 planning-gate closeout is canonical.
