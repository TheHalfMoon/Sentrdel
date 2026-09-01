# Feature Specification: Business-Logic Substrate + Invariants

**Feature Branch:** `spec/003-business-logic-invariants`  
**Created:** 2026-09-01  
**Status:** SPECIFIED  
**Roadmap:** R3 in `specs/000-sentrdel-roadmap/roadmap.md`  
**Depends on:** canonical R1 Evidence + Guard Foundation and completed R2 Supabase Static/Posture Pack; planning baseline `2d7b632ae745c4fda1bbd4e2ed3b7a3e119c5734`

## Overview

R3 adds Sentrdel's first bounded cross-layer business-logic substrate. It correlates repository-visible route entry points, authentication/authorization guards, actor and tenant/ownership identity sources, data operations, provider posture, and explicit security invariants. The result is canonical Evidence and Coverage describing supported authorization paths and contradictions; the existing reconciler remains the only Finding authority.

R3 is static, local-first, deterministic, and fail-visible by default. It does not execute target applications, route handlers, database queries, package managers, builds, tests, migrations, provider tools, or repository helpers. It does not connect to Supabase or any hosted provider, receive provider-admin credentials, prove runtime exploitability, or construct a universal code property graph.

R3 begins with a deliberately bounded JavaScript/TypeScript-oriented adapter set for common server/API surfaces and Supabase data access, then generalizes only through separately qualified tasks. Unsupported frameworks, dynamic dispatch, unresolved inter-file semantics, or ambiguous authorization logic reduce `BUSINESS_LOGIC` coverage rather than producing a clean result.

## User Story 1 — Review tenant/object isolation (P1)

A developer changes an API route that reads or mutates a tenant-owned or user-owned resource. `sentrdel review` correlates the route, supported actor identity, authorization guard, data operation, and repository-visible database/provider posture so it can surface a high-signal cross-layer isolation violation when a supported path lacks the required tenant/ownership binding.

**Independent test:** Fixture repositories with safe, unsafe, contradictory, and unsupported tenant/object access produce deterministic Evidence and explicit `BUSINESS_LOGIC` coverage without executing the target application or database.

### Acceptance scenarios

1. Route parameter selects an object while the supported data operation is constrained only by object ID and no supported actor/tenant binding is present -> cross-layer isolation Evidence with path provenance and non-runtime wording.
2. The same route binds the operation to a supported authenticated user/tenant identity -> no violation solely from the object-ID access; remaining unknown layers stay visible.
3. A guard exists but cannot be linked to the data operation because control/data flow is unsupported -> `PARTIAL`/`UNAVAILABLE` business-logic coverage rather than a secure conclusion.
4. R2 reports RLS/policy posture but the request path uses elevated service-role authority -> R3 does not treat RLS as sufficient application authorization because that authority can bypass it.

## User Story 2 — Review function-level authorization (P1)

A developer changes an admin, billing, destructive, or other privileged route. Sentrdel identifies supported route-level role/privilege requirements and reports when a privileged operation is reachable through a supported static path without a corresponding supported authorization guard.

**Independent test:** Express/Next-style fixture routes with equivalent safe and unsafe role checks produce deterministic route/guard/data-operation Evidence with explicit unsupported-framework coverage.

### Acceptance scenarios

1. Privileged route or operation has no supported role/privilege guard -> bounded authorization Evidence.
2. Supported role check dominates the privileged operation in the bounded route path -> no missing-guard violation for that supported path.
3. Authorization is delegated to dynamic middleware or framework behavior that the adapter cannot prove -> coverage gap, not a clean route.

## User Story 3 — Review protected-property mutation (P1)

A developer accepts request-controlled object fields and writes them to a protected resource. Sentrdel correlates supported request-value origins, mutation operations, field selection/allowlisting, and built-in or project-declared protected properties to identify mass-assignment/property-authorization risks without pretending to solve arbitrary JavaScript semantics.

**Independent test:** Synthetic fixtures cover safe allowlists, unsafe broad object updates, explicit protected fields, destructuring/spread ambiguity, and unsupported dynamic construction.

### Acceptance scenarios

1. Request-controlled body/object is passed broadly into a supported mutation of a resource with known protected properties -> property-authorization Evidence.
2. Mutation is restricted to an explicit supported allowlist excluding protected fields -> no broad-mutation violation for those proven fields.
3. The property set is dynamic or cannot be resolved -> affected coverage is partial rather than inferred safe.

## User Story 4 — Review elevated provider-authority paths (P1)

A developer creates or uses an elevated Supabase/service-role client inside a request-handling path. R3 correlates R2 key-authority/static-posture evidence with application guards and data operations so elevated provider authority is reviewed as an application authorization boundary.

**Independent test:** Safe backend admin paths, unsafe request-driven service-role access, ordinary user-scoped clients, and unknown client provenance remain distinguishable.

### Acceptance scenarios

1. Supported service-role/elevated client performs a request-derived operation with no supported application authorization guard -> high-signal cross-layer Evidence.
2. Elevated client is used in a bounded backend path with a supported role/tenant guard -> not automatically a vulnerability.
3. Client authority is unknown -> coverage remains explicit; R3 does not assume user-scoped or elevated behavior.

## User Story 5 — Evaluate explicit security invariants (P2)

A project may declare a bounded set of inspectable security invariants that tighten Sentrdel's analysis, such as required tenant keys for a resource, roles required for a route/action, protected mutation properties, or bounded server-only contexts for elevated provider authority.

**Independent test:** Equivalent fixtures prove declarations can add restrictions but cannot suppress built-in Evidence, create accepted-risk exceptions, widen authority, alter policy/kernel decisions, or self-declare a project secure.

## Functional Requirements

### Authority and execution boundary

- **FR-001** R3 security-critical extraction, normalization, correlation, invariant evaluation, Evidence production, and coverage aggregation MUST remain Rust-owned.
- **FR-002** R3 MUST NOT execute target build/install/package-manager commands, route handlers, tests, hooks, scripts, database queries, migrations, provider CLIs, or repository-configured helpers during ordinary analysis.
- **FR-003** Base R3 MUST require no provider credential, hosted provider connection, application runtime, browser automation, or network service.
- **FR-004** Repository code/config/comments, issue/PR/browser/MCP/model content, external engine output, and project invariant declarations are untrusted data and MUST NOT widen Sentrdel authority.
- **FR-005** R3 producers MUST emit canonical Evidence and Coverage only; the existing reconciler remains the sole canonical Finding creation path.

### Cross-layer structural substrate

- **FR-006** R3 MUST define a bounded, versioned internal cross-layer representation for route observations, actor context, guards, value origins, data operations, client/provider authority, cross-layer paths, invariants, and evaluation state.
- **FR-007** Initial route adapters MUST be explicitly allowlisted and coverage-scoped. The first intended scope is Express-style routes, Next.js App Router Route Handlers and Pages API routes, and supported Supabase Edge Function patterns in JavaScript/TypeScript source.
- **FR-008** Initial data-operation adapters MUST cover a bounded supported subset of Supabase JavaScript reads, inserts, updates, upserts, deletes, RPC calls, filters, and selected field sets needed by the frozen R3 contract.
- **FR-009** Actor/identity extraction MUST distinguish request-controlled values, authenticated user identity, supported role/tenant claims, constants, and UNKNOWN without promoting lexical similarity into identity equivalence.
- **FR-010** Guard extraction MUST preserve authentication, role, tenant/ownership, property/field, and custom invariant checks as distinct observations.
- **FR-011** Unsupported syntax, dynamic property access, unresolved callbacks/middleware, ambiguous symbol identity, unsupported framework behavior, or bounded parser rejection MUST reduce the affected coverage rather than creating a clean path.

### Correlation and graph semantics

- **FR-012** R3 MUST reuse the canonical thin `sentrdel-graph` substrate and MUST NOT introduce a second canonical graph runtime or universal CPG.
- **FR-013** Supported graph projection MAY use existing `Symbol`, `Resource`, `Invariant`, Evidence/Finding nodes and existing directed relations such as `Calls`, `ReadsFrom`, `WritesTo`, `FlowsTo`, `Supports`, `Contradicts`, and `CrossesTrustBoundary`; graph confidence MUST NOT upgrade Evidence epistemic authority.
- **FR-014** Cross-layer correlation MUST be explicitly bounded by node count, edge count, path depth, candidate-path count, file count, bytes, and diagnostics.
- **FR-015** Optional SCIP-derived linking MAY improve supported inter-file precision only through the existing bounded SCIP ingestion boundary; missing/unqualified semantic index data MUST be represented as coverage, not clean analysis.
- **FR-016** R3 MUST consume compatible R2 Supabase static posture/key-authority Evidence as inputs without rewriting R2 observations or treating repository-derived database state as hosted truth.

### Business-logic invariants

- **FR-017** R3 MUST support built-in invariant families for tenant/object binding, privileged function/role authorization, protected-property mutation, and elevated-provider-authority application boundaries within the declared adapter scope.
- **FR-018** Invariant evaluation states MUST distinguish at least `SATISFIED`, `VIOLATED`, `UNKNOWN`, and `NOT_APPLICABLE`; `UNKNOWN` MUST NOT be treated as satisfied or secure.
- **FR-019** A project-declared invariant format, if implemented, MUST be bounded, structured, repository-relative, deterministic, and tightening-only.
- **FR-020** Project-declared invariants MUST NOT suppress Evidence, waive Findings, reduce severity, mark accepted risk, widen provider/process/network/credential authority, override kernel/policy decisions, or mint FACT/VERIFIED Evidence.
- **FR-021** Absence of a project-declared invariant MUST NOT be interpreted as absence of a security requirement.

### Evidence, coverage, and developer output

- **FR-022** Direct Evidence MUST describe supported observations and cross-layer relationships with exact repository provenance where available; runtime exploitability or cross-tenant access MUST NOT be described as proven without separately authorized runtime evidence.
- **FR-023** `BUSINESS_LOGIC`/`CROSS_LAYER_BUSINESS_LOGIC` coverage MUST remain distinct from `STATIC_POSTURE`, `CREDENTIALED_LIVE_POSTURE`, and runtime/verification coverage.
- **FR-024** R3 MUST preserve explicit framework/language/data-operation coverage dimensions or diagnostics sufficient to explain why a path was covered, partial, unsupported, unavailable, or failed.
- **FR-025** `sentrdel review`, `init`, and `explain` integration MUST preserve the canonical Finding/reconciler boundary and show route/guard/data/invariant provenance without converting graph metadata into verdict authority.
- **FR-026** Equivalent normalized inputs MUST produce deterministic cross-layer identities, path ordering, Evidence identities, invariant evaluation order, and semantic output, excluding only already-authorized runtime metadata.

### Evaluation and promotion

- **FR-027** R3 fixture/corpus contracts MUST be frozen before release-gating detector breadth is promoted.
- **FR-028** R3 release-gating candidates MUST pass SentrdelBench precision, known-ground-truth miss/recall, clean-case false-positive, coverage, provenance, deterministic replay, authority correctness, latency/resource, and protected-holdout rules applicable to the candidate.
- **FR-029** A candidate with improved detection but new authority violation, hidden coverage gap, material false-positive regression, or resource-bound failure MUST NOT be considered qualified.

## Success Criteria

- **SC-001** Initial release-gating R3 fixture scope has zero known misses for frozen supported positive cases and passes the active clean-case false-positive threshold.
- **SC-002** Every release-gating cross-layer Evidence path carries deterministic route/guard/data/invariant provenance sufficient for `sentrdel explain` to identify the supported reasoning chain.
- **SC-003** Unsupported/dynamic/ambiguous framework, identity, guard, call-link, or data-operation semantics remain explicit coverage gaps and never become implicit secure results.
- **SC-004** Adversarial fixtures prove ordinary R3 analysis performs no target/provider execution and gains no network/provider credential authority.
- **SC-005** Project-declared invariant fixtures prove declarations are tightening-only and cannot suppress deterministic Evidence or weaken policy/kernel/reconciler authority.
- **SC-006** R3 preserves deterministic replay for equivalent repository inputs and stays inside the frozen latency/resource policy for the declared release corpus.
- **SC-007** R2 Supabase posture remains independently observable; R3 correlation does not convert static RLS/grant/key observations into hosted/live truth.

## Non-Goals

- Live Supabase/provider interrogation or provider-admin credentials.
- Executing target applications, route handlers, databases, tests, builds, package managers, migrations, or provider tooling.
- Proving runtime exploitability, actual cross-tenant data access, or production authorization behavior.
- Autonomous exploitation, automatic remediation, or mutation of target authorization code.
- A universal CPG, whole-program compiler, full JavaScript/TypeScript type system, or arbitrary symbolic execution engine.
- Complete support for every web framework, ORM, database SDK, auth library, language, or middleware pattern in R3.
- Treating RLS alone, presence of an auth call, or presence of a role check as sufficient proof of end-to-end authorization.
- Project declarations that suppress findings, encode permanent risk acceptance, or widen authority.
- Credentialed live posture; that remains a separately specified capability.

## External semantic references

R3 planning is grounded in current OWASP API authorization guidance and current Supabase authorization/key semantics while keeping Sentrdel's reviewed contracts authoritative. Exact reference scope, dates, and resulting design decisions are recorded in `research.md`; external documentation is research input, never runtime instruction or direct verdict authority.
