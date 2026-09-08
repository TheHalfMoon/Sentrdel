# R3 Business-Logic Substrate and Invariants

**Scope:** Spec 003 / R3 Business-Logic Substrate + Invariants  
**Authority:** descriptive documentation subordinate to the Constitution and canonical Spec 003 contracts

## Purpose

R3 implements Sentrdel's first bounded cross-layer application-security substrate. It correlates repository-visible application semantics across supported route entry points, actor/auth context, authorization guards, value origins, data operations, provider-client authority, semantic links, and explicit security invariants.

R3 remains static, local-first, deterministic, and fail-visible. It adds business-logic Evidence and Coverage to the existing Sentrdel judgment plane; it does not create a second verdict engine.

## Architecture

```text
bounded repository source/config
          |
          +--> route adapters --------+
          +--> actor/auth adapters ----+
          +--> guard adapters ---------+
          +--> value-origin adapters --+
          +--> data-operation adapters +----> bounded cross-layer IR
          |                            |               |
R2 Evidence/Coverage -----------------+               +--> existing Sentrdel Semantic Security Graph
optional qualified semantic links --------------------+               |
project invariants (tightening-only) -------------------------------+
                                                                       v
                                                             invariant/path evaluator
                                                                       |
                                                              Evidence + Coverage
                                                                       |
                                                               existing reconciler
                                                                       |
                                                                    Finding
```

The trusted implementation remains Rust-owned. Graph projection is limited to already-valid Sentrdel graph/SSG vocabulary and bounded path queries. Graph metadata provides context and provenance; graph confidence cannot upgrade Evidence epistemic authority.

## Implemented adapter scope

The initial R3 release scope is intentionally bounded to supported JavaScript/TypeScript patterns for:

- Express-style method/path route registration and bounded callback/middleware chains;
- Next.js App Router Route Handlers;
- Next.js Pages API route handlers;
- supported Supabase Edge Function handler patterns;
- supported authenticated actor/user/tenant/role observations;
- supported authentication, role, tenant/ownership, property/field, and elevated-client guard observations;
- bounded request/value-origin derivation;
- supported Supabase JavaScript `select`, `insert`, `update`, `upsert`, `delete`, RPC, filter, selected-field, and mutation-field observations needed by the frozen Spec 003 contract;
- bounded local and already-qualified semantic linking;
- compatible R2 Supabase static-posture/key-authority Evidence as supporting input.

Dynamic route generation, unsupported middleware composition, unresolved callbacks or symbols, arbitrary metaprogramming, unsupported framework/ORM/auth patterns, ambiguous identity equivalence, unsupported data-operation syntax, and exhausted analysis caps reduce coverage. They never become a clean result merely because R3 cannot prove the path.

## Built-in invariant families

R3 implements the initial invariant families frozen by Spec 003:

1. **Tenant/object binding** — supported user/tenant-owned data paths require a supported authenticated actor/tenant relationship where the invariant applies.
2. **Privileged function/role authorization** — supported privileged routes/actions require a supported dominating/linkable role or privilege guard.
3. **Protected-property mutation** — supported broad request-controlled mutations remain distinguishable from explicit allowlisted field writes and protected-property requirements.
4. **Elevated provider authority** — supported service-role/secret/elevated client use is treated as an application authorization boundary when correlated with a request-driven path.

Invariant evaluation preserves states such as satisfied, violated, unknown, and not-applicable. UNKNOWN does not mean secure.

## Project invariant authority

Project-declared invariants are bounded structured data. They may tighten Sentrdel analysis but cannot:

- suppress Evidence or waive Findings;
- reduce severity or declare accepted risk;
- impersonate built-in/kernel invariant identities;
- widen filesystem, process, network, provider, or credential authority;
- execute repository content, scripts, templates, or plugins;
- create canonical Findings directly;
- mint FACT/VERIFIED Evidence authority;
- disable built-in analysis when project configuration is malformed.

The repository remains untrusted data even when an invariant declaration is syntactically valid.

## Evidence and Finding authority

R3 producers emit canonical Evidence and Coverage through runtime-owned producer authority. They do not create canonical Findings.

The existing reconciler remains the sole Finding creation path. R3 interpretations preserve the distinction between direct repository observations and security interpretations. Static analysis does not by itself prove runtime exploitability, actual cross-tenant access, or hosted-provider truth.

## Coverage model

R3 keeps business-logic coverage separate from provider and runtime claims.

| Dimension | R3 meaning |
| --- | --- |
| Route/framework extraction | Whether the route/handler form is in the frozen supported adapter subset. |
| Actor/auth identity | Whether supported authenticated/request-controlled identity observations can be established. |
| Guard extraction | Whether supported authorization/tenant/property/elevated-boundary guards are observed and linkable. |
| Value origin | Whether relevant request/auth/data values can be derived within bounded depth/fan-in. |
| Data operation | Whether the supported Supabase operation/resource/filter/field subset is represented. |
| Local/semantic linking | Whether supported inter-observation/inter-file relationships can be established without guessing. |
| R2 provider correlation | Whether compatible static Supabase Evidence is available and usable as static supporting context. |
| Invariant evaluation | Whether the applicable invariant can be evaluated with sufficient supported evidence. |
| Aggregate business logic | Monotonic aggregate state; a clean Finding set cannot erase partial/failed/unsupported dimensions. |

`BUSINESS_LOGIC` / `CROSS_LAYER_BUSINESS_LOGIC` does not imply `STATIC_POSTURE`, `CREDENTIALED_LIVE_POSTURE`, `RUNTIME`, or verification coverage. Conversely, R2 static posture does not prove R3 application authorization.

## Execution and network boundary

Ordinary R3 analysis does not execute:

- target applications or route handlers;
- package managers, builds, tests, hooks, or repository helpers;
- SQL, migrations, database queries, or provider CLIs;
- arbitrary project invariant content.

Base R3 requires no hosted provider connection or provider-admin credential and performs no provider-network interrogation. Repository text cannot grant those capabilities.

## Cross-platform qualification

The canonical Linux/macOS/Windows matrix explicitly exercises the existing R3 supported-path/authority E2E canaries and adversarial extraction suite on each supported runner.

Those tests cover, among other bounded claims:

- safe, vulnerable, contradictory/unknown, unsupported-semantic-link, unsupported-framework, and hostile-repository fixture behavior;
- deterministic review/init/explain replay for the supported fixtures;
- no target-build or ordinary R3 target-execution authority;
- no R3 provider-network or provider-credential authority;
- no direct Finding authority from the R3 producer;
- project invariants cannot weaken built-ins or grant execution/network/credential/Finding authority;
- malformed, oversized, dynamic, generated/unsupported, and instruction-shaped inputs remain bounded and fail-visible.

Running the same bounded static tests on Linux, macOS, and Windows does not prove identical operating-system interception semantics, hostile-code sandboxing, network isolation, runtime behavior, or provider behavior across those operating systems.

## R2 relationship

R2 Supabase Evidence remains independently observable repository-derived static posture. R3 may consume compatible RLS/policy/grant/key/client/static-context Evidence as supporting inputs while retaining R2 identity, provenance, and authority limits.

R3 never upgrades R2 repository-derived posture into hosted truth. In particular, RLS presence is not treated as sufficient application authorization for a supported path using elevated service-role authority.

## Explicit non-claims

R3 does not claim:

- credentialed/live Supabase or other provider posture;
- target execution or automatic verification;
- runtime exploitability or actual cross-tenant data access;
- production authorization equivalence;
- autonomous exploitation or automatic remediation;
- a universal CPG, whole-program compiler, full JavaScript/TypeScript type system, or arbitrary symbolic execution engine;
- complete support for every framework, ORM, database SDK, auth library, language, middleware, or dynamic semantic;
- identical operating-system interception or sandbox semantics from cross-platform static qualification;
- that an empty Finding set means the repository or an unsupported path is secure.

## Dependency boundary

R3 admitted `tree-sitter-typescript = 0.23.2` only through the separately qualified R3-T007 / TSQ-001 dependency/source-governance path. Final R3 dependency/source governance revalidated continuity of that admission rather than silently adding or upgrading parser/build authority.

Any future adapter or dependency expansion requires its own canonical specification/dependency qualification and cannot be inferred from R3's current support.
