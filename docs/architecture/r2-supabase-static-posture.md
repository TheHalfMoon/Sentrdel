# R2 Supabase Static Posture Architecture and Coverage

**Scope:** Spec 002 / R2 Supabase P0 Static/Posture Pack  
**Authority:** descriptive documentation subordinate to the Constitution and canonical R2/R3 contracts

## Implemented architecture

R2 extends the R1 evidence/control plane with a Rust-owned, offline, deterministic Supabase Security Pack. Repository-owned Supabase migrations, supported SQL/configuration, Edge Function authorization settings, and relevant application key/context signals are treated as bounded untrusted data. The pack emits canonical Evidence and Coverage through the R1 contracts; only the existing reconciler can create canonical Findings.

The implemented static posture path covers the declared bounded subset for:

- Supabase migration discovery/order and repository-derived posture reduction;
- supported schemas, relations, RLS enable/disable, policies, grants/revokes, and SECURITY DEFINER/search-path posture;
- supported Storage authorization policy SQL;
- bounded allowlisted `supabase/config.toml` Auth/API/Edge Function settings;
- modern publishable/secret and legacy anon/service-role key authority classes without persisting secret plaintext;
- conservative browser/client, server, Edge Function, test/fixture, and unknown source contexts;
- elevated secret/service-role authority placed in supported browser/client contexts;
- supported Edge Function JWT/auth configuration and bounded explicit replacement-authorization patterns;
- deterministic `review`, `init`, and `explain` integration with explicit provider provenance and coverage.

Unsupported, malformed, ambiguous, dynamic, oversized, missing, or hosted-only state remains explicit partial/unavailable/not-implemented coverage. It is never converted into a clean posture result merely because static analysis could not prove it.

## Coverage dimensions

Provider posture and business-logic coverage remain distinct even after R3:

| Dimension | Current status | Meaning |
| --- | --- | --- |
| `DETECTION` | Implemented | Repository-visible Supabase presence/signals can be detected through the existing provider profile/pack path. |
| `STATIC_POSTURE` | Implemented for the declared bounded Spec 002 subset | Repository-owned migrations/config/source signals are analyzed offline and deterministically with explicit gaps. |
| `LIVE_POSTURE` | Not implemented / not executed | R1-R3 do not connect to Supabase or inspect hosted dashboard/database state. |
| `BUSINESS_LOGIC` / `CROSS_LAYER_BUSINESS_LOGIC` | Implemented separately by R3 for the bounded Spec 003 adapter/invariant scope | R3 correlates supported application paths and may consume compatible R2 static Evidence as supporting input; this does not change R2 static Evidence into hosted truth. |
| `RUNTIME` | Not implemented / not executed | R1-R3 make no claim about production/runtime behavior, actual exploitability, or data visibility. |

A completed static check does not imply the corresponding hosted, business-logic, or runtime control is secure. Each coverage dimension carries its own provenance and limitations.

## Authority and execution boundaries

R2 does not authorize or perform:

- provider-admin credential access;
- Supabase API/dashboard interrogation;
- Supabase CLI, `psql`, or database connections;
- migration, SQL, Edge Function, package-manager, build/install, hook, or target-helper execution;
- autonomous exploitation or production probing;
- provider-specific Finding creation that bypasses the R1 reconciler;
- repository/model/comment text widening network, process, policy, or epistemic authority.

Secret plaintext and stable unkeyed secret-value-only hashes remain prohibited from persistent Evidence, logs, snapshots, and exports.

R3 consumption of R2 Evidence does not widen these authorities. Service-role/elevated-client observations remain contextual static evidence; R3 may reason about a supported application boundary but cannot infer hosted configuration or runtime access from repository state alone.

## Qualification

The release-hardening path includes deterministic fixture/E2E evaluation, R2 SentrdelBench quality and latency/resource gates, dependency/source governance, and Linux/macOS/Windows execution of the bounded R2 adversarial authority canaries. These canaries prove the declared static Rust paths preserve secret-persistence, no-provider-network, no-target-execution, malformed-input, and instruction-authority boundaries on the supported CI platforms.

R3 adds its own cross-platform supported-path and adversarial qualification. Cross-platform qualification does not claim identical operating-system interception semantics, general process sandboxing, external-engine containment, hosted-provider behavior, or runtime authorization equivalence.

## Relationship to R1 and R3

R1 remains the canonical evidence, coverage, reconciliation, policy, persistence, guard, explanation, and developer-output substrate. R2 adds Supabase-specific static posture producers without creating a second judgment plane.

R3 is now the implemented bounded business-logic layer for Spec 003. It correlates supported route, actor/auth, guard, value/data-operation, provider-client, semantic-link, and invariant observations through the existing bounded SSG/graph substrate. Compatible R2 RLS/policy/grant/key/static-context Evidence can support R3 correlation while retaining its R2 identity, provenance, and static authority ceiling.

Nothing in R2 or R3 should be read as credentialed live posture, target execution, runtime exploitability proof, actual cross-tenant access, production authorization verification, universal CPG semantics, or complete framework/language coverage.

See `docs/architecture/r3-business-logic-invariants.md` for the R3-specific architecture and coverage boundary.
