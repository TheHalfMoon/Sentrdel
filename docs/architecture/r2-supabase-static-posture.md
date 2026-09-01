# R2 Supabase Static Posture Architecture and Coverage

**Scope:** Spec 002 / R2 Supabase P0 Static/Posture Pack  
**Authority:** descriptive documentation subordinate to the Constitution and active Spec 002 contracts

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

R2 keeps provider coverage dimensions distinct:

| Dimension | R2 status | Meaning |
| --- | --- | --- |
| `DETECTION` | Implemented | Repository-visible Supabase presence/signals can be detected through the existing provider profile/pack path. |
| `STATIC_POSTURE` | Implemented for the declared bounded Spec 002 subset | Repository-owned migrations/config/source signals are analyzed offline and deterministically with explicit gaps. |
| `LIVE_POSTURE` | Not implemented / not executed | R2 does not connect to Supabase or inspect hosted dashboard/database state. |
| `BUSINESS_LOGIC` | Not implemented | Cross-layer tenant/business-logic invariants are deferred to R3. |
| `RUNTIME` | Not implemented / not executed | R2 makes no claim about production/runtime behavior or data visibility. |

A completed static check does not imply the corresponding hosted or runtime control is secure. Static repository evidence and live provider posture remain separate claims.

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

## Qualification

The release-hardening path includes deterministic fixture/E2E evaluation, R2 SentrdelBench quality and latency/resource gates, dependency/source governance, and Linux/macOS/Windows execution of the bounded R2 adversarial authority canaries. These canaries prove the declared static Rust paths preserve secret-persistence, no-provider-network, no-target-execution, malformed-input, and instruction-authority boundaries on the supported CI platforms.

Cross-platform qualification does not claim identical operating-system interception semantics, general process sandboxing, or external-engine containment. Those remain independently scoped seams.

## Relationship to R1 and R3

R1 remains the canonical evidence, coverage, reconciliation, policy, persistence, guard, explanation, and developer-output substrate. R2 adds Supabase-specific static posture producers without creating a second judgment plane.

R3 is the planned business-logic layer. Nothing in R2 should be read as implementation of tenant isolation invariants, end-to-end authorization/business-flow reasoning, credentialed live posture, or runtime verification.
