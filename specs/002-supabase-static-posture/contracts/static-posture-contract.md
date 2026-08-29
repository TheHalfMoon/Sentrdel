# Contract: Supabase Static Posture R2

**Version:** 1  
**Authority:** R2 provider contract under the Sentrdel Constitution and R1 canonical Evidence/Coverage contracts.

## Purpose

This contract defines what the Supabase R2 provider may observe, reduce, emit, and claim. It does not grant live Supabase access, SQL execution, Finding authority, policy authority, or secret authority.

## Provider identity

The R2 static provider MUST use a runtime-owned `EvidenceAuthority` with `ProducerKind::NativeRule` or another already-authorized deterministic R1 producer kind. Repository bytes cannot choose or override producer identity/kind.

## Input contract

Allowed base inputs:

- canonical repository-relative Supabase migration files;
- canonical repository-relative `supabase/config.toml`;
- canonical repository-relative Edge Function/source files;
- bounded application source/config needed to establish a supported client/server authority context;
- R1 ProjectProfile/Supabase detection results;
- R1 diff/view metadata.

Forbidden base inputs/actions:

- provider credentials;
- hosted Supabase APIs;
- direct database connections;
- Supabase CLI execution;
- psql/Postgres execution;
- migration execution;
- Edge Function execution;
- target package/build/install commands;
- repository-controlled executable helpers.

## Resource bounds

Every reader/parser MUST have explicit non-zero caps for:

- number of files;
- file bytes;
- total bytes per analysis;
- SQL statements per file/analysis;
- tokens/nesting depth where applicable;
- TOML depth/collection sizes;
- source matches per file/analysis;
- diagnostic count.

Cap exhaustion MUST result in explicit failed/partial coverage and MUST NOT be interpreted as clean posture.

## Migration ordering contract

- Only canonical migration paths in the supported Supabase migration layout enter state reduction.
- Ordering MUST be deterministic from canonical repository inputs.
- Duplicate/ambiguous supported order keys MUST fail closed for stateful posture affected by the ambiguity.
- R2 MUST NOT infer that repository migration order proves the hosted database applied the same history.

## Supported SQL contract

Every security-relevant statement encountered is classified as one of:

- `SUPPORTED`
- `IGNORED_SAFE_SCOPE`
- `UNSUPPORTED_SECURITY_RELEVANT`
- `MALFORMED_OR_BOUNDED_REJECTION`

The initial supported security semantics are limited to:

- schema/object identities needed for provider posture;
- relation creation/existence within supported history;
- RLS enable/disable;
- CREATE/ALTER/DROP POLICY attributes required by R2;
- GRANT/REVOKE for supported privileges/roles;
- CREATE/ALTER/DROP FUNCTION properties required for SECURITY DEFINER/search_path posture;
- CREATE VIEW attributes only where required for API exposure posture;
- Storage policy SQL where it maps onto the same supported Postgres constructs.

Dynamic SQL, procedural execution semantics, arbitrary expression proving, extension behavior, trigger execution, and full PostgreSQL semantics are outside the supported subset unless later tasks explicitly extend this contract.

## Static-vs-live truth contract

R2 MUST label repository-derived posture as static. It MUST NOT emit observations claiming that production/hosted Supabase currently has a property unless a later separately authorized LIVE_POSTURE producer supplies that evidence.

`LIVE_POSTURE`, `BUSINESS_LOGIC`, and `RUNTIME` coverage remain not executed/not implemented in R2.

## RLS and grants contract

R2 treats these as independent supported properties:

- API exposure evidence;
- relation RLS state;
- policy presence/shape;
- role privileges/grants.

No one property proves the others secure. Unsupported/unknown state in a security-relevant layer degrades coverage.

## SECURITY DEFINER contract

Allowed direct observations include:

- a function is declared SECURITY DEFINER;
- its repository-supported search_path posture;
- its supported schema placement;
- supported execute grants.

`SECURITY DEFINER` alone MUST NOT be described as exploitable. High-signal interpretation requires a supported unsafe combination such as unpinned/mutable search_path or dangerous exposure/grants.

## API key authority contract

Supported semantic authority classes:

- `PUBLISHABLE`
- `LEGACY_ANON`
- `SECRET`
- `LEGACY_SERVICE_ROLE`
- `UNKNOWN_SUPABASE_KEY`

Elevated classes (`SECRET`, `LEGACY_SERVICE_ROLE`) may support a finding when statically placed in a supported browser/client-facing context.

Raw discovered secret material MUST be registered with the R1 redaction boundary before any persistence. Persistent output may contain only rule/type, location, redacted display, and sanitized non-secret fingerprint/context.

## Edge Function authorization contract

Platform JWT/auth verification disabled is a direct configuration observation when supported. It becomes a higher-confidence security interpretation only if R2 cannot prove a supported explicit replacement authorization boundary from the analyzed static inputs.

If replacement auth is dynamic/unsupported/ambiguous, R2 MUST expose uncertainty/partial coverage rather than assert there is no authorization.

## Evidence contract

Every R2 Evidence claim MUST:

- use the canonical R1 schema version;
- contain a bounded direct observation;
- keep security interpretation separate;
- use stable normalized subjects/locations where applicable;
- identify static repository input digests/provenance;
- contain no secret plaintext or secret-value-only stable digest;
- remain within the producer's R1 epistemic authority.

R2 provider code MUST NOT construct canonical Findings directly.

## Coverage contract

At least these dimensions are reported independently:

- `DETECTION`
- `STATIC_POSTURE_DATABASE`
- `STATIC_POSTURE_STORAGE`
- `STATIC_POSTURE_AUTH_CONFIG`
- `STATIC_POSTURE_EDGE_FUNCTIONS`
- `STATIC_POSTURE_KEY_BOUNDARY`
- `LIVE_POSTURE`
- `BUSINESS_LOGIC`
- `RUNTIME`

A provider-level “PASS” MUST NOT erase partial/unsupported dimensions.

## Determinism contract

Equivalent normalized repository inputs MUST produce deterministic:

- migration order;
- supported posture state;
- observation ordering;
- non-secret correlation fingerprints;
- Evidence identities, except existing canonical timestamp rules where timestamps are deliberately excluded or fixed by the orchestration contract.

## Benchmark/promotion contract

A candidate R2 rule becomes release-gating only after:

1. positive and negative fixtures exist;
2. adversarial/bounded parser fixtures pass;
3. deterministic replay passes;
4. known-ground-truth fixture misses are zero for its declared supported scope;
5. active clean-PR FP threshold passes;
6. secret and no-execution/no-network authority canaries pass;
7. exact-head repository CI passes.

Rule count alone is not a promotion criterion.
