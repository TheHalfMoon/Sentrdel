# Implementation Plan: Supabase P0 Static/Posture Pack

**Branch:** `spec/002-supabase-static-posture`  
**Date:** 2026-08-29  
**Spec:** `specs/002-supabase-static-posture/spec.md`  
**Depends on:** R1 canonical main `22e953aad1089b91c7b654addfa4086359353232`

## Summary

Build R2 as the first provider-specific Security Pack on top of the completed R1 Evidence + Guard Foundation. R2 performs bounded, deterministic, offline analysis of repository-owned Supabase migrations, configuration, Edge Functions, and application authority boundaries. It extends the existing `sentrdel-review` provider-pack substrate, emits R1 Evidence/Coverage, uses the existing reconciler for Findings, and joins SentrdelBench before release-gating check breadth grows.

No base R2 path connects to Supabase, executes SQL or provider tooling, runs target build/package code, or receives provider-admin credentials.

## Technical Context

**Language/Version:** Rust 1.98.0 exact R1/R2 trusted-core pin unless separately amended.  
**Existing substrate:** `sentrdel-schema`, `sentrdel-review`, `sentrdel-store`, `sentrdel-graph`, `sentrdel-cli`, SentrdelBench, R1 secret redaction.  
**Primary inputs:** repository-relative `supabase/migrations/*.sql`, `supabase/config.toml`, `supabase/functions/**`, relevant bounded application source/config.  
**Network:** none in base R2.  
**Target execution:** none.  
**Persistence:** canonical Evidence/Coverage through existing R1 stores; secret material removed before persistence.  
**Quality:** exact-head workspace CI, cross-platform qualification where applicable, deterministic fixture replay, SentrdelBench precision/miss/coverage/latency/authority gates.

## Constitution Check

| Principle | R2 gate | Result |
|---|---|---|
| Rust Trusted Core | Parsing/state reduction/Evidence orchestration remain Rust-owned | PASS |
| Evidence Before Verdict | Pack emits Evidence/Coverage; existing reconciler alone creates Findings | PASS |
| Vendor-Neutral, Local-First | Offline repository analysis; no required Supabase account/cloud | PASS |
| Honest/Monotonic Guardrails | STATIC_POSTURE is distinct from LIVE_POSTURE; ambiguity stays visible | PASS |
| Safe Verification | No execution verification or live probing in R2 | PASS |
| Full-Stack Through Packs | R2 is the first bounded provider posture pack | PASS |
| Reuse Mature Infrastructure | Reuse R1 contracts/parsers; no provider runtime SDK by default | PASS |
| FP/Latency Quality | R2 fixtures join SentrdelBench before release-gating promotion | PASS |
| Sentrdel Secures Itself | Inputs bounded; no target execution; secrets redacted; dependencies qualified | PASS |
| Spec Kit Governance | Dedicated bounded R2 slice with spec/design/contracts/checklist/tasks | PASS |

**Gate result:** PASS. No constitutional exception is required.

## Architecture

```text
repository files
  |
  +--> existing Supabase detector
  |
  +--> bounded migration reader --> SQL posture parser --> migration state reducer
  |                                                    |
  |                                                    +--> RLS/policy/grant/function facts
  |
  +--> bounded config reader ----> allowlisted TOML posture parser
  |
  +--> bounded function/source --> authority/context analyzers
  |                                                    |
  +----------------------------------------------------+
                                                       v
                                                Evidence + Coverage
                                                       |
                                               existing reconciler
                                                       |
                                                    Finding
                                                       |
                                             review/init/explain output
                                                       |
                                                SentrdelBench R2
```

## Trust Boundaries

1. **SQL boundary:** SQL is untrusted text. Parse only supported bounded syntax; never execute it.
2. **Migration-history boundary:** ordered files are repository evidence, not proof of hosted database state.
3. **Config boundary:** only allowlisted Supabase TOML keys are interpreted; unknown/deep/oversized values remain data/coverage.
4. **Source boundary:** JavaScript/TypeScript/source text cannot grant instruction authority or secret access.
5. **Secret boundary:** key-shaped values register with the existing redaction system before persistence.
6. **Provider boundary:** no remote Supabase API/database interaction in base R2.
7. **Finding boundary:** provider producers cannot create canonical Findings directly.
8. **Benchmark boundary:** rule promotion cannot alter evaluator expectations used to qualify that same candidate.

## Planned Components

### `crates/sentrdel-review/src/supabase/`

R2 SHOULD consolidate new provider behavior under a provider namespace while preserving compatible R1 detection exports as needed.

Proposed modules:

- `mod.rs` — provider orchestration and public bounded contract.
- `migration.rs` — deterministic migration discovery/order and state reduction.
- `sql.rs` — narrow SQL lexer/parser/statement model.
- `posture.rs` — RLS, policy, grant, exposed-schema, function posture producers.
- `config.rs` — bounded allowlisted `supabase/config.toml` parsing.
- `authority.rs` — publishable/anon vs secret/service-role source-context analysis.
- `edge.rs` — Edge Function auth configuration/source checks.
- `coverage.rs` — provider-specific coverage aggregation mapped to R1 CoverageRecord.

Module names are planning targets, not an authorization to break existing public APIs without migration tests.

### R1 contracts reused unchanged where possible

- `EvidenceAuthority` / canonical Evidence validation.
- `CoverageRecord` and provider coverage dimensions.
- `SecurityPackManifest`.
- repository view/path bounds.
- secret detection/redaction/persistence boundaries.
- Finding reconciler and explanation/output layers.

If R2 reveals a schema contract gap, the change must be minimal, version-compatible where possible, separately tested, and never grant provider code Finding/policy authority.

## SQL Posture Strategy

R2 will not build a full PostgreSQL parser. It will implement a bounded statement tokenizer/parser covering only the security-relevant forms frozen by the contract. Parsing results are one of:

- `SUPPORTED` — statement reduced into deterministic posture state;
- `IGNORED_SAFE_SCOPE` — recognized as outside R2 semantics without affecting security state;
- `UNSUPPORTED_SECURITY_RELEVANT` — cannot safely reduce; produces coverage uncertainty;
- `MALFORMED_OR_BOUNDED_REJECTION` — bounded failure with explicit coverage.

The reducer maintains repository-derived state keyed by normalized schema/object identity. It records provenance for the statement that most recently changed each supported security property.

## Static Posture Rules — Initial Release-Gating Candidates

Candidate families, promoted only after benchmark qualification:

1. API-relevant relation with supported final state `RLS_DISABLED` or no supported RLS enablement where exposure is established.
2. Broad grants to `anon`/`authenticated` inconsistent with supported restrictive posture.
3. Policy widening/removal/change detectable from migration delta.
4. `SECURITY DEFINER` function with absent/unsafe mutable `search_path`.
5. Privileged function exposed/callable in a supported API-facing schema with dangerous grants.
6. Elevated `sb_secret_*` / legacy service-role authority statically placed in supported browser/client context.
7. Storage authorization policy weaknesses expressible by the supported SQL model.
8. Edge Function auth verification disabled without a supported explicit replacement authorization boundary.

Non-release-gating observations may exist but must be clearly distinguished from qualified high-signal checks.

## Coverage Model

At minimum, R2 reports separately:

- `DETECTION`
- `STATIC_POSTURE_DATABASE`
- `STATIC_POSTURE_STORAGE`
- `STATIC_POSTURE_AUTH_CONFIG`
- `STATIC_POSTURE_EDGE_FUNCTIONS`
- `STATIC_POSTURE_KEY_BOUNDARY`
- `LIVE_POSTURE` = NOT_EXECUTED/NOT_IMPLEMENTED in R2
- `BUSINESS_LOGIC` = NOT_IMPLEMENTED in R2
- `RUNTIME` = NOT_IMPLEMENTED in R2

Unsupported security-relevant syntax reduces the appropriate static dimension to PARTIAL rather than allowing a clean aggregate.

## Data Flow — Migration State

```text
bounded migration paths
       |
canonical deterministic ordering
       |
bounded bytes + digest
       |
SQL statement parser
       |
statement provenance
       |
repository-derived posture state
       |
rule evaluation
       |
Evidence + Coverage
```

No step materializes a target database.

## Data Flow — Key Boundary

```text
bounded source/config bytes
       |
secret/key class recognizer
       +--> redaction registration for secret material
       |
conservative execution-context classifier
       |
Evidence: key authority class + repository context
       |
interpretation only when supported context proves risky placement
```

## Implementation Phases

### Phase A — Contracts and fixtures

Freeze provider pack manifest, SQL supported subset, migration ordering, state/provenance model, coverage dimensions, and synthetic fixture corpus.

### Phase B — Bounded SQL/migration substrate

Implement deterministic migration discovery/order, bounded tokenizer/parser, supported statement model, and state reducer. Add malformed/oversized/dynamic SQL adversarial tests before posture rules.

### Phase C — Database posture producers

Add RLS, policies, grants/revokes, SECURITY DEFINER/search_path, and conservative schema-exposure Evidence.

### Phase D — Keys, Storage, Auth, Edge Functions

Add elevated-key context checks, Storage policy mapping, bounded config parser, and Edge Function authorization posture.

### Phase E — Integration

Register the R2 Security Pack, replace R1 `NOT_IMPLEMENTED` static posture with honest R2 coverage, integrate review/init/explain output without changing reconciler authority.

### Phase F — Evaluation and closeout

Run R2 SentrdelBench corpus, clean-PR FP gate, known-ground-truth miss gate, deterministic replay, resource/latency, secret canaries, no-network/no-execution canaries, cross-platform CI, dependency/source governance, and protected-main closeout evidence.

## Dependency Policy

No new third-party crate is authorized by this plan. If implementation cannot safely meet the contract using current dependencies and Sentrdel-owned code, a dependency candidate must first receive:

- exact crate/version/source/license;
- capability justification;
- build.rs/proc-macro/native/network/credential assessment;
- source qualification and privileged dependency declaration where applicable;
- Self Security qualification before merge.

## Rollback / Failure Semantics

- Parser failure -> explicit coverage degradation; never clean posture.
- Unsupported security-relevant statement -> partial coverage with location/provenance.
- Ambiguous migration order -> fail analysis for the affected state or mark it uncertain; never guess.
- Secret detection -> redact before Evidence persistence.
- Provider config parse failure -> affected dimension partial/failed, not project PASS.
- Optional pack failure -> visible provider coverage failure; base Sentrdel remains operational.

## Complexity / Exceptions

No constitutional exception is requested. The main deliberate complexity is a narrow SQL posture parser/state reducer; this is justified because executing target Supabase/Postgres tooling would violate the repository trust boundary, while a full PostgreSQL implementation is unnecessary for R2.
