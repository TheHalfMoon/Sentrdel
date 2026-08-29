# Feature Specification: Supabase P0 Static/Posture Pack

**Feature Branch:** `spec/002-supabase-static-posture`  
**Created:** 2026-08-29  
**Status:** SPECIFIED  
**Roadmap:** R2 in `specs/000-sentrdel-roadmap/roadmap.md`  
**Depends on:** R1 `Evidence + Guard Foundation`, canonical at `22e953aad1089b91c7b654addfa4086359353232`

## Overview

R2 turns the R1 Supabase presence detector into Sentrdel's first provider-specific offline static posture pack. It analyzes repository-owned Supabase migrations, configuration, Edge Functions, and relevant application boundary signals as bounded data. It emits canonical Evidence and Coverage through the R1 contracts and relies on the existing reconciler for Findings.

R2 is deliberately offline and deterministic by default. It does not connect to Supabase, read dashboard state, consume provider-admin credentials, run the Supabase CLI, execute migrations, execute Edge Functions, or claim runtime/live posture. Static repository evidence and live hosted posture remain separate coverage dimensions.

## User Story 1 — Review database authorization posture (P1)

A developer changes Supabase migrations or schema SQL. `sentrdel review` identifies high-signal authorization risks such as exposed tables lacking RLS enablement in repository-visible state, dangerous grants to API-facing roles, insecure `SECURITY DEFINER` functions, or policy changes that materially widen access.

**Independent test:** A fixture project with migrations covering safe and unsafe RLS/grant/function patterns produces deterministic Evidence with exact repository locations, explicit static-posture coverage, and no target SQL execution.

### Acceptance scenarios

1. Exposed table + repository-visible RLS disabled/absent -> bounded static-posture Evidence; wording does not claim hosted runtime state.
2. RLS enabled with restrictive policies -> no unsupported `secure` project-wide verdict; completed checks and remaining gaps are reported separately.
3. Policy/grant broadening -> changed-state Evidence identifies the observable delta and its interpretation separately.
4. `SECURITY DEFINER` function without a pinned safe `search_path` -> high-signal Evidence with function location.
5. Ambiguous migration history -> `UNCERTAIN`/coverage gap rather than invented final database state.

## User Story 2 — Review privileged key and client/server boundaries (P1)

A developer uses Supabase API credentials or initializes clients in application or Edge Function code. Sentrdel distinguishes publishable/anon client use from elevated secret/service-role usage and flags repository-visible placement of elevated authority in browser/client-facing contexts.

**Independent test:** Fixtures with browser code, server code, Edge Functions, environment-variable references, and synthetic key-shaped canaries classify the static authority boundary without persisting plaintext secret values.

### Acceptance scenarios

1. Publishable/anon identifier in browser context -> no elevated-key finding solely for that use.
2. Secret/service-role key reference in browser/client bundle path -> high-signal Evidence.
3. Elevated key in backend/Edge Function context -> not automatically a finding; surrounding authorization and exposure remain separate checks.
4. Any discovered secret material passes through the existing R1 redaction-before-persist boundary.

## User Story 3 — Review Storage/Auth/Edge Function posture signals (P1)

A developer changes Supabase Storage policies, Auth-related configuration, or Edge Function authorization configuration. Sentrdel emits deterministic static Evidence for a bounded set of high-signal misconfigurations and explicitly reports unsupported areas.

**Independent test:** Repository fixtures exercise Storage policy SQL, `supabase/config.toml`, Edge Function JWT/auth settings, and hostile/oversized inputs without opening network connections or executing provider tooling.

## Functional Requirements

### Authority and execution boundary

- **FR-001** R2 MUST remain Rust-owned for security-critical parsing, normalization, Evidence production, coverage, and orchestration.
- **FR-002** R2 MUST NOT execute target SQL, Supabase CLI commands, package-manager commands, Edge Functions, hooks, or repository-configured helpers during analysis.
- **FR-003** R2 MUST NOT connect to Supabase or require provider credentials for base static posture.
- **FR-004** Repository files, SQL, TOML, JavaScript/TypeScript, comments, generated descriptions, and provider metadata are untrusted data and cannot widen Sentrdel authority.

### Postgres / Data API static posture

- **FR-005** R2 MUST parse a bounded, explicitly supported SQL subset sufficient to recognize schema/table/view/function/policy/grant/revoke and RLS enable/disable changes required by this spec. Unsupported syntax MUST create visible uncertainty/coverage rather than silent acceptance.
- **FR-006** R2 MUST track repository-derived state across ordered Supabase migration files deterministically when the supported subset permits it.
- **FR-007** R2 MUST identify repository-visible API-exposed relations lacking RLS protection when exposure and final RLS state are statically supportable.
- **FR-008** R2 MUST identify high-signal grants or policy changes that widen API-facing `anon`/`authenticated` access when statically observable.
- **FR-009** R2 MUST detect `SECURITY DEFINER` functions with unsafe or unpinned `search_path` posture and distinguish function location/schema exposure from speculative exploitability.
- **FR-010** R2 MUST treat database privileges, RLS policies, and exposed-schema posture as related but distinct Evidence; one layer MUST NOT erase another.

### Keys and application authority

- **FR-011** R2 MUST distinguish low-authority publishable/legacy anon key use from elevated secret/legacy service-role authority where statically identifiable.
- **FR-012** R2 MUST flag elevated secret/service-role authority when repository-visible code places it in browser/client-facing contexts.
- **FR-013** Secret plaintext and stable unkeyed secret-value-only hashes MUST NOT enter persistent Evidence, logs, snapshots, or exports.

### Storage, Auth, and Edge Functions

- **FR-014** R2 MUST analyze repository-visible Storage authorization policies represented in supported SQL using the same Evidence/coverage discipline as database RLS.
- **FR-015** R2 MUST parse a bounded allowlisted portion of `supabase/config.toml` needed for static Auth/API/Edge Function posture checks; unknown or oversized configuration MUST fail boundedly and surface coverage.
- **FR-016** R2 MUST identify high-signal Edge Function authorization configurations where repository-visible settings disable or weaken JWT/auth verification, while avoiding a finding when an explicit supported replacement authorization mechanism is statically proven.
- **FR-017** R2 MUST NOT treat the presence of an Edge Function, Auth setting, Storage object, or Supabase project as a vulnerability by itself.

### Evidence, Findings, and coverage

- **FR-018** Every R2 producer MUST emit canonical R1 Evidence and Coverage only; only the existing reconciler may create Findings.
- **FR-019** Provider detection, STATIC_POSTURE, LIVE_POSTURE, BUSINESS_LOGIC, and RUNTIME coverage MUST remain distinct dimensions.
- **FR-020** R2 MUST report LIVE_POSTURE as not executed/not implemented unless a later spec explicitly authorizes bounded credentialed access.
- **FR-021** Unsupported SQL/config/code constructs, incomplete migration history, dynamic construction, and missing files MUST remain visible as PARTIAL/UNAVAILABLE/NOT_IMPLEMENTED coverage as appropriate.
- **FR-022** Evidence observations MUST describe bounded repository facts; semantic security interpretation MUST remain separate from direct observation.

### Change-relative review

- **FR-023** `sentrdel review` SHOULD prioritize changed migrations/config/function code and preserve enough deterministic prior/current repository state to classify safe static deltas without inventing hosted-state causality.
- **FR-024** R2 MUST support deterministic replay and stable evidence identity for equivalent repository inputs.

## Success Criteria

- **SC-001** All release-gating R2 checks meet the active SentrdelBench clean-PR false-positive gate (no worse than 1 FP per 5 clean PRs).
- **SC-002** Every high/blocking R2 finding has exact repository location when applicable, direct observation, provider/rule provenance, epistemic status, and static-vs-live coverage.
- **SC-003** R2 static analysis performs no target/provider network or executable action in base mode, proven by adversarial fixtures/canaries.
- **SC-004** Known-ground-truth R2 fixture cases for RLS, grants, `SECURITY DEFINER`, elevated client keys, Storage policy, and Edge Function auth achieve zero known misses in the release-gating fixture set.
- **SC-005** Malformed/unsupported/oversized SQL/TOML/source inputs are bounded and cannot become clean posture by parser failure.
- **SC-006** No discovered secret plaintext or stable unkeyed secret-value-only digest is persisted by R2.

## Non-Goals

- Live Supabase dashboard/project interrogation.
- Applying migrations or executing SQL.
- Full PostgreSQL parser/planner/type system.
- Proving runtime data visibility or exploitability.
- Automatic remediation or migration mutation.
- Cross-layer tenant/business-logic invariants; those belong to R3.
- Firebase/Stripe/cloud provider breadth.
- Provider-admin credentials in base R2.

## External semantic references

R2 behavior is grounded in current Supabase security guidance while keeping Sentrdel's own contracts authoritative. Key upstream semantics to track during implementation include RLS requirements for exposed schemas, the interaction between grants and RLS, safe `SECURITY DEFINER`/`search_path` posture, elevated secret/service-role keys bypassing RLS, and Edge Function authorization boundaries. Exact upstream references and qualification dates are recorded in `research.md`.
