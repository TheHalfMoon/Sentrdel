# Research: Supabase P0 Static/Posture Pack

**Date:** 2026-08-29  
**Scope:** R2 offline/static posture only.

## Canonical starting point

R1 already provides:

- bounded Supabase presence detection in `crates/sentrdel-review/src/supabase_detection.rs`;
- canonical Evidence, Finding, Coverage, SecurityPackManifest, store/redaction, review/reconciliation, graph, and CLI contracts;
- target repository path/file bounds;
- tree-sitter/ast-grep structural parsing substrate;
- SentrdelBench release evaluation;
- a constitutional ban on executing target build/install/package/provider tooling during ordinary analysis.

R2 must extend these contracts rather than create a second provider-specific judgment path.

## Upstream Supabase semantics reviewed

Primary current documentation reviewed on 2026-08-29:

1. Supabase Row Level Security guide: `https://supabase.com/docs/guides/database/postgres/row-level-security`
   - RLS is the database authorization layer used for granular row access.
   - Tables in exposed schemas require careful RLS/grant posture; grants and RLS are distinct controls.
   - Supabase guidance recommends `SECURITY DEFINER` helpers outside exposed schemas and a pinned/empty `search_path` with schema-qualified names.

2. Supabase API key guide: `https://supabase.com/docs/guides/getting-started/api-keys`
   - publishable keys and legacy `anon` are low-authority/client-oriented;
   - secret keys and legacy `service_role` are elevated and bypass RLS;
   - elevated keys must remain in controlled backend contexts and must not be exposed in browser/client code.

3. Supabase Edge Function secrets guide: `https://supabase.com/docs/guides/functions/secrets`
   - Edge Functions receive provider variables through environment configuration;
   - elevated secret/service-role material is backend-only authority;
   - `.env` secret files must not be committed.

4. Supabase Edge Function authentication guidance: `https://supabase.com/docs/guides/functions/auth`
   - authenticated-user and secret/service-to-service modes have different authority;
   - privileged admin clients bypass RLS;
   - disabling platform JWT verification is not automatically insecure if an explicit replacement authorization boundary exists, therefore the R2 check must be contextual and coverage-aware rather than a raw boolean detector.

## Design decisions

### D1 — No target SQL execution

**Decision:** Parse migration SQL as bounded bytes; never start Postgres, Supabase CLI, containers, psql, migration runners, or repository scripts.

**Reason:** Execution would cross the R1 repository authority boundary and could activate arbitrary target-controlled code/configuration.

### D2 — Supported-subset state machine, not a full PostgreSQL implementation

**Decision:** Implement a deterministic migration-state reducer over an explicit SQL subset required by R2. Unsupported constructs produce parser coverage gaps/uncertainty.

**Supported initial semantic objects:** schemas, tables/views where needed for exposure, RLS enable/disable, policies, GRANT/REVOKE, functions with SECURITY DEFINER and search_path attributes, and Storage policies represented as SQL.

**Reason:** R2 needs security posture, not query planning/type checking. A narrow parser reduces dependency authority and makes unsupported behavior explicit.

### D3 — Repository-derived state is not hosted truth

**Decision:** Every posture record carries static provenance. Statements use wording such as “repository-derived migration state” rather than “your production database is configured as...”. LIVE_POSTURE remains separate and unexecuted.

### D4 — Preserve grants × RLS distinction

**Decision:** Model table/API role grants separately from RLS enablement and policies. The reconciler may combine supporting Evidence into a Finding, but no parser stage collapses the controls.

**Reason:** A table can have RLS and still have privilege/policy problems; absence of one signal cannot prove safety in the other layer.

### D5 — SECURITY DEFINER is high authority, not inherently vulnerable

**Decision:** Produce direct Evidence for SECURITY DEFINER, schema placement, and search_path posture. Escalate only supported dangerous combinations, especially absent/unsafe search_path and exposed callable placement.

### D6 — Key classes are authority classes

**Decision:** Recognize modern `sb_publishable_*` vs `sb_secret_*` classes and legacy anon/service_role semantic references. Synthetic secret-shaped fixture values must pass through R1 secret redaction.

**Reason:** Supabase is migrating away from JWT legacy keys; R2 should not freeze security semantics to legacy names.

### D7 — Client/server context must be bounded and conservative

**Decision:** Elevated-key misuse requires supported evidence that code is browser/client-facing, such as known frontend paths/framework entrypoints or browser-specific modules. Ambiguous placement remains inference/coverage, not a blocking fact.

### D8 — Edge Function auth requires replacement-auth awareness

**Decision:** `verify_jwt = false` or equivalent is a posture signal, not automatically a vulnerability. R2 checks whether a supported explicit authorization pattern is statically visible; otherwise it emits a bounded inference plus coverage caveat.

### D9 — No new provider SDK/runtime dependency

**Decision:** Base R2 adds no Supabase SDK, CLI, hosted API client, or database runtime dependency. Prefer existing parser substrate and Sentrdel-owned bounded parsing. Any new crate requires the existing dependency qualification path.

### D10 — Benchmark before breadth

**Decision:** Add R2 fixtures and benchmark dimensions before broadening the check inventory. Promotion of checks into release-gating status requires precision and known-ground-truth coverage evidence.

## Security risks and mitigations

- **Parser confusion / unsupported SQL:** fail boundedly, preserve explicit partial coverage.
- **Migration ordering ambiguity:** require canonical filename ordering and deterministic tie handling; surface ambiguity instead of guessing.
- **Dynamic SQL / generated migrations:** mark unsupported/dynamic areas; do not execute.
- **Secret leakage:** use existing changed-secret/redaction registration before persistent Evidence/logging.
- **False positive from SECURITY DEFINER:** separate observable function authority from unsafe search_path/exposure interpretation.
- **False positive from disabled Edge JWT:** account for supported replacement authorization patterns.
- **Provider semantic drift:** upstream references are research inputs; Sentrdel's versioned pack/rule semantics and benchmark fixtures remain review-controlled.

## Rejected alternatives

- Running `supabase db lint` as the canonical base analyzer: rejected because target/provider tooling execution violates the local untrusted-repository boundary and would introduce environment/runtime authority.
- Connecting to hosted Postgres for “ground truth” in R2: rejected; this requires credential, egress, consent, and live-posture contracts in a later slice.
- Embedding a full PostgreSQL server/parser stack: rejected as unnecessary authority/complexity for P0 static posture.
- Treating every `service_role` string or `verify_jwt=false` as a finding: rejected due to predictable false positives and context loss.
