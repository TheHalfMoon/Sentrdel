# Research: Business-Logic Substrate + Invariants

**Date:** 2026-09-01  
**Scope:** R3 offline/static cross-layer authorization analysis and security invariants.

## Canonical starting point

R1/R2 already provide the security authority and most of the required substrate:

- canonical Evidence, Finding, Coverage, policy, store/redaction, reconciliation, and CLI contracts;
- the reconciler as the sole canonical Finding creation path;
- bounded target repository view/path/file handling;
- `ast-grep-core` + `tree-sitter-javascript` structural matching in `sentrdel-review`;
- a thin canonical `sentrdel-graph` with stable identities, provenance, producer-local confidence, bounded reachability/subtree/diff operations, and `UNIVERSAL_CPG = false`;
- bounded optional SCIP ingestion for semantic reference evidence;
- R2 Supabase migration/config/key/static-posture Evidence, with business logic intentionally left unimplemented;
- `BUSINESS_LOGIC` pack coverage and public `CROSS_LAYER_BUSINESS_LOGIC` provider coverage semantics;
- SentrdelBench Core precision, miss/recall, clean-case false-positive, coverage, provenance, deterministic replay, authority, latency/resource, and protected-holdout contracts;
- constitutional bans on ordinary target build/install/package/provider execution and on treating untrusted content as instruction authority.

R3 therefore extends the existing judgment plane rather than creating a new graph, scanner verdict path, benchmark system, or provider runtime.

## Current external semantics reviewed

The following upstream documentation was reviewed as research input on 2026-09-01. Sentrdel's versioned reviewed contracts remain canonical runtime behavior; external documentation does not become direct runtime authority.

### OWASP API authorization guidance

Primary references:

- `https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/`
- `https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/`
- `https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/`
- `https://owasp.org/www-project-web-security-testing-guide/`

Relevant semantics:

- object identifiers controlled by a caller require object-level authorization, not merely successful authentication;
- property-level authorization is independent of object-level access and includes unsafe exposure or mutation of protected fields;
- function-level authorization must protect privileged functions/actions and cannot be assumed from route naming;
- authorization checks need to apply to the actual object/function/action path rather than relying on obscurity or identifiers alone.

**R3 consequence:** actor identity, object/tenant binding, function/role authorization, and protected-property mutation are separate invariant families. A single auth call or lexical guard match is not end-to-end proof.

### Supabase authorization and elevated authority

Primary references:

- `https://supabase.com/docs/guides/database/postgres/row-level-security`
- `https://supabase.com/docs/guides/database/postgres/column-level-security`
- `https://supabase.com/docs/guides/database/postgres/roles`
- `https://supabase.com/docs/guides/api/api-keys`
- `https://supabase.com/docs/guides/auth/server-side/nextjs`

Relevant semantics:

- PostgreSQL grants and RLS are independent authorization layers;
- RLS policies constrain row access for ordinary API roles but elevated service-role/secret authority can bypass RLS;
- backend elevated keys therefore require an application-side authorization boundary and must not be interpreted as user-scoped merely because RLS exists;
- server-side authentication code must distinguish verified identity from caller-controlled or merely cached/session-shaped data;
- column/property access can require protection independently of row/object access.

**R3 consequence:** R2 posture can support R3 correlation, but R3 never treats `RLS enabled` as sufficient end-to-end authorization and never rewrites repository-derived posture into hosted truth.

### Express route semantics

Primary reference:

- `https://expressjs.com/en/guide/routing.html`

Relevant semantics:

- Express routes are registered by HTTP method/path and one or more callback/middleware functions;
- route handlers may be chained, and middleware order matters to request processing;
- dynamic application composition can exceed a simple lexical model.

**R3 consequence:** an Express adapter may extract supported method/path/callback chains, but unsupported dynamic registration or middleware linkage must degrade coverage.

### Next.js route semantics

Primary references:

- `https://nextjs.org/docs/app/getting-started/route-handlers`
- `https://nextjs.org/docs/pages/building-your-application/routing/api-routes`

Relevant semantics:

- App Router Route Handlers are defined in `route.js`/`route.ts` files with exported HTTP-method functions;
- Pages API routes are server endpoint surfaces under the API route convention;
- endpoint authorization remains application responsibility.

**R3 consequence:** file/layout conventions provide bounded route evidence but do not themselves prove authorization.

## Existing native structural substrate

`crates/sentrdel-review/src/structural.rs` already provides:

- Sentrdel-owned compiled structural rules;
- bounded rule count, pattern bytes, document bytes, and deterministic match ordering;
- JavaScript tree-sitter parsing through `ast-grep-core`;
- explicit failure on malformed/missing parser nodes;
- no repository-provided rule execution, dynamic grammar loading, target commands, package managers, builds, or network operations.

Current exact workspace dependencies include:

- `ast-grep-core = 0.45.2`
- `tree-sitter = 0.26.13`
- `tree-sitter-javascript = 0.25.0`

No TypeScript grammar dependency is currently admitted.

## TypeScript grammar dependency candidate

A TypeScript grammar may materially improve source coverage because the intended framework scope commonly uses `.ts`/`.tsx`. The current upstream `tree-sitter-typescript` package/repository is a **candidate only**. Planning does not authorize adoption.

Before any adoption, an explicit task must record and qualify at minimum:

- exact upstream repository/ref/tag and package version;
- crate checksum and selected features;
- license expression/notices;
- `build.rs`, `cc`, generated/native source, proc-macro, artifact-download, network, and credential surfaces;
- lockfile delta and transitive privileged/build surfaces;
- source/privileged-dependency ledger updates;
- exact-head Self Security qualification.

If qualification does not complete safely, R3 remains JavaScript-first or uses already-qualified bounded semantic evidence and reports TypeScript coverage honestly.

## Graph and semantic-linking substrate

The canonical graph already contains useful node/relation vocabulary, including `Symbol`, `Resource`, `Invariant`, `Evidence`, `Finding`, `Calls`, `ReadsFrom`, `WritesTo`, `FlowsTo`, `Supports`, `Contradicts`, and `CrossesTrustBoundary`.

R3 should project cross-layer observations into this graph only when the stable semantic identity/provenance contract can represent them without inventing a new authority model. Graph confidence remains producer-local metadata and cannot mint stronger Evidence.

SCIP ingestion is useful for supported inter-file symbol/reference linkage. It is optional and bounded. Absence, unsupported language coverage, producer qualification failure, or ambiguity must remain visible coverage rather than silently falling back to a secure conclusion.

## R2 integration boundary

R2 provides distinct repository-derived observations for:

- RLS state and policy shape;
- grants/revokes;
- SECURITY DEFINER/search-path posture;
- Supabase client/key authority classes and source context;
- Storage/Auth/Edge static signals;
- explicit `LIVE_POSTURE`, `BUSINESS_LOGIC`, and `RUNTIME` gaps.

R3 can correlate these observations with routes, actor identity, guards, and data operations. R3 must preserve original R2 provenance and static-vs-live wording. A cross-layer interpretation is a new supported inference path, not a retroactive change to R2 facts.

## Evaluation substrate

SentrdelBench already prevents several failure modes critical to R3:

- no single aggregate score replaces precision/miss/coverage/authority dimensions;
- missing denominators cannot become perfect metrics;
- missing/failed coverage cannot become a clean result;
- deterministic replay compares semantic output;
- protected holdout expected outputs are separated from candidate-generation logic;
- an authority-contract violation invalidates qualification even if detection metrics improve.

R3 therefore extends corpus metadata and expected cross-layer outcomes rather than adding a second evaluator.

## Design decisions

### D1 — Static cross-layer IR before rules

**Decision:** Freeze an internal normalized representation for routes, actor identity, guards, value origins, data operations, client authority, paths, invariants, and evaluation state before adding release-gating rules.

**Reason:** Cross-layer checks otherwise devolve into unrelated lexical heuristics whose coverage and provenance cannot be composed safely.

### D2 — Adapter-first semantics

**Decision:** Each framework/data SDK surface enters through an explicit bounded adapter and declares what it can and cannot prove.

**Reason:** Framework-specific route/middleware/data semantics differ. Explicit adapters make unsupported state observable and prevent a generic matcher from overclaiming semantic authority.

### D3 — Reuse one canonical graph

**Decision:** Use `sentrdel-graph` for bounded path/context projection; do not add another graph database/runtime or universal CPG.

**Reason:** The existing graph already owns stable identity/provenance/bounded traversal, and duplicate graph truth would create authority drift.

### D4 — Conservative identity equivalence

**Decision:** Request parameters, authenticated user IDs, tenant claims, object columns, and variables are distinct until a supported extraction/link proves their relationship.

**Reason:** Name equality is not semantic equality. False identity joins are particularly dangerous in tenant-isolation analysis.

### D5 — Guards are typed, not generic booleans

**Decision:** Preserve authentication, role/function authorization, tenant/ownership binding, protected-property filtering, and project-invariant guards separately.

**Reason:** One control cannot silently substitute for another.

### D6 — R2 posture is supporting evidence

**Decision:** Correlate R2 static posture/key authority without treating it as hosted truth or sufficient application authorization.

**Reason:** Grants/RLS/application guards/elevated clients are independent layers.

### D7 — Project invariants tighten only

**Decision:** If a project invariant file is implemented, it can express additional requirements only.

**Reason:** Repository-controlled configuration is untrusted and cannot become a suppression, severity override, policy bypass, credential grant, or epistemic authority channel.

### D8 — UNKNOWN is first-class

**Decision:** Invariant/path evaluation has explicit unknown/unsupported states that propagate into coverage.

**Reason:** Business-logic analysis frequently encounters dynamic dispatch, middleware, generated code, framework indirection, or unresolved references. Guessing would create false security claims.

### D9 — Evaluation before release breadth

**Decision:** Freeze safe/unsafe/unknown/adversarial fixtures and expected Evidence/Coverage before promoting R3 checks into release-gating status.

**Reason:** R3 is highly false-positive-sensitive. Benchmark history must constrain detector breadth.

### D10 — No target execution as a shortcut

**Decision:** Ordinary R3 does not run the application, test suite, database, provider, package manager, or build system to resolve ambiguity.

**Reason:** That authority belongs to a later explicitly isolated Safe Verification slice. R3 remains a safe static judgment substrate.

## Security risks and mitigations

- **False semantic joins:** require stable supported identity/link evidence; otherwise UNKNOWN.
- **Dynamic middleware/callbacks:** explicit partial coverage rather than guessed dominance.
- **Mass-assignment false positives:** require supported request origin + mutation operation + property model; preserve dynamic-field uncertainty.
- **RLS overtrust:** model R2 posture separately and track elevated client authority.
- **Graph explosion:** hard caps on nodes, edges, path depth, candidate paths and diagnostics.
- **Untrusted project invariant configuration:** structured bounded parser, tightening-only semantics, no executable content, built-in analysis never suppressed.
- **Dependency expansion:** explicit qualification task before any TypeScript grammar or new parser enters.
- **Benchmark overfitting:** existing protected-holdout boundary and immutable evaluator inputs remain mandatory for promotion.

## Rejected alternatives

- **Universal CPG / new graph database:** rejected; duplicates the canonical graph and broadens trusted/runtime authority.
- **Run target tests/application for authorization truth:** rejected from R3; belongs to separately authorized Safe Verification.
- **Connect to hosted Supabase for ground truth:** rejected; credentialed live posture is separate authority.
- **Regex-only verdict engine:** rejected; lexical matches may be inputs but cannot safely establish cross-layer authorization paths.
- **Project suppression/exception rules inside invariants:** rejected; repository configuration cannot weaken evidence or judgment authority.
- **Mandatory SCIP/external indexer:** rejected; optional semantic evidence must not make normal local analysis dependent on an external engine.
- **Full JavaScript/TypeScript compiler or symbolic executor:** rejected as unnecessary complexity/authority for the bounded R3 slice.
