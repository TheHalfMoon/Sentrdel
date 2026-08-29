# Data Model: Supabase P0 Static/Posture Pack

**Status:** DESIGN_FROZEN_FOR_TASKING  
**Date:** 2026-08-29

R2 reuses canonical R1 Evidence, Finding, Coverage, ProjectProfile, graph, and SecurityPackManifest schemas. The types below are internal provider analysis models unless a later task proves a versioned public schema is required.

## Core identities

### `SupabaseObjectId`

```text
schema: normalized SQL identifier
name: normalized SQL identifier
kind: TABLE | VIEW | FUNCTION | POLICY | SCHEMA | OTHER_SUPPORTED
```

Identity is repository-analysis identity, not a hosted Supabase object identifier.

### `StatementProvenance`

```text
path: NormalizedRepoPath
migration_order: deterministic ordinal
statement_index: bounded ordinal
start_line/start_column/end_line/end_column: optional bounded location
content_digest: digest of non-secret source bytes under existing canonical rules
```

Provenance identifies where repository-derived posture came from.

## Migration model

### `MigrationInput`

```text
path
order_key
content_digest
bytes_len
```

Rules:

- path must be canonical repository-relative;
- bytes are read through `RepoFileView` caps;
- ordering must be deterministic;
- ambiguous duplicate order keys fail closed for stateful analysis.

### `SqlParseCoverage`

```text
SUPPORTED
IGNORED_SAFE_SCOPE
UNSUPPORTED_SECURITY_RELEVANT
MALFORMED_OR_BOUNDED_REJECTION
```

An unsupported security-relevant statement degrades the affected provider coverage dimension.

### `SupportedSqlStatement`

Initial variants:

```text
CREATE_SCHEMA
CREATE_TABLE
ALTER_TABLE_ENABLE_RLS
ALTER_TABLE_DISABLE_RLS
CREATE_POLICY
ALTER_POLICY
DROP_POLICY
GRANT
REVOKE
CREATE_FUNCTION
ALTER_FUNCTION
DROP_FUNCTION
CREATE_VIEW          # only attributes needed by R2
OTHER_RECOGNIZED_SAFE_SCOPE
```

The representation stores only security-relevant normalized properties and provenance. It does not attempt to preserve arbitrary SQL semantics.

## Repository-derived posture state

### `RelationPosture`

```text
object: SupabaseObjectId
exists_in_supported_history: bool
rls_state: ENABLED | DISABLED | UNKNOWN
grant_state: normalized supported grants by role/privilege
policy_ids: deterministic set of known policy identities
exposure_state: API_RELEVANT | NOT_PROVEN_API_RELEVANT | UNKNOWN
last_security_change: StatementProvenance
```

`UNKNOWN` is first-class and cannot be treated as secure.

### `PolicyPosture`

```text
relation
policy_name
command_scope: ALL | SELECT | INSERT | UPDATE | DELETE | UNKNOWN
roles: deterministic supported role set
using_expression_digest: optional non-secret expression digest
check_expression_digest: optional non-secret expression digest
semantic_shape: bounded normalized attributes only
provenance
```

R2 does not claim full SQL expression equivalence. Expression digests are context fingerprints, not proof of authorization semantics.

### `FunctionPosture`

```text
object
security_mode: INVOKER | DEFINER | UNKNOWN
search_path: PINNED_EMPTY | PINNED_EXPLICIT | UNPINNED_OR_MUTABLE | UNKNOWN
schema_exposure: API_RELEVANT | NOT_PROVEN_API_RELEVANT | UNKNOWN
execute_grants: supported role set
provenance
```

`SECURITY DEFINER` alone is privileged posture; dangerous combinations determine finding interpretation.

## Supabase configuration model

### `SupabaseConfigPosture`

Only allowlisted keys needed by R2 are retained. Unknown values are ignored as data unless their presence prevents safe interpretation, in which case coverage is PARTIAL.

```text
api_exposed_schemas: optional deterministic schema set
edge_function_auth: map<function_name, EdgeAuthPosture>
auth_static_flags: bounded allowlisted map
parse_coverage
provenance
```

No secret values are retained.

### `EdgeAuthPosture`

```text
function_name
platform_jwt_verification: ENABLED | DISABLED | UNKNOWN
supported_replacement_auth: PROVEN | NOT_PROVEN | UNKNOWN
provenance[]
```

The distinction prevents `verify_jwt=false` from becoming an unconditional finding.

## Key authority model

### `SupabaseKeyClass`

```text
PUBLISHABLE
LEGACY_ANON
SECRET
LEGACY_SERVICE_ROLE
UNKNOWN_SUPABASE_KEY
```

### `SourceExecutionContext`

```text
BROWSER_OR_CLIENT
SERVER
EDGE_FUNCTION
TEST_OR_FIXTURE
UNKNOWN
```

### `KeyAuthorityObservation`

```text
key_class
context
path/location
redacted_display
sanitized_non_secret_fingerprint
```

The raw secret value and stable unkeyed value-only digest are never fields.

## Provider coverage

### `SupabasePostureCoverage`

Maps to R1 CoverageRecord dimensions:

```text
DETECTION
STATIC_POSTURE_DATABASE
STATIC_POSTURE_STORAGE
STATIC_POSTURE_AUTH_CONFIG
STATIC_POSTURE_EDGE_FUNCTIONS
STATIC_POSTURE_KEY_BOUNDARY
LIVE_POSTURE
BUSINESS_LOGIC
RUNTIME
```

Each dimension records normal R1 coverage state and diagnostic/provenance. R2 MUST leave LIVE_POSTURE/BUSINESS_LOGIC/RUNTIME explicitly unimplemented/not executed.

## Evidence mapping

Direct Evidence observations should be narrowly factual examples:

- `RLS is disabled for relation public.accounts in repository-derived migration state.`
- `Function private.lookup_role is SECURITY DEFINER and has no supported pinned search_path attribute.`
- `An elevated Supabase secret-key class is referenced from a supported browser/client context.`
- `Edge Function webhook has platform JWT verification disabled; no supported replacement authorization pattern was proven.`

Security interpretation is separate and may explain why the posture can widen data or privileged function access.

## Finding correlation

The existing reconciler correlates provider Evidence using stable non-secret fingerprints and subjects. R2 producers do not construct Finding objects directly.

Likely correlation subjects:

- relation object identity;
- function object identity;
- edge function name + repository path;
- key boundary path/context.

## Invariants

1. No type stores discovered secret plaintext.
2. No stable value-only secret digest is persisted.
3. Hosted/live state is never represented as proven by repository migration state.
4. Unknown parser/config state is not equivalent to secure state.
5. Unsupported security-relevant syntax degrades coverage.
6. Provider pack state cannot create Findings or policy decisions directly.
7. Deterministic inputs produce deterministic internal state and Evidence identity.
