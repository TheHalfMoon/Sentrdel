# Data Model: Business-Logic Substrate + Invariants

**Status:** DESIGN_FROZEN_FOR_TASKING  
**Date:** 2026-09-01

R3 reuses canonical R1 Evidence, Finding, Coverage, ProjectProfile, graph, SecurityPackManifest, store/redaction and SentrdelBench contracts. The types below are internal analysis models unless a later implementation task proves a versioned public schema is required.

## Identity and provenance rules

Every R3 semantic record MUST have:

- deterministic repository-relative semantic identity;
- explicit source provenance;
- no workstation-specific absolute path or random identity component;
- no secret plaintext or secret-value-only stable digest;
- explicit UNKNOWN/unsupported state where semantics cannot be proven.

Lexical name equality is not identity equivalence. A route parameter named `userId`, an authenticated user ID, a database `user_id` column and a tenant claim remain distinct until a supported adapter/link establishes their relationship.

## `RouteId`

```text
framework_family
normalized_repository_path
route_kind
http_method
normalized_route_pattern
handler_semantic_key
```

`RouteId` is repository-analysis identity. It is not a deployed URL identity and does not prove the route is reachable in production.

## `SourceLocation`

```text
path: NormalizedRepoPath
start_byte/end_byte
start_line/start_column/end_line/end_column: optional bounded coordinates
content_digest
```

Locations bind observations to bounded source bytes.

## `RouteObservation`

```text
route_id: RouteId
framework: EXPRESS | NEXT_APP | NEXT_PAGES_API | SUPABASE_EDGE | OTHER_SUPPORTED
method: GET | POST | PUT | PATCH | DELETE | OPTIONS | HEAD | OTHER_SUPPORTED
route_pattern
handler_symbol: optional stable symbol identity
callback_chain: ordered bounded list<HandlerLink>
provenance[]
coverage_state
```

Dynamic route generation or unresolved callback identity never becomes an empty safe chain; it degrades route/link coverage.

## `ActorContext`

```text
actor_id
identity_kind: AUTHENTICATED_USER | TENANT | ROLE | SERVICE | ANONYMOUS | REQUEST_CONTROLLED | UNKNOWN
source_kind: VERIFIED_AUTH_ADAPTER | REQUEST_PARAM | REQUEST_BODY | REQUEST_HEADER | TOKEN_CLAIM | CONSTANT | DERIVED_SUPPORTED | UNKNOWN
semantic_key
trust_basis: DIRECT_OBSERVATION | SUPPORTED_DERIVATION | UNKNOWN
provenance[]
```

`VERIFIED_AUTH_ADAPTER` means the adapter can identify a supported authentication/identity source statically. It does not mean the user/token is valid at runtime.

## `GuardKind`

```text
AUTHENTICATION
REQUIRED_ROLE
TENANT_BINDING
OWNERSHIP_BINDING
OBJECT_MEMBERSHIP
PROPERTY_ALLOWLIST
PROPERTY_DENYLIST_REQUIREMENT
ELEVATED_CLIENT_BOUNDARY
CUSTOM_INVARIANT_REQUIREMENT
```

Guard kinds are independent. One cannot silently satisfy another.

## `GuardObservation`

```text
guard_id
guard_kind
subject_actor: optional ActorContext identity
resource: optional ResourceRef
required_values: deterministic bounded set
comparison_shape: EQUAL | MEMBERSHIP | CONJUNCTION_SUPPORTED | EXPLICIT_ALLOWLIST | OTHER_SUPPORTED | UNKNOWN
dominance_scope: SAME_HANDLER_PREFIX | SUPPORTED_MIDDLEWARE_PREFIX | LINKED_HELPER | UNKNOWN
provenance[]
```

A guard is an observation about supported source structure. `dominance_scope=UNKNOWN` cannot satisfy a path invariant.

## `ValueOriginKind`

```text
REQUEST_PATH
REQUEST_QUERY
REQUEST_BODY
REQUEST_HEADER
AUTHENTICATED_USER_ID
AUTHENTICATED_TENANT_ID
AUTHENTICATED_ROLE
CONSTANT
SUPPORTED_DERIVED
DATABASE_RESULT
UNKNOWN
```

## `ValueOrigin`

```text
value_id
origin_kind
semantic_key
source_actor: optional ActorContext identity
derivation_inputs[]
provenance[]
```

Derivation depth and fan-in are bounded. Unsupported expressions terminate in UNKNOWN rather than inferred equivalence.

## `ProviderClientAuthority`

```text
client_id
provider: SUPABASE | OTHER_SUPPORTED
authority_class: USER_SCOPED | PUBLISHABLE_OR_ANON | ELEVATED_SECRET_OR_SERVICE_ROLE | SERVER_UNKNOWN | UNKNOWN
source_evidence_ids[]
provenance[]
```

R2 key/static context may support authority classification. Elevated authority does not itself imply a vulnerability.

## `DataOperationKind`

```text
READ
INSERT
UPDATE
UPSERT
DELETE
RPC
OTHER_SUPPORTED
```

## `FilterPredicate`

```text
field_semantic_key
operator: EQ | IN | MATCH_SUPPORTED | OTHER_SUPPORTED
value_origin: ValueOrigin identity
provenance
```

Arbitrary SQL/query semantics are not represented.

## `FieldSet`

```text
mode: EXPLICIT | BROAD_REQUEST_OBJECT | DYNAMIC | UNKNOWN
fields: deterministic bounded set<string>
value_origins: optional map<field, ValueOrigin>
provenance
```

`BROAD_REQUEST_OBJECT` is used only when the adapter proves a broad request-controlled object feeds a supported mutation operation. Dynamic fields remain explicit.

## `DataOperation`

```text
operation_id
operation_kind
resource: ResourceRef
provider_client: optional ProviderClientAuthority identity
filters[]
read_fields: optional FieldSet
mutation_fields: optional FieldSet
rpc_name: optional normalized identifier
handler_symbol: optional stable symbol identity
provenance[]
coverage_state
```

A `DataOperation` records static source intent only. It does not prove execution or hosted data effects.

## `ResourceRef`

```text
provider: optional provider family
namespace: optional normalized schema/domain
resource_name
resource_kind: TABLE | VIEW | FUNCTION | STORAGE_OBJECT | APPLICATION_RESOURCE | OTHER_SUPPORTED
r2_subject: optional canonical R2 subject reference
```

Where an R2 subject exists, the link preserves the original R2 Evidence identity/provenance rather than rewriting it.

## `LinkBasis`

```text
SAME_HANDLER_STRUCTURAL
SUPPORTED_CALLBACK_CHAIN
SUPPORTED_IMPORT_BINDING
SCIP_REFERENCE
EXPLICIT_ADAPTER_LINK
UNKNOWN
```

## `CrossLayerLink`

```text
source_semantic_id
target_semantic_id
relation
basis: LinkBasis
confidence_basis: EXTRACTED | INFERRED | AMBIGUOUS
provenance[]
```

Confidence remains graph/context metadata. It cannot upgrade Evidence epistemic class.

## `CrossLayerPath`

```text
path_id
route_id
actor_ids[]
guard_ids[]
data_operation_id
provider_client_id: optional
links[]
r2_evidence_ids[]
path_state: SUPPORTED | PARTIAL | AMBIGUOUS | BOUNDED_REJECTION
provenance[]
```

Path identity is derived from ordered stable semantic identities and link basis, not timestamps.

Hard limits apply to path length, candidate paths, graph nodes/edges and correlated observations.

## Invariant model

### `InvariantKind`

```text
TENANT_BINDING
REQUIRED_ROLE
PROTECTED_PROPERTIES
ELEVATED_CLIENT_CONTEXT
```

The initial project-declarable set is intentionally no broader than the initial built-in evaluator families.

### `InvariantSource`

```text
BUILT_IN
PROJECT_DECLARATION
```

Project declarations are requirements only and receive no suppression/authority semantics.

### `InvariantDefinition`

```text
invariant_id
kind: InvariantKind
source: InvariantSource
scope: InvariantScope
requirements: typed invariant-specific requirement
provenance[]
```

Project `invariant_id` values are namespaced separately from Sentrdel built-ins so repository input cannot impersonate built-in identifiers.

### `InvariantScope`

```text
route_pattern: optional bounded normalized pattern
http_methods: optional deterministic set
resource: optional ResourceRef
operation_kinds: optional deterministic set
target_paths: optional bounded repository-relative patterns
```

Scope patterns are declarative matching data, never executable glob/shell commands.

### `TenantBindingRequirement`

```text
resource_tenant_field
required_actor_identity: AUTHENTICATED_USER_ID | AUTHENTICATED_TENANT_ID
allowed_supported_filter_shapes
```

### `RequiredRoleRequirement`

```text
required_roles: non-empty deterministic set
applies_to_operation_or_route
```

### `ProtectedPropertiesRequirement`

```text
protected_properties: non-empty deterministic set
mutation_operations
```

### `ElevatedClientContextRequirement`

```text
allowed_server_contexts
required_guard_kinds: deterministic non-empty set
```

## `InvariantEvaluationState`

```text
SATISFIED
VIOLATED
UNKNOWN
NOT_APPLICABLE
```

`UNKNOWN` MUST NOT be aggregated as satisfied or clean.

## `InvariantEvaluation`

```text
evaluation_id
invariant_id
path_id: optional
state: InvariantEvaluationState
supporting_observation_ids[]
contradicting_observation_ids[]
coverage_reasons[]
provenance[]
```

A violation is an R3 security interpretation supported by bounded observations. Canonical Finding creation remains with the reconciler.

## Business-logic coverage

### `BusinessLogicCoverageArea`

```text
ROUTES
ACTOR_IDENTITY
GUARDS
VALUE_ORIGINS
DATA_OPERATIONS
LOCAL_LINKING
SEMANTIC_LINKING
R2_PROVIDER_CORRELATION
PROJECT_INVARIANTS
INVARIANT_EVALUATION
```

### `BusinessLogicCoverage`

```text
area
state: canonical CoverageState
reason_code
scope
input_digests[]
producer
```

Aggregate provider/project `CROSS_LAYER_BUSINESS_LOGIC` coverage is derived monotonically from relevant subareas: partial/failed/unsupported required areas cannot be erased by another covered area.

## Evidence mapping

Direct observations remain narrow examples:

- `POST /api/accounts/:id is a supported Express route at src/routes/accounts.ts.`
- `The supported data operation filters accounts.id from request path parameter id.`
- `The supported operation uses an elevated Supabase service-role client derived from R2 key-authority evidence.`
- `A supported role guard requiring admin dominates the bounded privileged operation path.`

Cross-layer interpretations remain separate examples:

- `No supported actor/tenant binding was found on the covered route-to-operation path; tenant-binding invariant is VIOLATED within the declared static scope.`
- `Protected field role is included in a broad request-controlled mutation; protected-properties invariant is VIOLATED within the supported mutation model.`

Neither form may claim actual production exploitability or cross-tenant access.

## Graph mapping

R3 SHOULD reuse existing graph vocabulary where valid:

- route/handler -> `Symbol` or bounded resource/symbol identity;
- data target -> `Resource`;
- invariant -> `Invariant`;
- supported relations -> `Calls`, `ReadsFrom`, `WritesTo`, `FlowsTo`, `Supports`, `Contradicts`, `CrossesTrustBoundary`.

If a required R3 relationship cannot be represented without ambiguous overloading, an implementation task must either keep it internal or propose a minimal reviewed schema extension; planning does not pre-authorize new public graph variants.

## Invariants

1. Unknown or unsupported semantics never become `SATISFIED`.
2. Project declarations can add requirements only; they cannot suppress or weaken Sentrdel authority.
3. R2 static posture remains static and independently provenance-backed.
4. Elevated client authority is contextual, not automatically vulnerable.
5. Graph confidence cannot upgrade Evidence epistemic authority.
6. Cross-layer identity equivalence requires a supported link; names alone are insufficient.
7. Every release-gating violation preserves route/guard/data/invariant provenance sufficient for deterministic explanation.
8. No type stores discovered secret plaintext or an unkeyed value-only secret digest.
9. Deterministic equivalent inputs produce deterministic internal identities, ordering and semantic output.
10. No model type grants target execution, provider/network credential, policy, kernel, reconciler or Finding authority.
