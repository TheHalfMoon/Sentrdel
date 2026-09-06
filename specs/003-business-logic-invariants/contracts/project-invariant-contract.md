# Contract: R3 Project Security Invariants

**Version:** 1  
**Status:** IMPLEMENTED_FOR_R3_T025  
**Implemented surface:** `.sentrdel/invariants.toml`, loaded by `crates/sentrdel-review/src/business_logic/project_invariant.rs` under the bounded version-1 grammar and authority ceiling frozen by this contract. Persistent Evidence/Coverage mapping remains separately governed by R3-T026.

## Purpose

Project invariants let a repository state additional security requirements that Sentrdel can evaluate against the bounded R3 cross-layer representation. They are **tightening-only requirements**, not policy overrides, suppressions, waivers, executable rules, or new security authority.

Repository invariant content is untrusted data.

## Authority ceiling

A project invariant MAY:

- require a tenant/owner binding for a supported resource/path;
- require one or more roles for a supported route/action;
- identify protected properties that must not receive broad request-controlled mutation;
- require supported application guards around elevated provider-client authority;
- narrow a requirement to bounded route/resource/operation/path scope.

A project invariant MUST NOT:

- suppress deterministic Evidence;
- suppress, waive, ignore, retire or automatically accept a Finding;
- lower severity, confidence or epistemic class;
- mark accepted risk or create an expiry-free exception;
- widen process, filesystem, network, provider, credential or secret authority;
- authorize target/provider execution;
- override repository/core/user policy or a kernel invariant;
- alter reconciler-only Finding creation;
- declare FACT, VERIFIED or FIX_VERIFIED status;
- modify benchmark expected outputs, evaluator behavior, protected holdouts or release gates;
- load code, plugins, scripts, commands, templates or dynamic expressions;
- import remote content or require network access.

Unknown fields cannot create permissive behavior.

## Implemented bounded document shape

R3-T025 implements an exact Sentrdel-owned version-1 grammar at `.sentrdel/invariants.toml`: an exact integer `version = 1`, `[[invariant]]` records, lowercase-ASCII/underscore keys, quoted non-empty strings without escapes/control characters, and flat arrays of quoted strings. Blank lines and full-line `#` comments are inert. Unknown structure, keys, value syntax, versions, unsupported classes, or malformed records reject the whole project declaration.

```toml
version = 1

[[invariant]]
id = "accounts-tenant-binding"
type = "tenant_binding"
resource = "public.accounts"
route = "/api/accounts/:id"
methods = ["GET", "PATCH"]
tenant_field = "user_id"
actor = "authenticated_user_id"

[[invariant]]
id = "admin-delete-role"
type = "required_role"
route = "/api/admin/users/:id"
methods = ["DELETE"]
roles = ["admin"]

[[invariant]]
id = "profile-protected-fields"
type = "protected_properties"
resource = "public.profiles"
operations = ["UPDATE", "UPSERT"]
properties = ["role", "is_admin", "tenant_id"]

[[invariant]]
id = "service-role-request-boundary"
type = "elevated_client_context"
route = "/api/internal/*"
required_guards = ["required_role"]
allowed_contexts = ["express-server"]
```

The field vocabulary and parser behavior above are frozen by R3-T025 and its implementation tests. Changing the version, admitting new value syntax, adding inert metadata, or widening any authority-bearing field requires ordinary reviewed spec/contract evolution.

## Version contract

- A declaration MUST contain an exact supported integer version.
- Unknown versions fail validation for project invariants and produce explicit configuration/coverage diagnostics.
- Version failure MUST NOT disable built-in R3 analysis.
- Version changes require ordinary reviewed spec/contract evolution.

## Identifier contract

Project invariant IDs:

- are required and non-empty;
- use a bounded lowercase ASCII identifier form frozen by implementation tests;
- are unique within the declaration;
- are stored in a project-specific namespace that cannot collide with or impersonate Sentrdel built-in/kernel invariant identifiers.

## Allowed invariant types

### `tenant_binding`

Required semantic fields:

- bounded resource identity;
- tenant/owner field identity;
- required actor identity class (`authenticated_user_id` or `authenticated_tenant_id` in the initial model);
- optional bounded route/method/operation scope.

The evaluator verifies only supported static path/filter/guard relationships. Unknown linking remains `UNKNOWN`, not satisfied.

### `required_role`

Required semantic fields:

- non-empty deterministic allowed/required role set;
- bounded route/action/operation scope.

A lexical role string elsewhere in source is insufficient; the R3 path model must prove a supported guard relationship.

### `protected_properties`

Required semantic fields:

- bounded resource identity;
- non-empty protected-property set;
- supported mutation operation scope.

Dynamic mutation fields remain coverage uncertainty and cannot automatically satisfy the invariant.

### `elevated_client_context`

Required semantic fields:

- bounded route/path or operation scope;
- one or more required application guard kinds;
- optional allowlisted supported server-context classes.

This invariant cannot grant permission to use credentials; it only adds a requirement when elevated authority is observed.

## Scope matching contract

Scope fields are declarative bounded match data only.

Implementation MUST define caps and deterministic normalization for:

- repository-relative path patterns;
- route patterns;
- HTTP method sets;
- resource identifiers;
- operation sets;
- field/role collections.

No scope field is interpreted by a shell, regex engine with unbounded user expressions, template engine, script runtime, or repository executable.

If glob-like syntax is admitted, its grammar must be narrow, deterministic, resource-bounded and Sentrdel-owned.

## Resource limits

Before parsing/retention, implementation MUST freeze non-zero caps for at least:

- total file bytes;
- invariant count;
- invariant ID bytes;
- route/path/resource string bytes;
- role/property count and bytes;
- methods/operations/guard count;
- nesting/collection depth if the selected parser permits nesting;
- diagnostics.

Cap exhaustion fails the project-invariant input closed and leaves built-in analysis operational.

## Validation behavior

The declaration is accepted only if every retained invariant satisfies the frozen schema and authority ceiling.

At minimum, validation rejects:

- duplicate IDs;
- unknown invariant types;
- blank required values;
- empty required sets;
- unsupported actor/guard/context/operation classes;
- absolute or escaping repository paths;
- unknown authority-bearing keys;
- executable/command/plugin fields;
- suppression/waiver/severity/risk-acceptance fields;
- oversized content or collections.

R3-T025 uses whole-document rejection: any invalid retained record rejects the project declaration and yields no project definitions. Invalid content cannot suppress built-ins.

## Unknown-key policy

R3-T025 uses fail-closed validation for unknown fields. No forward-compatible inert metadata keys are currently admitted. Any future metadata field must be explicitly allowlisted through reviewed contract evolution and remain provably incapable of affecting invariant semantics or authority.

## Evaluation contract

Project invariants use the same R3 evaluator states:

- `SATISFIED`
- `VIOLATED`
- `UNKNOWN`
- `NOT_APPLICABLE`

Rules:

- `UNKNOWN` is not satisfied;
- malformed declaration state is not a clean invariant result;
- project invariant satisfaction does not prove project-wide security;
- project invariant violation produces bounded Evidence/Coverage input to the existing reconciler, not a direct canonical Finding;
- project requirements cannot make a built-in invariant less strict.

## Built-in interaction

Built-in and project invariants are evaluated independently and combined monotonically:

- a project invariant can add a new requirement;
- a project invariant may duplicate a built-in requirement but cannot weaken it;
- project `SATISFIED` cannot cancel built-in `VIOLATED` or `UNKNOWN`;
- project parse failure cannot cancel built-in Evidence;
- an empty/missing project invariant file means only that no additional project requirement was supplied; it does not mean no authorization requirement exists.

## Evidence and persistence

Persistent project-invariant Evidence may contain only:

- invariant ID/type/scope;
- normalized non-secret requirement metadata;
- declaration location/digest;
- evaluation state and bounded supporting/contradicting observation IDs;
- explicit coverage diagnostics.

It MUST NOT persist discovered secret values or introduce unkeyed secret-value-only hashes.

R3-T025 does not itself add persistent Evidence/Coverage producer integration; that runtime-owned mapping remains R3-T026 authority.

## Determinism

Equivalent normalized declaration and repository inputs MUST produce deterministic:

- invariant ordering and identities;
- validation diagnostics;
- scope matching;
- evaluation ordering/state;
- Evidence identities and semantic output.

## Security tests required before implementation is considered complete

The implementation task must include adversarial tests proving that repository declarations cannot:

- suppress a built-in Evidence record;
- weaken a built-in violation/unknown state;
- set severity or epistemic authority;
- request network/provider credentials;
- execute commands/plugins/templates;
- escape repository paths;
- create a built-in/kernel invariant ID collision;
- cause unbounded parsing/matching;
- turn malformed/unknown configuration into a clean result.
