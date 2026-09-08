# Contract: Trusted-Base / Candidate Revision Pair

**Status:** PLANNING_CONTRACT  
**Scope:** S1 local deterministic identity/snapshot boundary.

## Purpose

Prevent a regression verdict from being detached from the exact semantic states it compares. S1 MUST know which immutable state is the trusted base, which is the candidate, and whether their snapshots are semantically comparable before any security disposition is computed.

## Allowed inputs

S1 may consume:

- exact locally validated commit/tree identities;
- canonical Sentrdel semantic records already produced for those identities;
- bounded local repository metadata required to prove identity;
- synthetic fixture identities only in test/benchmark mode.

## Forbidden inputs/actions

S1 MUST NOT:

- infer trust from a branch name, PR number, tag display label, timestamp, author, or forge status;
- fetch network remotes or call forge APIs to discover the base/candidate;
- execute target code, builds, package managers, tests, hooks, migrations, provider tools, credential helpers, external Git filters/textconv/diff helpers, or repository instructions;
- receive provider/forge credentials merely to compare two snapshots;
- treat model/external-engine output as revision identity authority.

## Exact role contract

```text
RevisionPair {
  contract_version,
  trusted_base,
  candidate,
  pair_id
}
```

- `trusted_base` and `candidate` roles are explicit and ordered.
- A reversed pair is a distinct comparison.
- `pair_id` is deterministic and domain-separated over the contract version and exact ordered identities.
- Display metadata may accompany a revision but cannot replace immutable identity.

## Production identity requirements

A production revision identity MUST bind enough immutable local Git/repository state to prevent mutable-ref drift. The preferred identity is exact commit SHA plus root tree SHA when available through the validated local boundary.

If the comparison input is not a Git revision, a future separately specified identity contract is required. S1 planning does not silently generalize to arbitrary remote archives or workspaces.

## Fixture identity requirements

Synthetic fixtures MAY use a deterministic test-only identity namespace. Test identities:

- must be visibly non-production;
- must be deterministic;
- cannot establish a trusted production base;
- cannot bypass snapshot compatibility checks.

## Snapshot compatibility

Before semantic comparison, S1 MUST validate all producer/configuration dimensions material to the requested invariant/Coverage comparison.

Compatibility requires, as applicable:

- matching snapshot contract version;
- compatible canonical schema contract;
- identifiable producer/version;
- compatible configuration/capability scope;
- explicit Coverage for missing/unsupported dimensions;
- bounded valid record identities/provenance.

If compatibility is unknown or false, the affected comparison is `UNKNOWN`/unavailable. S1 MUST NOT normalize across incompatible producers simply because output field names look similar.

## Baseline/candidate mutation rule

Comparison treats both semantic snapshots as immutable inputs. Candidate analysis cannot rewrite base records, provenance, Coverage, producer identity, or evidence chains.

## Identity failure behavior

The following fail visible and do not produce a clean regression result:

- missing exact base identity;
- missing exact candidate identity;
- base and candidate accidentally identical where the caller claimed otherwise;
- invalid or malformed revision identity;
- snapshot bound to a different revision than its declared role;
- producer/configuration incompatibility;
- duplicate stable record identity;
- resource-cap exhaustion during validation.

## Authority ceiling

Revision identity proves only which local states are compared. It does not prove security, runtime behavior, author intent, trustworthiness of the candidate, forge approval, deployment state, or Finding truth.
