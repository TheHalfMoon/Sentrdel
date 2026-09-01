# Contract: Business-Logic Substrate R3

**Version:** 1  
**Authority:** R3 cross-layer analysis contract under the Sentrdel Constitution and canonical R1/R2 Evidence/Coverage/reconciler contracts.

## Purpose

This contract defines what R3 may read, derive, correlate, emit and claim. It does not grant target execution, live provider access, provider credentials, Finding authority, policy authority, secret authority, runtime exploitability authority, or universal-CPG authority.

## Allowed base inputs

R3 may consume only bounded, validated forms of:

- canonical repository-relative source/config files admitted by explicit R3 adapters;
- R1 ProjectProfile, diff/view and structural-analysis metadata;
- canonical R2 Supabase static-posture/key-authority Evidence/Coverage;
- canonical graph records and bounded graph context;
- optional SCIP artifacts only through the existing qualified bounded ingestion contract;
- optional project invariant declarations only through the separately frozen tightening-only contract;
- Sentrdel-owned fixture and benchmark metadata.

## Forbidden base inputs/actions

Ordinary R3 analysis MUST NOT:

- execute target application code, route handlers, tests, hooks or scripts;
- execute target package-manager/build/install commands;
- execute SQL, migrations, database clients, Supabase CLI or provider tooling;
- connect to hosted Supabase/provider APIs or target databases;
- require provider-admin or production credentials;
- invoke repository-controlled executable helpers or plugins;
- run browser automation or production probing;
- autonomously exploit, mutate or remediate target code;
- load repository-provided structural rules or executable invariant content;
- create canonical Findings outside the existing reconciler.

## Resource bounds

Every R3 reader/parser/adapter/correlator MUST enforce explicit non-zero caps appropriate to its surface, including where applicable:

- files and total bytes;
- document bytes;
- structural rules/pattern bytes/matches;
- routes/handlers/callbacks/middleware links;
- actor/guard/value-origin/data-operation records;
- derivation depth and fan-in;
- graph nodes/edges and semantic links;
- path depth and candidate paths;
- invariant count/fields/pattern bytes;
- diagnostics and emitted observations.

Cap exhaustion MUST produce failed/partial coverage for the affected scope and MUST NOT become a clean invariant evaluation.

## Adapter contract

Each framework/data adapter MUST declare:

- exact syntax/framework family it recognizes;
- route/data/identity/guard semantics it may emit;
- unsupported or dynamic constructs that lower coverage;
- deterministic stable identity/provenance rules;
- resource caps;
- test fixtures for positive, negative, ambiguous and malformed cases.

Initial intended adapter families are bounded Express, Next.js App Router/Pages API, supported Supabase Edge Function patterns, and a bounded Supabase JavaScript data-operation subset. Planning does not claim every variation is supported.

## TypeScript contract

TypeScript source support requiring a new grammar/dependency is not admitted merely because R3 targets `.ts` conventions. No TypeScript grammar may enter the build or trusted parser path until the explicit dependency-qualification task is canonical and passes source/privileged-dependency/Self Security review.

If qualification is absent, the implementation MUST report narrower language coverage rather than silently parse unsupported TypeScript as proven semantics.

## Actor and identity contract

Allowed actor/value observations include supported forms of:

- authenticated user/tenant/role identity from an explicitly supported adapter;
- request path/query/body/header-controlled values;
- constants;
- bounded supported derivations.

Static recognition of an authentication API call does not prove a valid runtime user/token. Lexical name equality does not prove identity equivalence.

An actor/object/tenant relationship is usable for invariant satisfaction only when a supported bounded derivation/link establishes it.

## Guard contract

R3 MUST preserve distinct guard kinds for at least:

- authentication;
- required role/function authorization;
- tenant/ownership/object membership;
- protected-property allowlisting/filtering;
- elevated-client application authorization;
- tightening-only project invariant requirements.

A guard can satisfy an invariant path only when the bounded adapter/correlation model proves the required scope/dominance/link. A matching check elsewhere in a file is insufficient.

Unsupported dynamic middleware or helper semantics result in UNKNOWN/partial coverage.

## Data-operation contract

The initial Supabase JavaScript operation subset may observe bounded forms of:

- resource/relation selection;
- reads/selects;
- inserts;
- updates;
- upserts;
- deletes;
- bounded RPC invocation identity;
- explicitly supported filters;
- explicit selected/mutated fields;
- broad request-controlled mutation objects where structurally proven.

R3 does not claim arbitrary query equivalence, SQL semantics, execution, result cardinality, hosted data state or runtime reachability.

## R2 correlation contract

R3 may reference canonical R2 Evidence/Coverage for supported static properties such as:

- RLS/policy posture;
- grants;
- provider key/client authority;
- server/client/static context;
- Storage/Auth/Edge static posture.

R3 MUST preserve the original R2 Evidence identity and static-vs-live limitation. It MUST NOT rewrite R2 Evidence or claim hosted state.

RLS/policy posture and application authorization remain independent controls. Elevated service-role/secret authority MUST be represented as capable of bypassing ordinary RLS semantics where supported; elevated authority alone is not automatically a violation.

## Graph and link contract

R3 MUST reuse the existing canonical thin `sentrdel-graph` substrate and its stable identity/provenance rules.

R3 MUST NOT:

- introduce a second canonical graph runtime;
- claim universal CPG coverage;
- allow graph confidence to mint FACT/VERIFIED authority;
- treat fuzzy/ambiguous links as proven identity.

Every cross-layer link records a bounded basis such as same-handler structure, supported callback/import linkage, validated SCIP reference or explicit adapter linkage. Ambiguous links reduce path/invariant coverage.

## SCIP contract

SCIP is optional semantic evidence. Only artifacts admitted through the existing bounded SCIP ingestion and producer-qualification contract may be used.

Missing, malformed, unqualified, unsupported or incomplete SCIP data MUST NOT become a clean result. When semantic linkage is necessary to decide an invariant and cannot be safely proven, the evaluation remains UNKNOWN/partial.

## Path correlation contract

A cross-layer path is an ordered bounded relationship among supported route, actor/guard, value, data-operation, provider-client and R2 observations.

Path correlation MUST be:

- deterministic;
- provenance-backed;
- bounded in nodes/edges/depth/count;
- explicit about extracted/inferred/ambiguous link basis;
- fail-visible on cap exhaustion or unresolved semantics.

A partially supported path cannot be represented as fully covered merely because another path or layer is covered.

## Invariant evaluation contract

Initial evaluator state is:

- `SATISFIED`
- `VIOLATED`
- `UNKNOWN`
- `NOT_APPLICABLE`

`UNKNOWN` is not secure and cannot be aggregated as `SATISFIED`.

Initial built-in families are:

1. tenant/object binding;
2. privileged function/role authorization;
3. protected-property mutation;
4. elevated provider-client application authorization.

Project-declared invariants, if present, use the separate project-invariant contract and may tighten only.

## Evidence contract

R3 Evidence MUST:

- use canonical R1 schemas and runtime-owned producer authority;
- preserve exact bounded source/R2/graph provenance where applicable;
- separate direct observations from cross-layer security interpretation;
- use stable normalized non-secret subjects/correlation identities;
- contain no secret plaintext or stable unkeyed secret-value-only digest;
- remain inside the producer's epistemic authority;
- avoid runtime/live/exploitability wording unless supplied by a separately authorized stronger producer.

R3 producer code MUST NOT construct canonical Findings directly.

## Coverage contract

R3 MUST expose enough independent coverage to identify at least:

- route/framework extraction;
- actor identity;
- guard extraction;
- value-origin derivation;
- data operations;
- local/inter-file semantic linking;
- R2 provider correlation;
- project-invariant parsing/evaluation where applicable;
- invariant evaluation;
- aggregate canonical `CROSS_LAYER_BUSINESS_LOGIC` / pack `BUSINESS_LOGIC` state.

Unsupported/partial required areas cannot be erased by an aggregate PASS or empty Finding set.

## Project declaration authority contract

Repository project declarations are untrusted configuration. They MAY add explicit requirements within the separate bounded invariant schema. They MUST NOT:

- suppress Evidence or Findings;
- define ignore/waiver/accepted-risk behavior;
- lower severity or confidence;
- broaden process/network/provider/secret/credential authority;
- override policy or kernel decisions;
- change reconciler-only Finding authority;
- declare FACT/VERIFIED status;
- change benchmark expected outputs or release gates;
- execute code/plugins/scripts/templates.

Malformed declarations cannot disable built-in analysis.

## Determinism contract

Equivalent normalized repository/R2/optional semantic-index/invariant inputs MUST produce deterministic:

- route/actor/guard/value/data identities;
- semantic link/path identities and ordering;
- invariant ordering/evaluation;
- Evidence identities and semantic output;
- coverage aggregation;

except for runtime metadata already explicitly excluded by canonical serialization contracts.

## Benchmark and promotion contract

A candidate R3 release-gating check/invariant becomes qualified only after:

1. frozen positive/negative/unknown/adversarial fixtures exist;
2. expected Evidence/Coverage and supported scope are declared before qualification;
3. deterministic replay passes;
4. known-ground-truth misses meet the active threshold for the declared scope;
5. clean-case false-positive threshold passes;
6. coverage and provenance completeness gates pass;
7. authority assertions and no-execution/no-network canaries pass;
8. applicable latency/resource gates pass;
9. protected-holdout rules apply where required;
10. exact-head repository CI and dependency/source governance pass.

Detection breadth or recall improvement cannot compensate for an authority violation, hidden coverage gap, material FP regression or resource-bound failure.

## Non-claims

This contract does not claim:

- compiler-complete JavaScript/TypeScript semantics;
- arbitrary middleware/control-flow resolution;
- runtime route reachability;
- actual user/token validity;
- production database/provider state;
- actual cross-tenant access or exploitability;
- complete framework/ORM/auth-library coverage;
- live provider posture;
- universal CPG construction;
- automatic remediation or safe-fix verification.
