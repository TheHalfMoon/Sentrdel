# Contract: Security Invariant Regression Semantics

**Status:** PLANNING_CONTRACT  
**Scope:** S1 deterministic pairwise comparison semantics and authority.

## Inputs

A comparison may consume only validated compatible S1 revision/snapshot records and existing canonical semantics, including:

- R3 `InvariantDefinition`;
- R3 `InvariantEvaluation` and its `SATISFIED`, `VIOLATED`, `UNKNOWN`, `NOT_APPLICABLE` state;
- canonical Coverage records;
- bounded canonical Evidence/provenance references;
- existing `sentrdel-graph` stable-ID projection/diff context.

## Output authority

S1 produces deterministic **comparison records**, not canonical Findings.

A comparison record:

- cannot create or waive a Finding;
- cannot lower or raise policy/kernel authority by itself;
- cannot convert graph confidence, model confidence, external severity, benchmark score, or source reputation into FACT/VERIFIED authority;
- cannot claim runtime exploitability or hosted/live provider state;
- cannot treat missing data as PASS;
- preserves the authority ceiling and uncertainty of the inputs it compares.

Only the existing reconciler may create canonical Findings under separately authorized evidence/rule paths.

## Matching contract

### Exact invariant match

An invariant is `MATCHED` only when:

1. stable invariant identity matches; and
2. normalized definition semantics are compatible.

Definition compatibility includes kind, source authority, scope, and requirements. One stable ID with incompatible semantics is `INVARIANT_DEFINITION_CONFLICT`, not a valid match.

### Semantic object match

Existing exact stable semantic identity is authoritative. Source movement may change provenance without changing identity.

The following are insufficient identity proof:

- same file name;
- same line number or nearby lines;
- similar symbol/route/resource text;
- edit distance;
- graph neighborhood similarity;
- confidence score;
- model judgment.

### Rename/move

- move with exact stable identity: matched continuity metadata;
- rename changing stable identity: unmatched unless an existing/separately frozen deterministic continuity witness proves identity;
- `MOVED` is not a security disposition.

## Coverage compatibility contract

Coverage is paired by stable capability/scope/producer/provider-dimension semantics. Existing exact states remain visible.

Candidate coverage degradation that removes required proof is `COVERAGE_LOST`. Examples include:

- `COVERED -> PARTIAL`;
- `COVERED -> UNSUPPORTED`;
- `COVERED -> UNAVAILABLE`;
- `COVERED -> FAILED`;
- `COVERED -> TIMED_OUT`;
- `COVERED -> SKIPPED_BY_POLICY` when the comparison requires the skipped capability;
- required producer disappearance;
- unsupported/dynamic semantics replacing previously supported semantics;
- cap exhaustion preventing the required candidate observation.

A base gap becoming sufficiently covered in the candidate may be `COVERAGE_GAINED`.

## Invariant transition contract

All rules assume compatible invariant definitions and sufficient applicable comparison coverage unless stated otherwise.

| Base | Candidate | Required S1 behavior |
|---|---|---|
| SATISFIED | VIOLATED | `REGRESSION` |
| VIOLATED | SATISFIED | `IMPROVEMENT` only with sufficient candidate proof |
| SATISFIED | SATISFIED | `UNCHANGED` unless material Coverage loss |
| VIOLATED | VIOLATED | `UNCHANGED` unless material Coverage loss |
| SATISFIED | UNKNOWN | `COVERAGE_LOST` when visibility degraded, else `UNKNOWN` |
| VIOLATED | UNKNOWN | never improvement; `COVERAGE_LOST` or `UNKNOWN` |
| UNKNOWN | SATISFIED | `COVERAGE_GAINED` when visibility improved, else `UNKNOWN` |
| UNKNOWN | VIOLATED | `COVERAGE_GAINED` when visibility improved, else `UNKNOWN`; candidate violation remains explicit |
| any | incompatible definition/snapshot | `UNKNOWN` |

`NOT_APPLICABLE` is resolved through scope/presence semantics. It is not globally ordered as safer or less safe.

## Presence contract

### Candidate-only semantic object

Do not label its state as a newly introduced security regression unless base scope/Coverage proves meaningful absence or a compatible base state. Otherwise preserve `UNKNOWN`/coverage context.

### Base-only semantic object

Do not label removal as mitigation unless candidate scope/Coverage proves semantic absence and the security requirement remains applicable/authoritative.

### Removed project invariant

A valid base tightening-only invariant disappearing from the candidate remains visible as requirement removal when candidate project-invariant coverage proves deletion. It is not mitigation merely because no candidate evaluation exists.

## No historical inference

S1 is pairwise. It MUST NOT emit `REINTRODUCED` or any other state requiring more than the trusted-base/candidate pair. Historical classification requires a later contract with explicit revision history.

## Determinism contract

For equivalent normalized inputs, the comparator MUST produce identical:

- pair identity;
- matching/presence/continuity decisions;
- dispositions and reason codes;
- result IDs;
- result ordering;
- Coverage ordering;
- evidence/provenance reference ordering;
- bounded graph-context ordering;
- diagnostics and resource-cap state.

Input iteration order must not affect semantic output.

## Resource and failure contract

The comparator uses bounded keyed matching and hard validated limits. It MUST NOT perform unbounded fuzzy all-pairs matching.

Any malformed record, duplicate conflicting identity, incompatible definition, invalid provenance reference, or cap exhaustion fails visible. Failure cannot be represented as an empty clean comparison.

## Public-interface boundary

This contract is internal S1 semantics. It does not freeze public CLI wording, JSON schema, exit codes, GitHub checks, annotations, or forge behavior. Those belong to S2/S3 and must consume S1 semantics without changing them.
