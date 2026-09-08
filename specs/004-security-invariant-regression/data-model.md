# Data Model: Security Invariant Regression Core

**Status:** PLANNING_MODEL  
**Authority:** Internal S1 design target. Existing canonical schema/R3 contracts remain authoritative until implementation freezes concrete Rust types.

## Design rules

- Pair order is explicit: trusted base first, candidate second.
- IDs are deterministic, domain-separated, bounded, and based on canonical identities rather than display text.
- Exact stable identity is the primary matching key.
- Before/after state, Coverage, Evidence references, and provenance remain separately addressable.
- Uncertainty is represented explicitly and cannot be normalized into clean output.
- Comparison records are not canonical Findings and cannot upgrade epistemic authority.

## `RevisionIdentity`

Conceptual fields:

```text
role: TRUSTED_BASE | CANDIDATE
repository_identity: canonical local repository identity when available
commit_id: exact immutable commit identity when available
root_tree_id: exact immutable tree identity when available
snapshot_input_digest: deterministic bounded digest of normalized comparison inputs
fixture_identity: test-only optional identity
```

Rules:

- production comparison requires immutable local identity sufficient to prevent mutable-ref drift;
- fixture identity is allowed only in test/benchmark mode;
- branch/ref/PR names are display metadata only;
- candidate identity does not grant trust or execution authority.

## `RevisionPair`

```text
contract_version
pair_id
trusted_base: RevisionIdentity
candidate: RevisionIdentity
```

`pair_id` is domain-separated over contract version + exact ordered base/candidate identity. Reversing the pair changes the ID.

## `SemanticSnapshot`

Conceptual composition:

```text
revision: RevisionIdentity
snapshot_contract_version
producer_contracts[]
configuration_identity[]
invariant_definitions[]
invariant_evaluations[]
coverage_records[]
evidence_refs[]
graph_projection_or_digest
resource_state
```

A snapshot should compose existing canonical records rather than duplicate public schemas. Compatibility validation happens before comparison.

## `ProducerContractIdentity`

Needed only for producer dimensions material to comparison:

```text
producer_id
producer_version
configuration_digest
capability_scope
schema_or_contract_version
```

Missing/incompatible identity yields fail-visible comparison uncertainty. An unversioned producer cannot silently be treated as semantically identical across revisions.

## `InvariantDefinitionIdentity`

```text
invariant_id: StableSemanticId
definition_digest
kind
source
scope_digest
requirement_digest
```

The stable ID is necessary but not sufficient when the definition behind it changes. `definition_digest` is a deterministic Sentrdel-owned digest of normalized semantics, not source formatting.

## `PairPresence`

```text
MATCHED
BASE_ONLY
CANDIDATE_ONLY
```

Presence is separate from security disposition. An absent side may mean true semantic absence or merely missing coverage; Coverage decides what can be concluded.

## `ContinuityBasis`

```text
EXACT_STABLE_ID
PROVEN_DETERMINISTIC_CONTINUITY
UNMATCHED
```

`PROVEN_DETERMINISTIC_CONTINUITY` is reserved for an existing or separately frozen Sentrdel-owned witness. Planning authorizes no heuristic/fuzzy matcher.

Movement is represented through changed provenance under matched continuity, not as a security verdict.

## `CoveragePair`

Conceptual fields:

```text
comparison_key
base_state
candidate_state
base_reason
candidate_reason
base_input_digests[]
candidate_input_digests[]
compatibility
```

The comparison key derives from stable capability/scope/producer/provider-dimension semantics. Exact existing Coverage states are preserved.

## `SecurityDeltaDisposition`

```text
REGRESSION
IMPROVEMENT
UNCHANGED
UNKNOWN
COVERAGE_LOST
COVERAGE_GAINED
```

The disposition is a pairwise summary, not an epistemic upgrade. Every record retains the underlying states and reason.

## `SecurityDeltaReason`

The implementation should freeze machine-stable reason codes. Planned families include:

```text
INVARIANT_STATE_WEAKENED
INVARIANT_STATE_IMPROVED
INVARIANT_STATE_UNCHANGED
CANDIDATE_COVERAGE_DEGRADED
CANDIDATE_COVERAGE_GAINED
PRODUCER_DISAPPEARED
SNAPSHOT_INCOMPATIBLE
INVARIANT_DEFINITION_CONFLICT
INVARIANT_REQUIREMENT_REMOVED
SEMANTIC_OBJECT_ADDED
SEMANTIC_OBJECT_REMOVED
SEMANTIC_CONTINUITY_UNPROVEN
MOVE_ONLY_CONTINUITY
RESOURCE_CAP_REACHED
```

Exact names may be refined before implementation but must remain deterministic and semantically narrow.

## `SecurityRegressionRecord`

Conceptual fields:

```text
regression_id
pair_id
pair_presence
continuity_basis
base_invariant_id?
candidate_invariant_id?
base_definition_digest?
candidate_definition_digest?
base_evaluation_state?
candidate_evaluation_state?
disposition
reason_code
coverage_pairs[]
base_supporting_evidence_refs[]
candidate_supporting_evidence_refs[]
base_provenance[]
candidate_provenance[]
graph_diff_context?
diagnostics[]
resource_state
```

Rules:

- `regression_id` is deterministic and domain-separated;
- collections are bounded, normalized, deduplicated, and sorted;
- base and candidate evidence/provenance are never merged in a way that erases side identity;
- graph context carries no independent verdict authority;
- this is not a canonical Finding.

## Pairwise invariant-state matrix

The comparator must preserve coverage and definition compatibility before applying state transitions.

| Base state | Candidate state | Disposition | Conditions |
|---|---|---|---|
| SATISFIED | VIOLATED | REGRESSION | compatible definition + sufficient comparison coverage |
| VIOLATED | SATISFIED | IMPROVEMENT | compatible definition + sufficient candidate proof |
| SATISFIED | SATISFIED | UNCHANGED | no material candidate coverage degradation |
| VIOLATED | VIOLATED | UNCHANGED | no material candidate coverage degradation |
| SATISFIED | UNKNOWN | COVERAGE_LOST or UNKNOWN | COVERAGE_LOST when candidate visibility degraded |
| VIOLATED | UNKNOWN | COVERAGE_LOST or UNKNOWN | never IMPROVEMENT |
| UNKNOWN | SATISFIED | COVERAGE_GAINED or UNKNOWN | candidate supported; base could not prove prior state |
| UNKNOWN | VIOLATED | COVERAGE_GAINED or UNKNOWN | candidate supported; base could not prove prior state |
| any | incompatible | UNKNOWN | no semantic coercion |

`NOT_APPLICABLE` requires scope/presence reasoning. It is not globally ordered above or below the other states.

## Added/removed definition semantics

### Base-only invariant definition

If the base contains a valid tightening requirement and candidate project-invariant coverage proves its removal, record `INVARIANT_REQUIREMENT_REMOVED`. Do not call the disappearance mitigation. Any stronger policy/Finding consequence remains outside S1 authority.

If candidate project-invariant coverage is incomplete, disposition is `COVERAGE_LOST`/`UNKNOWN`.

### Candidate-only invariant definition

Record addition only when base coverage proves the relevant definition space was analyzed. Otherwise preserve uncertainty. An added requirement can be security tightening context but does not retroactively prove a base vulnerability.

## Semantic object continuity

- same stable ID, same semantic definition, moved provenance: matched/unchanged unless invariant state or Coverage changes;
- same stable ID, changed mutable graph metadata: matched; graph modification is context only;
- same stable ID, incompatible invariant definition: conflict/unknown;
- different stable IDs with similar names/locations/graph neighborhoods: unmatched unless deterministic continuity witness exists;
- removed object: improvement requires candidate proof of semantic absence and continued applicable requirement/coverage;
- added object: regression requires enough base coverage to establish a meaningful before state/absence.

## Resource limits

Concrete implementation limits must reuse/derive from existing bounded R3/review/graph limits and measured benchmark evidence. Planned categories:

```text
max_snapshot_invariants
max_snapshot_evaluations
max_snapshot_coverage_records
max_graph_nodes
max_graph_edges
max_pair_results
max_evidence_refs_per_result
max_provenance_refs_per_result
max_diagnostics
max_total_input_bytes
```

All must be non-zero, validated, and fail visible. Planning intentionally does not invent numeric values without implementation/benchmark evidence.
