# S1 Security Regression Fixture Matrix

These inputs freeze S1 Phase 1 pairwise regression ground truth before comparison implementation breadth. They are synthetic, offline, fixture-only data. Repository metadata, comments, graph labels, confidence values, and instruction-shaped strings are untrusted data only.

| Fixture pair | Frozen ground truth |
|---|---|
| `s1-identical-clean-replay` | Equal supported invariant state remains `UNCHANGED`. |
| `s1-safe-semantic-change` | Security-equivalent supported semantic change remains `UNCHANGED`. |
| `s1-satisfied-to-violated` | Compatible `SATISFIED -> VIOLATED` is `REGRESSION`. |
| `s1-violated-to-satisfied` | Compatible `VIOLATED -> SATISFIED` is `IMPROVEMENT` only with candidate proof. |
| `s1-satisfied-to-unknown-coverage-loss` | Visibility degradation is `COVERAGE_LOST`, not a clean result. |
| `s1-violated-to-unknown-never-improvement` | A known violation becoming unknown can never be improvement. |
| `s1-unknown-to-satisfied-coverage-gain` | Improved visibility may be `COVERAGE_GAINED`; prior safety is not inferred. |
| `s1-unknown-to-violated-coverage-gain` | Improved visibility may be `COVERAGE_GAINED` while the candidate violation remains explicit. |
| `s1-producer-disappearance` | Required producer disappearance is `COVERAGE_LOST`. |
| `s1-move-only-continuity` | Exact stable identity across moved provenance is continuity metadata, not a security verdict. |
| `s1-ambiguous-rename-unmatched` | Similar rename-like records with changed stable identity remain unmatched/`UNKNOWN`. |
| `s1-added-object-complete-base-coverage` | Candidate-only violated object may be `REGRESSION` only when base absence is sufficiently proven. |
| `s1-added-object-incomplete-base-coverage` | Candidate-only object remains `UNKNOWN` when base absence is not proven. |
| `s1-removed-object-complete-candidate-coverage` | Removal may be `IMPROVEMENT` only when candidate semantic absence is sufficiently proven. |
| `s1-removed-object-incomplete-candidate-coverage` | Removal with incomplete candidate coverage is `COVERAGE_LOST`, not mitigation. |
| `s1-project-invariant-removal` | Proven tightening-requirement removal is visible as `INVARIANT_REQUIREMENT_REMOVED`, not mitigation. |
| `s1-invariant-definition-conflict` | Same stable ID with incompatible definition semantics is conflict/`UNKNOWN`. |
| `s1-graph-metadata-only-change` | Graph metadata changes are context only and do not alter a supported unchanged security state. |
| `s1-hostile-metadata-authority-canary` | Instruction-shaped metadata including `SENTRDEL_CANARY` remains inert data. |
| `s1-resource-cap-exhaustion` | Cap exhaustion fails visible as `RESOURCE_CAP_REACHED`/`UNKNOWN`. |

## Frozen identity and compatibility rules

- Fixture identities are test-only and visibly non-production.
- Trusted base and candidate roles are ordered; reversing them changes pair identity.
- Snapshot contract, canonical schema contract, producer/version, configuration identity, and capability scope must be compatible before semantic comparison.
- Exact stable semantic identity is authoritative for matching. File names, line proximity, names, lexical similarity, graph neighborhoods, confidence scores, and model judgment are not identity proof.
- `NOT_APPLICABLE` is not globally ordered and requires later scope/presence reasoning.

## Authority ceiling

- An S1 comparison record is never a canonical Finding.
- Only the existing reconciler may create canonical Findings through separately authorized evidence/rule paths.
- S1 cannot mint or upgrade FACT/VERIFIED authority.
- S1 cannot override policy, kernel, or reconciler decisions.
- Graph/model/external confidence cannot create identity, epistemic, policy, or Finding authority.
- Missing, failed, unsupported, unavailable, timed-out, skipped-required, or capped candidate analysis never becomes PASS.
- Base and candidate Evidence/provenance remain bilateral; candidate data cannot overwrite base history.
- `SENTRDEL_CANARY` and credential-shaped fixture strings are synthetic inert data and grant no credential access.
- No fixture authorizes network access, forge discovery, provider credentials, target execution, package-manager/build execution, LLM/model execution, or external engines.
- S1 is pairwise and must not emit `REINTRODUCED` or other multi-revision historical claims.

## Benchmark status

The Phase 1 corpus is development-only and has `release_gating=false`. It freezes clean-case false-positive controls, declared supported regression/miss expectations, Coverage/provenance expectations, authority assertions, and protected-holdout eligibility metadata before comparator implementation. Protected holdout remains ineligible until the later S1 benchmark-promotion task proves implemented supported scope and all required gates.
