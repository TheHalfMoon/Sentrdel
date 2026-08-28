# SentrdelBench Core Evaluation Contract

**Status:** R1_BINDING_EVALUATION_CONTRACT  
**Task:** T088  
**Applies to:** Sentrdel v0.1 Evidence + Guard Foundation  
**Authority:** Constitution Principle VIII, Implementation Amendment 002, `plan.md`, and `tasks.md`

## 1. Purpose

SentrdelBench Core is the minimum immutable evaluation boundary used to measure security quality before detector breadth grows. It exists to prevent rule count, model confidence, or a single aggregate score from replacing explicit evidence about precision, misses, false positives, coverage, provenance, determinism, latency, resource use, and authority correctness.

T088 defines the contract only. T089 implements the first executable harness and machine-readable run record. T090 implements physical corpus-class separation and protected-holdout handling. T077 later expands this core into the release benchmark.

SentrdelBench is an evaluation plane. It does not create canonical Findings, alter policy authority, promote candidate artifacts, or grant protected expected outputs to candidate-generation logic.

## 2. Normative language

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

A benchmark result is **qualified** only when the evaluator can prove the required run identity, corpus identity, expected-output identity for the evaluated subset, and applicable metric inputs. Missing inputs produce explicit `NOT_APPLICABLE`, `NOT_MEASURED`, or evaluation failure states; they MUST NOT silently become zero, perfect, or clean results.

## 3. Immutable run boundary

For one evaluation run, these inputs are immutable:

1. evaluator identity: implementation version plus content digest;
2. metric-contract identity: version/digest of this contract or its machine representation;
3. corpus revision and corpus class;
4. expected outputs/ground truth for the evaluated subset;
5. baseline identity, when a baseline comparison is requested;
6. candidate identity;
7. resource/latency measurement policy;
8. authority/contract assertions used by the evaluator.

Candidate-generation or research logic MUST NOT mutate any of these inputs during the run. A mutation, identity mismatch, unreadable expected-output source, or post-start corpus change invalidates the run rather than producing a partial PASS.

The future T089 run record MUST identify these immutable inputs explicitly. Machine metadata that describes the measurement host MAY be runtime metadata and is not itself an evaluator authority source.

## 4. Corpus classes

The evaluation model recognizes three corpus classes:

- **PUBLIC_REGRESSION** — fixtures and expected outputs intended for ordinary deterministic regression testing and public inspection.
- **DEVELOPMENT_EVALUATION** — evaluation cases that may be used during candidate development and comparison but remain distinct from basic regression fixtures.
- **PROTECTED_HOLDOUT** — promotion-gate cases whose expected outputs are not supplied to candidate-generation logic.

T088 defines the semantics. T090 owns the concrete repository/storage layout, protected-label access rules, and promotion mechanics.

A result MUST name its corpus class. Results from different corpus classes MUST NOT be merged in a way that hides which class produced them.

## 5. Evaluation unit and matching

The default review evaluation unit is one benchmark case representing a bounded repository/diff input plus its declared expected outputs.

Expected security outcomes MUST use stable benchmark identifiers. Evaluator matching MUST be deterministic and SHOULD prefer canonical Finding/evidence identities once those are available. Until the relevant user-story implementation exists, a fixture MAY use a benchmark-local expected identifier, but the identifier MUST be stable within the corpus revision and MUST NOT depend on absolute workstation paths, timestamps, random IDs, or output ordering.

For finding-oriented metrics:

- **true positive (TP):** one expected finding matched by one emitted finding according to the evaluator's frozen matching rule;
- **false negative (FN):** an expected finding with no valid emitted match;
- **false positive (FP):** an emitted in-scope finding with no valid expected match;
- duplicate emitted matches for one expected finding MUST NOT inflate TP; duplicates are either ignored after the first deterministic match or counted as FP according to the frozen evaluator rule;
- severity used for a gated subset comes from the expected-output contract and the canonical emitted record, never from model prose.

Matching rules are evaluator inputs and therefore immutable during one run.

## 6. Required metric dimensions

No single scalar score is canonical truth. Every run reports explicit dimensions independently.

### 6.1 High-severity precision

For R1 review evaluation, the high-severity set is canonical `BLOCK` and `HIGH` unless a later binding contract explicitly changes the set before the run starts.

A high-severity match is counted as `TP_high` only when an expected `BLOCK`/`HIGH` finding is matched and the emitted canonical Finding is also `BLOCK`/`HIGH`. An expected high-severity finding that is unmatched, or matched only by an emitted `MEDIUM`/`LOW`/`INFO` Finding, remains a high-severity miss for this dimension. An emitted `BLOCK`/`HIGH` Finding with no valid high-severity expected match is `FP_high`.

The evaluator MUST therefore report at least:

- `high_severity_expected`;
- `high_severity_true_positive`;
- `high_severity_false_negative`;
- `high_severity_false_positive`;
- `severity_mismatch_count`.

`high_severity_precision = TP_high / (TP_high + FP_high)`

The run MUST record the integer numerator and denominator components. If no high-severity finding was emitted, precision is `NOT_APPLICABLE`; it MUST NOT be represented as `1.0` merely because the denominator is zero. Lowering severity cannot convert a known high-severity miss into a high-severity true positive or silently improve the metric.

### 6.2 Known-ground-truth recall and miss rate

For expected in-scope findings:

`known_ground_truth_recall = TP / (TP + FN)`

`known_ground_truth_miss_rate = FN / (TP + FN)`

If the evaluated subset contains no declared expected positives, both are `NOT_APPLICABLE`. A clean-only corpus cannot prove recall.

### 6.3 Clean-PR false positives

A **clean case** is a case whose frozen expected-output contract declares no in-scope security finding for the evaluated capability set.

The evaluator MUST report at least:

- `clean_cases_evaluated`;
- `clean_cases_with_false_positive`;
- `clean_case_false_positive_rate = clean_cases_with_false_positive / clean_cases_evaluated`;
- `false_positive_findings_on_clean_cases`.

A future release gate may use a concrete threshold such as T078; T088 does not invent that threshold.

### 6.4 Coverage completeness and gaps

Coverage is not inferred from the absence of findings.

For every producer/capability dimension declared by a benchmark case, the evaluator MUST classify the observed coverage outcome using the canonical coverage semantics when available. At minimum the report must distinguish completed/available analysis from partial, unavailable, failed, skipped, timed-out, unsupported, or otherwise explicit gap states.

The evaluator MUST report counts for:

- expected coverage dimensions;
- completed dimensions;
- gap dimensions;
- unexpected/missing coverage records.

A coverage gap MUST NOT be counted as a clean security result.

### 6.5 Evidence provenance completeness

For each emitted finding/evidence item that the case requires to be provenance-backed, the evaluator verifies the required provenance references are present, syntactically valid, and resolve to the expected in-run evidence objects where resolution is applicable.

The report MUST include:

- provenance-required objects;
- provenance-complete objects;
- provenance-incomplete objects;
- dangling/invalid provenance references.

`provenance_completeness = complete / required`

When no object in the subset requires provenance, the ratio is `NOT_APPLICABLE` rather than perfect by default.

Provenance completeness measures traceability, not truth. It MUST NOT upgrade an epistemic class.

### 6.6 Deterministic replay

The evaluator MUST support replay comparison of the same immutable case/candidate/evaluator inputs.

Deterministic equality applies to canonical machine output after explicitly excluded runtime metadata is removed. Exclusions MAY include timing samples, measurement-host metadata, and observation timestamps only when the relevant contract declares them runtime metadata. Findings, Evidence identities, coverage state, policy decisions, ordering, stable diagnostics, and other semantic output MUST NOT be excluded merely to make replay pass.

The report MUST distinguish:

- `REPLAY_EQUAL`;
- `REPLAY_DIFFERENT`;
- `REPLAY_NOT_MEASURED`.

A replay difference MUST retain or identify the differing canonical fields; a hash-only mismatch without diagnosable field context is insufficient for qualification.

### 6.7 Review latency and resource usage

The contract reserves explicit fields for review performance. T079 later freezes release-grade latency gating.

When measured, the run MUST identify:

- cold/warm measurement mode;
- changed LOC or another frozen workload-size measure;
- sample count;
- elapsed-time statistic(s), including the percentile used for a gate;
- peak or bounded memory measurement where available;
- machine/OS/architecture metadata required to interpret the sample;
- whether external engine/downstream/network time is included.

Performance values without measurement-policy and machine metadata are `UNQUALIFIED_MEASUREMENT` and cannot support a release claim.

### 6.8 Guard false blocks and guard latency

The core reserves these dimensions before guard implementation exists:

- allowed actions incorrectly blocked/ASKed by the controlled seam;
- expected DENY actions incorrectly allowed;
- guard decision latency excluding downstream tool execution, human approval wait, and framing wait when the active guard contract excludes them;
- bounded framing/resource failures.

Until guard benchmark cases exist, these dimensions are `NOT_MEASURED`; they MUST NOT appear as zero false blocks or zero latency.

### 6.9 Explanation and authority-contract correctness

The evaluator MUST support boolean/count assertions for security authority contracts, including as applicable:

- LLM/reasoner output did not mint FACT/VERIFIED authority;
- only the reconciler created canonical Findings;
- kernel DENY was not weakened;
- coverage gaps were not represented as clean posture;
- explanation/presentation did not mutate canonical severity, proof, or workflow state;
- protected expected outputs were not exposed to candidate-generation logic;
- untrusted context did not become privileged instruction.

An authority-contract violation is reported independently of precision/recall. A candidate with strong detection metrics but a violated authority invariant is not a qualified security improvement.

## 7. Metric state model

Every metric field has an explicit state. At minimum:

- `MEASURED` — numerator/denominator or samples are valid;
- `NOT_APPLICABLE` — the frozen subset has no denominator/applicable subject;
- `NOT_MEASURED` — the capability or instrumentation is intentionally absent from this run;
- `UNQUALIFIED_MEASUREMENT` — a value exists but required measurement metadata is absent;
- `EVALUATION_ERROR` — required evaluator/corpus/expected-output/authority inputs were invalid or inconsistent.

`NOT_APPLICABLE`, `NOT_MEASURED`, and `EVALUATION_ERROR` MUST NOT be coerced to zero or PASS.

## 8. Comparison semantics

Baseline/candidate comparison is dimension-by-dimension. The evaluator MUST preserve raw metric components and states for both sides.

A comparison MAY classify each dimension as improved, unchanged, regressed, newly measured, no longer measured, or incomparable. It MUST NOT collapse security quality into a weighted opaque score.

Promotion/release logic uses explicit thresholds and Pareto-aware judgment. A precision gain MUST NOT erase a new authority violation, hidden coverage gap, severe recall regression, or unbounded resource failure.

## 9. Fixture truth and safety rules

Benchmark fixtures are test data, not runtime authority.

Fixtures MUST:

- be deterministic and bounded;
- use synthetic or explicitly permitted data;
- contain no real credentials, PHI, or production secrets;
- avoid requiring network access for base qualification;
- avoid target package-manager/build execution unless a later specification explicitly authorizes an isolated verification tier;
- declare expected outcomes separately from candidate output;
- preserve explicit coverage expectations, including expected gaps;
- use repository-relative logical paths in expected machine output;
- avoid workstation-specific absolute paths, timestamps, random values, and environment-dependent identities in ground truth.

Malicious/hostile fixture content remains untrusted data and MUST NOT become instructions to the evaluator or product under test.

## 10. Run validity and failure

A run is invalid if any of the following occurs:

- evaluator identity changes after start;
- metric definitions change after start;
- corpus or expected-output revision changes after start;
- candidate-generation logic can read protected expected outputs for a protected-holdout run;
- required expected-output material is missing or malformed;
- semantic output is silently excluded from replay equality;
- a metric with no denominator is reported as perfect/zero rather than explicit state;
- coverage absence is treated as clean posture;
- authority-contract failure is hidden by aggregate scoring.

Invalid runs fail qualification. They do not produce an authoritative PASS/FAIL product verdict.

## 11. Machine-readable T089 obligations

T089's executable run record MUST be able to represent, without loss:

- evaluator version/digest;
- metric-contract version/digest;
- corpus class/revision and evaluated case IDs;
- expected-output revision/digest for the evaluated subset;
- baseline and candidate identities;
- metric states plus raw numerator/denominator/sample components;
- high-severity expected/TP/FN/FP and severity-mismatch components;
- coverage/provenance components;
- deterministic replay status and semantic-difference references;
- authority-contract assertion results;
- measurement policy and machine metadata when performance is measured;
- diagnostics/evaluation errors.

T088 intentionally does not prescribe a serialization implementation or Rust type layout; T089 owns that implementation while preserving this information model.

## 12. T090 protected-holdout obligations

T090 MUST make the corpus-class distinction enforceable in repository/test layout or an equivalently auditable boundary. Public/base tests MUST NOT require private holdout data. Candidate-generation logic MUST NOT receive protected expected outputs. Holdout results are promotion evidence, not a tuning oracle.

## 13. Non-claims

T088 does not claim:

- that a benchmark proves absence of vulnerabilities;
- that coverage gaps are secure outcomes;
- that public fixtures predict all real repositories;
- that provenance completeness proves semantic correctness;
- that deterministic replay proves security correctness;
- that latency measured on one machine generalizes universally;
- that SentrdelBench is a production self-learning system;
- that any candidate may self-promote because benchmark metrics improved.

## 14. Change control

Changes to metric meaning, denominator rules, matching semantics, immutable run inputs, corpus-class authority, or replay exclusions change the evaluator contract and require ordinary reviewed Spec Kit/repository changes.

A candidate being evaluated MUST NOT modify the evaluator/contract or protected expected outputs used to judge that same candidate.
