# SentrdelBench Fixture Conventions

This directory is the repository-visible fixture root for SentrdelBench Core.

T088 defines conventions only. T089 implements the executable harness and machine-readable run record. T090 implements the physical public/development/protected-holdout split and protected-label handling.

## 1. Fixture classes

Every benchmark case belongs to exactly one declared class:

- `PUBLIC_REGRESSION`
- `DEVELOPMENT_EVALUATION`
- `PROTECTED_HOLDOUT`

Until T090 implements the physical layout, contributors MUST NOT infer class from directory location alone. The future corpus manifest is authoritative.

Protected-holdout expected outputs MUST NOT be added to ordinary public fixtures merely to make a candidate pass.

## 2. Case identity

Each case requires a stable, repository-independent identifier.

Case IDs MUST:

- be unique within the corpus revision;
- use bounded ASCII text;
- remain stable when files are relocated without semantic fixture change;
- avoid absolute paths, usernames, machine names, timestamps, random values, and temporary-directory names.

Renaming a case ID is a corpus revision change.

## 3. Case contents

A benchmark case may contain:

- repository/diff fixture input;
- a fixture manifest;
- expected Findings or benchmark-local expected finding IDs;
- expected Evidence/provenance obligations;
- expected Coverage dimensions/gaps;
- authority-contract assertions;
- replay expectations;
- workload-size metadata for performance evaluation.

Expected outputs MUST remain separate from candidate-produced output.

Fixture source text, issue/PR-like text, logs, MCP content, engine output, and model text are untrusted data. Their contents MUST NOT be interpreted as instructions to the evaluator.

## 4. Ground-truth rules

Ground truth MUST be reviewable and deterministic.

Expected records MUST NOT depend on:

- absolute workstation paths;
- wall-clock timestamps unless time itself is the tested semantic input;
- non-deterministic iteration order;
- random IDs;
- ambient environment variables;
- live network responses;
- real credentials or production secrets.

A clean case explicitly declares no expected in-scope finding for the capability set being evaluated. Absence of an expected finding is not enough if the capability itself is out of scope or expected to be unavailable; coverage expectations must make that distinction explicit.

## 5. Matching

The evaluator owns the frozen deterministic matching rule for one run.

Fixtures SHOULD prefer canonical Sentrdel identities when the implementing feature exposes them. Before those identities exist, benchmark-local expected IDs MAY be used, but the mapping must remain stable for the corpus revision.

One emitted result cannot satisfy multiple expected results unless the frozen evaluator contract explicitly models a one-to-many semantic relationship. Duplicate emitted matches MUST NOT inflate true-positive counts.

## 6. Severity

If a metric gates a severity subset, the expected fixture declares the expected severity or severity class. Candidate/model prose MUST NOT redefine the gated severity after evaluation begins.

Changes to expected severity are ground-truth changes and require a new corpus revision.

## 7. Coverage expectations

Every case SHOULD declare which producer/capability dimensions are expected to run and which gaps are intentionally expected.

Coverage expectations distinguish:

- completed/available analysis;
- partial analysis;
- unavailable/unsupported capability;
- failure;
- timeout;
- explicit skip;
- missing coverage record.

A missing or failed producer is never encoded as a clean expected security result.

## 8. Provenance expectations

Where a case expects an emitted security claim to be evidence-backed, the case SHOULD declare the required evidence/provenance relationship rather than merely the final message text.

Provenance checks validate traceability and reference integrity. They do not grant a stronger epistemic class.

## 9. Deterministic replay

Cases intended for replay MUST be self-contained for base qualification.

Replay fixtures MUST NOT require live network access, package-manager execution, target builds, external credentials, or mutable remote state unless a later specification explicitly creates a qualified isolated tier.

Expected semantic machine output excludes only runtime metadata explicitly allowed by the evaluation contract. Fixtures MUST NOT mark semantic fields as ignorable merely to hide nondeterminism.

## 10. Performance fixtures

A performance-capable case SHOULD declare the workload-size measure needed by the active metric policy, for example changed LOC.

Performance comparisons require measurement metadata from the T089/T079 machinery. A fixture alone cannot claim a latency target was met.

## 11. Guard fixtures

Guard false-block/decision-latency fields are reserved by T088. Until the guard benchmark exists, review benchmark cases MUST NOT synthesize zero false-block or zero-latency results.

Future guard cases must distinguish expected `ALLOW`, `ASK`, `DENY`, and `UNDECIDABLE` semantics and preserve framing/resource expectations separately from downstream tool behavior.

## 12. Safety

Fixtures MUST use synthetic or explicitly permitted data.

Do not add:

- real API keys, tokens, signing keys, SSH material, database passwords, or cloud credentials;
- PHI or production user data;
- instructions that require exploitation of third-party/production systems;
- test steps that execute target package managers/build scripts during ordinary analysis qualification;
- hidden dependencies on developer machine state.

Secret-detection fixtures use synthetic canaries whose plaintext is safe to publish and whose expected persisted outputs remain redacted according to the product contract.

## 13. Corpus revision

Any change that alters evaluated meaning requires a corpus revision change, including:

- adding/removing a case;
- changing input semantics;
- changing expected Findings/Evidence/Coverage;
- changing expected severity;
- changing matching identity;
- changing authority assertions.

Pure documentation/formatting changes that do not alter evaluated bytes or expected semantics MAY preserve the revision if the future corpus manifest/digest remains unchanged.

## 14. T090 reserved layout

T090 will establish the auditable physical or equivalent logical separation for:

```text
tests/benchmark/
  public-regression/
  development-evaluation/
  protected-holdout/   # expected outputs are not available to candidate-generation logic
```

This sketch is a convention, not authorization to commit protected labels to the public repository. T090 must choose an implementation that actually preserves the protected-output boundary.
