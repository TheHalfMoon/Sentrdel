# Protected Holdout Boundary

This directory contains repository-visible metadata only. Protected benchmark cases, labels, expected Findings/Evidence/Coverage, and case-level qualification diagnostics are not committed to this repository.

For T090:

- protected case material and expected outputs are `EXTERNAL_ONLY`;
- ordinary/base CI MUST NOT require private holdout bytes;
- candidate-generation logic MUST NOT receive protected expected outputs;
- the independent holdout evaluator may receive a frozen candidate identity plus evaluator/metric-contract identity and a read-only protected corpus/expected-output source;
- qualification returns an aggregate promotion receipt bound to candidate/evaluator/contract/corpus/expected-output identities, not the private labels themselves;
- missing private material means the holdout was not run; it is never interpreted as a passing holdout result.

A holdout case may become public regression data only through deliberate declassification after the qualification cycle. Declassification requires new public corpus/expected-output revisions, retirement of that case from protected qualification, and replacement holdout capacity before the disclosed case can no longer function as an unseen promotion gate.

Base tests enforce that this committed directory contains only `.gitignore`, `README.md`, and `manifest.json`.
