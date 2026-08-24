# Third-Party Source and Data Policy

Sentrdel Core is Apache-2.0. This does not automatically authorize copying any donor source, rule set, dataset, template, grammar, benchmark, or generated artifact.

Before `COPIED_SOURCE` or `COPIED_DATA` enters the repository, record:

- upstream repository/project;
- exact commit/tag/artifact digest;
- exact files/data;
- license expression and required notices;
- embedded/transitive licensing concerns;
- maintenance/security status;
- intended integration mode and trust boundary;
- modifications;
- tests proving the adopted behavior/provenance.

Prefer, in order:

1. native dependency with a compatible license and narrow feature set;
2. stable protocol/process integration;
3. independent implementation of general concepts/algorithms;
4. copied/vendored source only when the benefit clearly outweighs maintenance/provenance cost.

Copyleft/restricted components do not link into the permissive trusted core unless a future explicit legal/architecture decision establishes a compatible boundary. Optional external processes remain subject to their own licenses and distribution rules.
