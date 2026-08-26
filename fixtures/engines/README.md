# T029 external-engine adversarial fixtures

These fixtures are synthetic and deterministic. They contain no credentials or third-party data.

Static native-result fixtures:

- `native-valid-minimal.json` — one valid Sentrdel-native Evidence claim.
- `native-valid-multiple.json` — multiple valid claims.
- `native-empty.json` — valid empty result set.
- `native-malformed.json` — truncated JSON that must never become Evidence.
- `native-out-of-root.json` — parent-traversal location that must fail closed.
- `native-unsupported-schema.json` — unsupported native schema version.

`crates/sentrdel-engine/tests/t029_adversarial.rs` also runs the integration-test binary as a qualified external-engine fixture for bounded flood, timeout, non-zero exit, missing executable, and environment-scrubbing cases. The environment test seeds only synthetic canary values into an outer launcher and proves the actual engine child cannot observe cloud, model-provider, signing, or SSH credential variable names unless explicitly allowlisted.

T029 does not create CoverageRecords; T030 owns termination-to-coverage mapping.
