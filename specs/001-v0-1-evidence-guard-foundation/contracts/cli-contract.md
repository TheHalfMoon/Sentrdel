# Contract — Sentrdel v0.1 CLI

**Status:** BINDING_FOR_R1_IMPLEMENTATION

## Commands

### `sentrdel init`

Purpose: initialize safe local Sentrdel metadata/configuration and detect project stack/provider signals without executing target build/install scripts.

Required output:

- repository identity/root;
- detected languages/ecosystems;
- CI/MCP/provider/framework signals;
- security pack availability/coverage state;
- warnings for unsupported/partial domains.

Must support machine-readable JSON output.

### `sentrdel review`

Purpose: review a selected git change and return findings + coverage.

Minimum selection modes:

- current working-tree/staged state;
- explicit base ref/commit when supplied.

R1 MUST NOT execute target repository hooks or build/install scripts.

Human output order:

1. merge/action decision;
2. plain-language findings;
3. proof/evidence chips;
4. coverage gaps;
5. optional technical detail.

Machine output contains canonical finding/evidence references and coverage records.

### `sentrdel explain <finding-id>`

Purpose: render an existing finding from the local store.

Required layers:

1. novice impact statement: actor + capability + object;
2. security narrative + minimal remediation direction;
3. full evidence/provenance/coverage references.

This command MUST NOT alter finding state.

### `sentrdel guard mcp`

Purpose: run an MCP gateway with pre-invocation Sentrdel policy and ASEL capture.

Required:

- explicit upstream server configuration;
- inventory of observed server/tools and metadata digests;
- ALLOW/ASK/DENY/UNDECIDABLE behavior;
- `ENFORCED` fidelity for calls that truly pass through the gateway;
- safe handling of tool descriptions/results as untrusted content;
- event-chain head emitted on clean shutdown/session summary.

### `sentrdel guard install-git-hooks`

Purpose: install Sentrdel-managed pre-commit/pre-push hook integration where supported.

Required:

- never overwrite an unrelated existing hook without explicit safe composition/approval;
- report that local git hooks are `PARTIAL`/bypassable, not universal enforcement;
- provide uninstall/restore metadata.

## Global flags

R1 should support, where applicable:

- `--json`
- `--no-network`
- `--config <path>` only for user-approved config paths; repository config remains bounded/monotonic
- `--reason` explicit optional LLM reasoning
- `--verbose` diagnostics without leaking secret plaintext

Exact flag names MAY evolve during implementation if contract tests and docs are updated before release.

## Exit Codes

Numeric codes are frozen for R1:

- `0` — command completed and no active blocking security decision applies.
- `1` — command completed and a blocking security/policy decision applies.
- `2` — usage or invalid configuration.
- `3` — analysis incomplete/undecidable under command policy (for example required producer failure) where returning 0/1 would misrepresent coverage.
- `4` — unexpected internal failure/integrity failure.

Commands MAY provide more granular machine-readable reason codes inside JSON, but process exit semantics remain stable.

## Output guarantees

### Human mode

- Never require CWE/CVSS knowledge to understand the primary action.
- Blocking findings use plain language first.
- Proof status is explicit: e.g. `Observed`, `Corroborated`, `Unconfirmed`, `Contested`, later `Proven by test`.
- Coverage gaps are visible near the summary; they are not hidden in verbose logs.

### JSON mode

Top-level envelope:

```text
{
  schema_version,
  command,
  repository,
  decision,
  findings[],
  coverage[],
  diagnostics[],
  timing,
  store_refs?
}
```

JSON output MUST be stable enough for CI integration and contract-tested.

## Network behavior

Base `init` and native review work offline.

Any advisory lookup or LLM provider requiring network must:

- be explicit in config/command behavior;
- respect `--no-network`;
- produce coverage state when unavailable;
- never silently upload full repository content.

## Determinism

Given identical repository contents, config, producer versions and offline fixtures, native review JSON MUST be deterministic except documented runtime metadata such as duration/timestamp. Content/finding fingerprints MUST not depend on wall-clock time or absolute local paths.
