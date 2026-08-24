# Quickstart — Sentrdel v0.1 Evidence + Guard Foundation

This is the planned R1 user/developer flow. Commands are implementation contracts, not claims that code already exists.

## User flow 1 — Initialize a project

```bash
sentrdel init
```

Expected shape:

```text
Sentrdel initialized.

Detected
  Languages       TypeScript
  Ecosystem       npm
  CI              GitHub Actions
  Provider        Supabase
  MCP             2 configurations

Coverage
  Native changed-code review      available
  Dependency advisory review      available/offline-cache dependent
  Supabase detection              covered
  Supabase static posture         NOT IMPLEMENTED (R2)
  Supabase business logic         NOT IMPLEMENTED (R3)

Provider detection is not a security verdict.
```

## User flow 2 — Review AI-generated changes

After any agent/developer changes code:

```bash
sentrdel review
```

Example target UX:

```text
BLOCK — fix before merging

1. Someone using your application may reach a dangerous command with untrusted input.
   Where: src/api/export.ts:41
   Evidence: structural observation + changed-code reachability
   Proof: Corroborated inference, not runtime verified

Coverage gaps
   Supabase provider detected; RLS/Auth/Storage static posture is not available in R1.
```

Technical details:

```bash
sentrdel explain <finding-id>
```

JSON/CI:

```bash
sentrdel review --json > sentrdel-review.json
```

Expected exit codes:

- 0 no active blocking decision;
- 1 blocking security decision;
- 2 usage/config error;
- 3 incomplete/undecidable analysis where success/block would misrepresent coverage;
- 4 internal/integrity failure.

## User flow 3 — bounded stdio MCP guard

R1 supports only stdio MCP through Sentrdel's bounded gateway. Remote/Streamable HTTP MCP is intentionally deferred.

```bash
sentrdel guard mcp -- <upstream-mcp-command> [args...]
```

Target behavior:

```text
Transport: STDIO
Protocol: explicitly negotiated supported version
MCP tool: github.create_pull_request
Policy: ASK
Fidelity: ENFORCED
Reason: repository write through the controlled stdio gateway
```

Kernel-invariant denial:

```text
MCP tool: filesystem.write
Target: outside approved workspace
Policy: DENY
Fidelity: ENFORCED
Reason: SENTRDEL-KERNEL-WORKSPACE-BOUNDARY
```

The denial cannot be downgraded by repo config, tool output, later plugin or LLM. Oversized/unterminated frames and unsupported protocol versions fail closed under configured policy.

## User flow 4 — Git hook assistance

```bash
sentrdel guard install-git-hooks
```

Sentrdel reports:

```text
Fidelity: PARTIAL
Local git hooks can be bypassed; use CI enforcement for a team merge gate.
```

## User flow 5 — Offline/local-first operation

```bash
sentrdel review --no-network
```

Native producers still run. Network-dependent capabilities use local cache/fixtures or emit explicit coverage gaps. No LLM is required.

## User flow 6 — Optional reasoner

```bash
sentrdel review --reason
```

Reasoner output remains INFERENCE/HYPOTHESIS and cannot become authoritative FACT/VERIFIED, suppression or policy authority.

## User flow 7 — ASEL integrity check

R1 exposes the computed session head and verifies the available chain:

```bash
sentrdel evidence verify --session <session-id>
```

Target shape:

```text
Events: 42
Chain valid: yes
Computed head: sha256:...
Trusted checkpoint: not supplied

The available chain is internally consistent. Without a trusted external head/signature,
this does not independently prove that the entire local history was not replaced or truncated.
```

## Developer bootstrap target

Implementation is pinned to Rust 1.98.0:

```bash
rustup show
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Security/release gates additionally include `cargo-audit`, `cargo-deny`, dependency/source qualification and lockfile/toolchain checks.

## Contract acceptance sequence

Before detector breadth:

1. canonical Evidence/ASEL schemas compile and round-trip;
2. SQLite persistence preserves immutable IDs and secret-redaction/value-hash prohibition;
3. ASEL chain/head verification reports its trust limits honestly;
4. kernel DENY cannot be downgraded;
5. Regorus pathological input fails bounded/fail-closed;
6. external engines receive scrubbed/allowlisted environments;
7. missing producer creates a coverage gap;
8. native review works offline on hostile-repo fixtures without executing target helpers/tools;
9. bounded stdio MCP gateway survives malformed/oversized/unsupported-version inputs and records a complete chain;
10. `init` detects Supabase but reports static posture/business logic as not covered;
11. plain-language output remains backed by the same canonical Finding/Evidence objects;
12. optional reasoner cannot escalate epistemic authority.