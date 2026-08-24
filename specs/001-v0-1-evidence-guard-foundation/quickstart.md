# Quickstart — Sentrdel v0.1 Evidence + Guard Foundation

This is the planned R1 user/developer flow. Commands are contracts for implementation, not claims that code already exists.

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
  Supabase deep security pack     NOT IMPLEMENTED (R3)

No provider detection is treated as a security verdict.
```

## User flow 2 — Review AI-generated changes

After Cursor/Codex/Claude/another agent changes code:

```bash
sentrdel review
```

Example target UX:

```text
BLOCK — fix before merging

1. Someone using your application may reach a dangerous command with untrusted input.
   Where: src/api/export.ts:41
   Evidence: structural rule + changed-code reachability
   Proof: Corroborated pattern, not runtime verified

Coverage gaps
   Supabase provider detected; deep RLS/Auth/Storage checks are not available in this release.
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

## User flow 3 — MCP guard

Run Sentrdel as the MCP security gateway between an agent and an upstream MCP server using the implementation-defined upstream configuration:

```bash
sentrdel guard mcp ...
```

Target behavior:

```text
MCP tool: github.create_pull_request
Policy: ASK
Fidelity: ENFORCED
Reason: repository write through a controlled MCP gateway
```

Kernel-invariant denial:

```text
MCP tool: filesystem.write
Target: outside approved workspace
Policy: DENY
Fidelity: ENFORCED
Reason: SENTRDEL-KERNEL-WORKSPACE-BOUNDARY
```

The denial cannot be downgraded by repository config, tool output, later plugin, or LLM.

## User flow 4 — Git hook assistance

```bash
sentrdel guard install-git-hooks
```

Sentrdel must explicitly report:

```text
Fidelity: PARTIAL
Local git hooks can be bypassed; use CI enforcement for a team merge gate.
```

## User flow 5 — Offline/local-first operation

```bash
sentrdel review --no-network
```

Native producers still run. Network-dependent capabilities use local cache/fixtures or emit coverage gaps. No LLM is required.

## User flow 6 — Optional reasoner

```bash
sentrdel review --reason
```

Reasoner output can add explanations/hypotheses but must visibly remain unverified unless deterministic/runtime evidence supports it.

## Developer bootstrap target

Once implementation starts:

```bash
rustup show
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Security/release gates will additionally include the repository's frozen `cargo-deny`/advisory policy after dependency setup.

## Contract acceptance sequence

Before any detector breadth is added, implementation should prove in this order:

1. canonical Evidence/ASEL schemas compile and round-trip;
2. SQLite persistence preserves immutable IDs and redaction;
3. ASEL chain tampering is detected;
4. kernel-invariant DENY cannot be downgraded;
5. missing external producer creates coverage gap;
6. native review works offline on a fixture diff;
7. MCP gateway enforcement records a complete event chain;
8. `init` detects Supabase but reports deep provider security as not covered;
9. plain-language output remains backed by the same canonical Finding/Evidence objects;
10. optional reasoner cannot escalate its epistemic authority.
