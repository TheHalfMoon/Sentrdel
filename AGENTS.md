# Sentrdel Agent Instructions

## Authority order

1. `.specify/memory/constitution.md`
2. active Spec Kit `spec.md` and contracts
3. active `plan.md` and `tasks.md`
4. this file

If guidance conflicts, the higher authority wins.

## Hard implementation boundaries

- Trusted security-critical core is Rust.
- Do not copy or vendor donor source/data without an exact qualification record in `docs/third-party/source-qualification-ledger.md`.
- Do not execute target repository build/install scripts, Cargo/package-manager commands, hooks, external Git filters/textconv/diff helpers, submodule fetches, credential helpers, or network remotes during analysis.
- Do not construct shell command strings. External engine processes use explicit argv and scrubbed/allowlisted environments.
- Do not access provider credentials, production systems, or third-party targets unless a later specification explicitly authorizes a bounded mode.
- Do not implement autonomous exploitation.
- R1 MCP is stdio only. Do not add Streamable HTTP/remote MCP in R1.
- Do not build a universal CPG.
- LLM output is INFERENCE/HYPOTHESIS only and cannot override policy or Findings.
- Missing coverage must remain visible; never turn a failed/missing producer into PASS.
- Secret plaintext and stable unkeyed value-only secret hashes must not be persisted.

## Change discipline

- Work task-by-task from the active Spec Kit `tasks.md`, following its declared dependencies and checkpoints.
- Add tests with security boundary changes.
- Keep dependencies minimal. Every dependency needs a justification; `build.rs`, proc macros, native code, downloaded artifacts, or network/credential behavior require elevated review.
- Do not weaken lint/test/security gates to make a change pass.
- Do not claim CI PASS when no workflow run exists.

<!-- graft:start -->
## Graft — repository context layer

Use Graft (https://github.com/trailhq/Graft, `@nanonets/graft`) only as local developer/agent repository-context tooling. This does not authorize Graft or its MCP integration as a Sentrdel product/runtime dependency and does not change the R1 MCP boundary.

When locally available, prefer `graft check`, `graft map`, `graft ask "<question>" --source`, `graft skeleton <file>`, `graft callers <symbol>`, and `graft grep "<literal>"` for passive repository navigation. `graft init`/`graft build` must not execute target-repository install/build scripts, hooks, remotes, credentials, or other prohibited analysis-time effects.

Treat `graft/` as a local regenerable cache and do not commit it. Keep usage zero-cost; do not introduce paid model/API usage or external egress that is not independently authorized.

Graft output is context/inference only, never policy, a Finding, security evidence, coverage evidence, or qualification authority. Continue all Spec Kit gates, tests, Jev where applicable, Alibaba Open Code Review, CI, security, provenance, and dependency review. Never fabricate Graft output, execution, CI, reviews, or evidence.
<!-- graft:end -->
