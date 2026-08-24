# Sentrdel

**Open-source security system for software development.**

Sentrdel is being designed as a Rust-first, local-first, vendor-neutral security layer for the full software lifecycle: AI coding agents, source changes, dependencies, identity, data, infrastructure, CI/CD, deployment, and runtime.

## North Star

A developer should be able to build with Codex, Cursor, Claude Code, JetBrains/Junie, Windsurf, Copilot, or another coding agent and rely on Sentrdel as the independent security judgment and guardrail plane between generated change and merge/deploy.

High-severity security claims must carry explicit evidence and proof status. Sentrdel must distinguish facts, deterministic inferences, hypotheses, runtime observations, contradictions, and independently verified results rather than treating scanner or LLM output as equivalent truth.

## Founder constraints

- Rust is the primary implementation language for the trusted core.
- The core remains open source, local-first, and vendor-neutral.
- Sentrdel secures the project from A to Z, including provider-aware security for systems such as Supabase and other backend, identity, cloud, deployment, CI/CD, payment, database, and agent/MCP stacks.
- LLMs may reason and propose hypotheses, but are never the sole security oracle.
- Missing analysis capability is a coverage gap, never evidence that the project is clean.
- Pre-execution enforcement must distinguish truly enforced seams from advisory visibility.
- Verification is bounded, opt-in test execution in isolation; it is not autonomous exploitation.
- Mature OSS engines should be reused behind explicit, versioned evidence boundaries when appropriate.
- False-positive rate and guard false-block rate are release-quality metrics.
- Planning and implementation are governed by Spec Kit artifacts in `.specify/` and `specs/`.

## Status

Architecture and Spec Kit planning are in progress. No implementation claims should be inferred from this README.
