# Development-Assurance Source Mining for Sentrdel — 2026-09-16

**Status:** RESEARCH / DEVELOPMENT-PROCESS REFERENCE ONLY  
**Product implementation authority:** NONE  
**Runtime dependency admission:** NONE  

## Purpose

The founder's GitHub universe contains several projects whose best value to Sentrdel is not product-code reuse. Their strongest contribution is **how Sentrdel itself is planned, changed, verified, and closed**.

These sources must remain subordinate to Sentrdel's Constitution, active Spec Kit, and protected-main governance. They are not a second lifecycle authority.

## 1. Diffcipline — proof-before-done

Repository:

```text
TheHalfMoon/Diffcipline
```

High-value principles observed:

- repository truth over agent self-report;
- exact diff and changed-surface inspection;
- expected/forbidden path policy;
- explicit risk profiles;
- configured verification that remains `NOT RUN` unless actually executed;
- deterministic `PASS / REVIEW / FAIL` rather than an opaque model score;
- machine-readable evidence;
- immutable release identity/checksum/Sigstore provenance;
- negative benchmark evidence is retained instead of rerun away.

The most important transferable rule is:

```text
required check not executed successfully
  -> cannot claim PASS
```

Sentrdel fit:

- exact-head task closeout discipline;
- source-intake qualification closeout;
- future verification/conformance receipts;
- preventing agents from converting intended tests into claimed evidence;
- development-side changed-surface guards for high-risk Sentrdel core changes.

Disposition:

```text
DEVELOPMENT_ASSURANCE_REFERENCE
NO_RUNTIME_DEPENDENCY
```

Sentrdel already has its own canonical CI/governance. Reuse should be selective: proof-contract ideas, risk/evidence semantics, and possibly test fixtures—not a second mandatory gate engine unless a later measured need is proven.

## 2. SpecGrain — bounded independent work units

Repository:

```text
TheHalfMoon/SpecGrain
```

High-value principles observed:

- recursively refine work until a leaf is independently understandable and verifiable;
- evidence over executor self-report;
- WorkPacket identity separate from execution-attempt occurrence identity;
- deterministic readiness before promotion;
- explicit scope, acceptance, recovery, context budget, change surface, evidence and safety declarations;
- independent verification binds current spec revision, packet digest, execution-result digest, implementation revision, observed changed paths, acceptance checks and evidence checks;
- append-oriented hash-chained evidence;
- evidence forks fail closed;
- ambiguous recovery state is preserved for investigation rather than guessed.

Sentrdel fit:

- future large source-admission programs should be decomposed into exact-path qualification grains;
- dynamic verification profiles should use bounded task packets rather than large agent missions;
- source-reuse work should separate `execution attempt` from `verification evidence`;
- large roadmap packages SM-1..SM-7 should still become small dependency-ordered Spec Kit units before implementation.

Disposition:

```text
PLANNING_AND_DELIVERY_REFERENCE
NO_PRODUCT_RUNTIME_ADOPTION
```

Sentrdel remains Spec-Kit-governed unless separately changed. SpecGrain is a methodology/source reference, not permission to replace the active governance system.

## 3. HarnessMind — evidence semantics and standards restraint

Repository:

```text
TheHalfMoon/HarnessMind
```

High-value principles observed:

- runtime evidence before commodity static diagnostics;
- predicates are type/lifecycle constrained so unsupported claims become unrepresentable;
- distinct absence states rather than treating lack of observation as absence;
- component identity separated from occurrence/load identity;
- stable IDs/content hashes/provenance with deterministic serialization;
- evidence graphs are projections, not truth;
- observed/correlated/ablation-supported/replicated evidence levels;
- paired trials bind environment, agent/model versions, harness hashes, repository commit and verifier;
- raw outcomes retained;
- proposer/judge separation;
- avoid rebuilding standards where mature ones exist.

HarnessMind's cancellation decisions are especially useful to Sentrdel architecture:

- use standardized agent trajectory formats such as ATIF where justified instead of inventing another trajectory format;
- use OpenTelemetry semantic conventions where justified instead of inventing a telemetry protocol;
- delegate sandbox execution to qualified sandbox providers rather than building a bespoke universal sandbox;
- consume mature static-lint machine-readable results rather than rebuilding a broad commodity rule library.

Sentrdel fit:

- future runtime evidence/agent-security profile semantics;
- distinguishing observed event from causal/security conclusion;
- external agent execution receipts;
- standards-first Operational Evidence Bridge;
- experimental validation of new semantic producers before they are treated as durable product value.

Disposition:

```text
EVIDENCE_SEMANTICS_AND_STANDARDS_REFERENCE
NO_RUNTIME_DEPENDENCY
```

## 4. Combined development-assurance rule set

These projects reinforce a useful build discipline for Sentrdel:

```text
Plan small.
Bind exact revision and change surface.
Execute only explicitly authorized checks/actions.
Keep executor output separate from verifier authority.
Record incomplete/blocked/not-run states explicitly.
Preserve negative evidence.
Use independent verification before closure.
Prefer standards over proprietary duplicate formats.
Do not turn a graph, model, agent, or executor into truth authority.
```

## 5. Relationship to product source mining

This document complements:

```text
docs/third-party/cross-repository-source-mining-2026-09-16.md
```

Product/source priority remains Golam/Kodac/Ascout/OpenCTI and existing Sentrdel-qualified Graphify/Tree-sitter surfaces. Diffcipline, SpecGrain, and HarnessMind primarily improve **how those future changes are bounded and proven**, not the Sentrdel runtime architecture itself.
