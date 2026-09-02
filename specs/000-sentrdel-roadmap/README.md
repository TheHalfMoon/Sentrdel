# Sentrdel Roadmap Navigation and Authority Index

**Purpose:** Make the roadmap corpus easy to read without confusing strategic direction with implementation authority.

This file is navigation only. It does not override the Constitution, an active Spec Kit, or canonical task ordering.

## Required reading order

For any continuation that needs roadmap context, read in this order:

1. `.specify/memory/constitution.md`
2. the currently active Spec Kit `spec.md`, contracts, `plan.md`, and `tasks.md`
3. `specs/000-sentrdel-roadmap/roadmap.md`
4. `specs/000-sentrdel-roadmap/improvement-plan-2026-08-26.md`
5. `specs/000-sentrdel-roadmap/strategic-amendment-2026-09-02-semantic-security-graph.md`
6. `specs/000-sentrdel-roadmap/competitive-triangulation-2026-09-02.md`
7. `specs/000-sentrdel-roadmap/post-r3-execution-blueprint-2026-09-02.md`

If any lower document conflicts with a higher authority, the lower document must change.

## Current implementation boundary

At the time this index was authored, the active implementation authority is R3:

`specs/003-business-logic-invariants/`

The strategic documents in this directory **must not** reorder, widen, or bypass the canonical R3 task ledger.

In particular, the post-R3 blueprint is not permission to start R5, R6, R7, R9, or any other successor work before R3 has canonical closeout, post-merge CI, and live repository-governance proof.

## Strategic thesis

The current roadmap refinement is intentionally narrower than "build an open-source AppSec platform clone."

The product thesis is:

> **Sentrdel is the open-source security-invariant regression and evidence judgment engine for AI-built software.**

The **Sentrdel Semantic Security Graph (SSG)** is the bounded reasoning substrate, not the product category by itself.

The core product question is:

> **What security property did this change weaken, what evidence proves it, what analysis is missing, and what stronger claim—if any—was separately verified?**

## What Sentrdel should own

Sentrdel should own the security judgment layer that is difficult to make both deterministic and open:

- canonical Evidence and Coverage contracts;
- stable semantic identities and provenance;
- bounded route / actor / auth / guard / data / provider-authority relationships;
- security invariants;
- trusted-base versus candidate invariant regression;
- explicit coverage regression;
- reconciler-only Finding authority;
- bounded verification evidence upgrades;
- conformance and benchmark contracts;
- local-first developer judgment and forge/agent delivery through stable protocols.

## What Sentrdel should normally reuse or import

Sentrdel should prefer qualified mature infrastructure for capabilities that do not materially improve its invariant/evidence moat:

- generic SAST engines;
- SCA/SBOM generation;
- vulnerability/advisory databases;
- secret scanners;
- IaC scanners;
- package intelligence;
- DAST/runtime engines;
- code indexing/parsing infrastructure;
- forge/IDE integration primitives.

External output remains untrusted evidence and never becomes canonical judgment merely because the upstream tool reports severity, confidence, reachability, or exploitability.

## Post-R3 bounded sequence

The current preferred strategic decomposition after canonical R3 closeout is:

1. Security Invariant Regression Core;
2. local Security Regression Developer Contract;
3. GitHub/forge delivery using the same local judgment protocol;
4. Open Regression Conformance;
5. bounded verification for selected high-value invariants;
6. External Evidence Import Protocol;
7. semantic provider/framework expansion by invariant leverage;
8. dependency/build action guard at genuinely controllable seams;
9. runtime evidence correlation;
10. mature SSG-backed project posture;
11. controlled open-intelligence/research learning flywheel.

Each numbered item is a roadmap decomposition only. Each requires its own future Spec Kit lifecycle and dependency proof before implementation.

## First proof-of-category demos

Before broad feature expansion, the project should prove four end-to-end cases:

1. tenant-isolation regression;
2. elevated provider-authority regression;
3. protected-property mutation regression;
4. coverage regression where a previously provable security property becomes unsupported or ambiguous.

The fourth demo is mandatory because it proves that losing visibility is not silently converted into a clean result.

## Defensibility filter

Before approving a major future feature, ask:

1. Does it improve deterministic invariant judgment, evidence provenance, coverage truth, verification, or conformance?
2. Is a mature external engine already good enough at the raw scanning capability?
3. Can Sentrdel import the result instead of rebuilding the engine?
4. Does building it introduce new credential, network, process, runtime, or supply-chain authority?
5. Would the feature make the four proof-of-category demos materially better?

If the answer is mostly "no," defer the feature.

## Merge-order warning for the current planning PR

The strategic roadmap PR created from this corpus must not move protected `main` while the active R3 PR depends on the current canonical base for exact-head qualification.

Finish and prove the active R3 unit first. Then reconcile the roadmap PR against the new canonical `main`, qualify it normally, and only then consider merging the planning amendment.