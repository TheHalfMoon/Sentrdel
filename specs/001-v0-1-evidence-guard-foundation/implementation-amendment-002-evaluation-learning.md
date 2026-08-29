# Implementation Amendment 002 — Evaluation, Controlled Learning, Context Provenance, and Guard Credential Boundaries

**Status:** BINDING_APPLIED  
**Date:** 2026-08-26  
**Applies to:** `specs/001-v0-1-evidence-guard-foundation/` and roadmap sequencing  
**Constitution impact:** No exception requested. This amendment tightens Principles II, III, IV, VIII, and IX and preserves the R1 product category.

## 1. Why this amendment exists

The R1 architecture already separates Evidence from Findings, constrains LLM authority, reports coverage gaps honestly, and defines bounded guard/engine boundaries. A fresh project/market/security evaluation found four missing controls that materially affect whether Sentrdel can become a trustworthy long-lived security system:

1. evaluation infrastructure arrives too late relative to detector expansion;
2. no safe architecture exists yet for continuous improvement from false positives, misses, incidents, or new ecosystem knowledge;
3. agent-era instruction provenance and project security memory are not first-class authority-bounded concepts;
4. the stdio MCP server process boundary needs explicit deny-by-default credential inheritance rules comparable to the external-engine runner.

This amendment adds those controls without authorizing self-modification, exploitation, remote MCP, or hidden model authority.

## 2. Immutable evaluation boundary

### 2.1 SentrdelBench Core

R1 MUST establish a minimal benchmark/evaluation substrate before broad detector growth.

For a single evaluation run, the following are immutable inputs identified by digest/version:

- evaluator implementation/version;
- metric definitions;
- corpus revision;
- expected outputs/ground truth for the evaluation subset;
- resource/latency measurement policy;
- authority/contract checks.

Candidate-generation logic MUST NOT mutate them during the run.

### 2.2 Required R1 metric classes

At minimum the core evaluator MUST support or reserve explicit machine-readable fields for:

- high-severity precision;
- known-ground-truth recall/miss rate;
- clean-PR false positives;
- guard false blocks where guard behavior is evaluated;
- coverage completeness/gaps;
- Evidence provenance completeness;
- deterministic replay equality/stability;
- review latency and resource usage;
- guard decision latency and framing/resource bounds;
- explanation/authority contract correctness.

No single scalar score becomes canonical truth. Release/promotion logic uses explicit thresholds and Pareto-aware comparison.

### 2.3 Corpus isolation

The benchmark architecture MUST distinguish:

- public regression fixtures;
- development evaluation fixtures;
- protected holdout fixtures/labels.

Candidate-generation logic MUST NOT receive protected holdout expected outputs. Holdout qualification is a promotion gate, not a tuning oracle.

## 3. Controlled Research/Learning Plane

### 3.1 Candidate-only authority

Future learning/research automation MAY create:

- candidate rules;
- candidate graph heuristics;
- candidate Security Pack checks;
- candidate fixtures;
- candidate fuzz targets;
- candidate remediation/explanation text;
- hypotheses about recurring false positives or misses.

It MUST NOT directly create authoritative Findings or bypass normal schema/reconciliation/policy authority.

### 3.2 Promotion firewall

The intended lifecycle is:

`DRAFT -> REPLAYED -> BENCHMARKED -> HOLDOUT_QUALIFIED -> SHADOW -> APPROVED -> SIGNED -> ACTIVE`

and later:

`ACTIVE -> STALE | REVOKED | RETIRED`

A future dedicated spec MAY simplify this lifecycle for low-authority declarative artifacts, but it MUST preserve independent promotion authority.

### 3.3 Self-modification prohibition

The Research/Learning Plane MUST NOT autonomously modify or promote changes to:

- Rust kernel invariants;
- epistemic-class authority constraints;
- Evidence/Finding authority boundaries;
- reconciler-only Finding creation;
- verification semantics;
- benchmark evaluator/holdout labels used to judge its current candidate;
- release gate definitions.

Those remain ordinary reviewed repository changes governed by Spec Kit and repository review/CI.

## 4. Feedback is Evidence, not truth

Developer/user triage such as `false positive`, `accepted risk`, `expected behavior`, or `not exploitable` MUST be stored/represented as scoped feedback/context with actor, rationale, time, and provenance where persisted.

A dismissal MUST NOT automatically disable a rule or become FACT.

A future learning system may generate a hypothesis from repeated feedback, but the hypothesis remains candidate-only until replay/benchmark/holdout/promotion gates succeed.

## 5. Project Security Memory authority ceiling

A future `SecurityMemory` contract SHOULD support inspectable project context such as:

- canonical sanitizer/guard identities;
- project invariants;
- accepted-risk decisions with expiry;
- generated-code scope;
- intentionally public resources;
- tenant/security architecture requirements.

Every memory record MUST be bounded by:

- scope;
- provenance/source;
- authority class;
- creation time;
- optional expiry;
- invalidation subjects/digests where applicable;
- reviewer/actor identity when human approval is authoritative.

Security Memory MUST NOT:

- mint FACT/VERIFIED Evidence;
- silently suppress Evidence;
- weaken Rust kernel invariants;
- become an unbounded permanent exception list.

Graph/file/profile changes SHOULD be able to mark dependent memory `STALE` or `REVALIDATION_REQUIRED` rather than silently continuing to trust it.

Memory creation/update/revocation SHOULD produce auditable ASEL or equivalent security events once the feature exists.

R1 is allowed to define the authority contract without implementing general-purpose memory behavior.

## 6. Context and instruction provenance

Agent-era inputs require explicit separation between **content that may be read** and **content authorized to instruct a privileged action**.

A future `ContextProvenance`-class contract SHOULD represent:

- source/channel kind;
- origin identity when knowable;
- content digest;
- trust class;
- instruction-authority class;
- sensitivity;
- integrity status;
- receipt/evaluation timestamp/session.

By default, repository text, code comments, issue/PR text, CI logs, MCP descriptions/results, browser content, external-engine output, and model output are untrusted content. Reading such content MUST NOT itself grant authority to widen policy, authorize credential access, or weaken evidence capture.

Repository-controlled authority remains bounded by the Constitution rule that repository configuration may narrow but not widen core permissions.

## 7. MCP child-process credential boundary

The R1 stdio MCP guard MUST apply a deny-by-default child-process environment policy to any MCP server process Sentrdel launches/manages.

Implicit inheritance of the developer's complete environment is prohibited.

Examples of authority-bearing variables that MUST be absent unless an explicit capability and user policy grants them include:

- cloud credentials (`AWS_*`, Azure/GCP equivalents);
- forge tokens (`GITHUB_TOKEN`, `GH_TOKEN`, GitLab equivalents);
- model/provider API keys;
- signing credentials;
- SSH agent/socket authority;
- database credentials/URLs;
- provider service-role or admin keys;
- unrelated application secrets.

Minimal process requirements such as executable lookup path, locale, or synthetic HOME-like state may be provided only as narrowly as necessary.

Credential canary tests MUST prove default non-inheritance.

Future capability brokerage SHOULD prefer scoped operations/tokens over ambient plaintext secret inheritance when feasible.

## 8. Temporal security state

Graph-diff/review infrastructure SHOULD support change-relative classification such as:

- `NEW`;
- `PRE_EXISTING`;
- `WORSENED`;
- `MITIGATED`;
- `MOVED`;
- `REINTRODUCED`;
- `UNCERTAIN`.

Classification MUST be backed by stable identities and available diff/provenance. When causality cannot be proven, Sentrdel reports uncertainty rather than inventing introduction attribution.

## 9. Producer reliability calibration

Future producer/rule reliability profiles MAY summarize benchmark-derived behavior, including precision, known blind spots, supported scope, benchmark revision, and calibration date.

Reliability is explanatory/reconciliation context only. It cannot upgrade a producer above its schema-authorized epistemic class.

## 10. Rules and Security Packs as supply-chain objects

Future rule/pack distribution MUST treat security content as a supply-chain input.

The design SHOULD support:

- content digest;
- provenance/publisher;
- manifest/schema version;
- declared filesystem/process/network/secret capabilities;
- authority ceiling;
- benchmark qualification metadata;
- signing/verification state;
- revocation/retirement state.

R1 does not implement remote community-pack distribution.

## 11. R1 binding task consequences

This amendment is implemented in R1 through the following task additions and ordering changes:

- T088: evaluation contract and benchmark conventions;
- T089: executable benchmark-core harness and run record;
- T090: corpus-class separation and protected-holdout semantics;
- T091: early self-security dependency gates;
- T092: protected-main governance verification;
- T093: deny-by-default MCP child-process credential boundary;
- T095: authority-safe context/learning contract.

T088-T092 and T095 execute after the foundational substrate and before broad detector growth. T093 executes before MCP server forwarding behavior. T094 is intentionally unused so existing assigned IDs remain stable.

## 12. Non-goals preserved

This amendment does not authorize:

- autonomous rule promotion or trusted-core self-modification;
- autonomous exploitation or production scanning;
- remote/Streamable HTTP MCP;
- general-purpose Security Memory implementation in R1;
- credentialed provider posture without a dedicated later specification;
- hidden use of protected holdout labels for tuning;
- weakening canonical Evidence/Finding/policy/verification authority boundaries.
