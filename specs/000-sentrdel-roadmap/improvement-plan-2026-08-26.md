# Sentrdel Improvement Plan of Record — 2026-08-26

**Status:** PROPOSED_BINDING_AMENDMENT  
**Base:** `c3a05834c13d5608b1e15e2a6ca353eb6389079c`  
**Scope:** Product, security, evaluation, learning, and execution-order improvements discovered by the 2026-08-26 major project evaluation.  
**Authority when merged:** This document refines roadmap sequencing but does not override the Constitution. The active Spec Kit `spec.md`, `plan.md`, and `tasks.md` remain the executable R1 authority.

## Purpose

Sentrdel's core thesis remains valid: Rust trusted core, Evidence Before Verdict, local-first/vendor-neutral operation, monotonic guardrails, explicit coverage truth, provider-aware Security Packs, safe verification, and reuse of mature security engines behind strict evidence boundaries.

The 2026-08-26 evaluation found that the largest strategic gap is not another scanner or another LLM integration. It is the absence of a first-class **evaluation + controlled learning system** that can prove whether Sentrdel is getting better without allowing self-modification to corrupt the trusted judgment plane.

This Plan of Record converts those findings into ordered repository work.

## Non-negotiable architecture rule

Sentrdel MUST distinguish three planes:

1. **Trusted Judgment Plane** — canonical Evidence, reconciliation, Findings, policy, guard decisions, verification semantics, and kernel invariants.
2. **Research/Learning Plane** — may generate hypotheses, candidate rules, candidate pack checks, candidate fixtures, candidate fuzz targets, and candidate remediation guidance.
3. **Evaluation Plane** — frozen benchmark definitions, immutable evaluator behavior for a run, regression corpora, adversarial corpora, and protected holdouts.

The Research/Learning Plane MUST NOT directly:

- create authoritative FACT or VERIFIED Evidence;
- create or mutate canonical Findings outside the reconciler;
- weaken a kernel invariant or prior DENY;
- suppress deterministic Evidence;
- change evaluation criteria while evaluating its own candidate;
- promote its own candidate directly to ACTIVE production authority.

Candidate promotion requires replay, benchmark qualification, protected-holdout evaluation, shadow qualification where applicable, and explicit approval/signing according to the future learning-plane specification.

## Ordered execution plan

### Gate A — Finish the current R1 trusted foundation

Continue the existing canonical order first:

`T032 -> T033 -> T034 -> T035 -> T036`

Do not interrupt this sequence with broad learning-plane implementation. T032's active SQLite graph mapping remains separate from this planning amendment.

### Gate B — Interpose SentrdelBench Core before detector breadth

Before broad US1 detector expansion, establish a minimal immutable evaluation substrate. The R1 benchmark must exist before Sentrdel accumulates rules that can overfit or increase noise.

Required dimensions:

- high-severity precision;
- confirmed miss/recall where ground truth exists;
- clean-PR false-positive rate;
- guard false-block rate;
- explicit coverage completeness;
- evidence/provenance completeness;
- deterministic replay stability;
- review latency;
- guard latency;
- memory/resource bounds;
- explanation contract correctness.

The evaluator is multi-objective. A candidate MUST NOT be considered better solely because recall increased if false positives, false blocks, latency, or authority correctness materially regress.

Corpus classes:

1. public regression corpus;
2. development evaluation corpus;
3. protected holdout corpus whose expected outputs are not exposed to candidate-generation logic.

### Gate C — Prove one excellent end-to-end review thread

After the benchmark core, prioritize a vertical product proof before broad rule count:

`safe git diff -> one excellent secret detector + one excellent GitHub Actions detector -> Evidence -> reconciler -> Finding -> graph context/blast radius -> sentrdel review -> benchmark`

This does not replace the existing US1 tasks. It changes the quality strategy: prove the developer experience and evidence semantics early, then expand producer breadth.

### Gate D — Self-security moves forward

Sentrdel MUST protect its own repository before claiming release-grade security tooling.

Near-term requirements:

- protect `main` with a GitHub ruleset/branch policy;
- require the canonical CI gates appropriate to the changed paths;
- disallow casual direct pushes to protected release authority;
- move `cargo-audit`/`cargo-deny` and privileged-dependency qualification checks earlier than final release closeout where practical;
- retain pinned GitHub Actions and no persisted checkout credentials;
- later add SBOM, artifact digest, provenance/attestation, and signed release metadata.

Branch protection is repository governance, not evidence that the code is secure.

### Gate E — Harden MCP process authority before Guard implementation

Before `T050`-`T058` can be considered complete, the stdio MCP server process boundary must receive the same credential discipline as the external-engine boundary.

Default child environment: deny by default.

Potentially permitted only when explicitly needed and normalized:

- minimal executable search path;
- locale;
- synthetic/restricted HOME-equivalent where required;
- server-specific variables explicitly granted by user policy.

Credentials and authority-bearing variables such as cloud keys, model-provider keys, forge tokens, signing material, SSH agent sockets, database credentials, and service-role secrets MUST NOT be inherited implicitly.

Future designs SHOULD prefer scoped capability brokerage over plaintext secret inheritance where practical.

### Gate F — Make instruction/context provenance first-class

Agent-era security requires Sentrdel to distinguish data from authorized instruction. Future contracts must be able to represent at least:

- source kind/channel;
- origin identity where knowable;
- content digest;
- trust class;
- instruction authority class;
- sensitivity;
- integrity status;
- receipt/evaluation time.

Examples such as issue text, PR comments, README content, source comments, MCP descriptions/results, browser content, CI logs, and tool output are untrusted context by default and MUST NOT silently acquire authority to widen security permissions or authorize secret access.

R1 may freeze the authority contract without implementing every integration surface.

### Gate G — Add scoped Project Security Memory, not hidden LLM memory

A future Security Memory subsystem should retain inspectable, provenance-backed project security context such as canonical sanitizers, architecture invariants, accepted-risk expiry, generated-code regions, intentional public resources, and tenant-isolation requirements.

Memory is context, not authority. It MUST NOT:

- manufacture FACT/VERIFIED status;
- silently suppress Evidence;
- weaken kernel policy;
- become an unbounded permanent exception store.

Memory requires scope, provenance, authority class, expiry, invalidation subjects, and reviewer identity where applicable. Graph changes SHOULD invalidate or mark related memory `STALE` and require revalidation.

Memory mutations should be auditable security events.

### Gate H — Add temporal security intelligence

Findings should eventually expose change-relative state, not merely current existence. Target lifecycle vocabulary:

- `NEW`
- `PRE_EXISTING`
- `WORSENED`
- `MITIGATED`
- `MOVED`
- `REINTRODUCED`
- `UNCERTAIN`

This must be evidence/graph-diff backed and must not invent causality that the available provenance cannot prove.

### Gate I — Calibrate producer reliability

Sentrdel should eventually maintain measured producer/rule reliability profiles derived from benchmark history, including precision, known blind spots, supported scope, benchmark revision, and last calibration time.

Reliability is contextual evidence for reconciliation/explanation; it MUST NOT grant an epistemic class the producer is otherwise forbidden to emit.

### Gate J — Treat Rules and Security Packs as supply-chain objects

Community rules/packs must not become an unreviewed plugin execution surface. Future pack/rule lifecycle should record:

- manifest/schema version;
- content digest;
- publisher/provenance;
- declared filesystem/process/network/secret capabilities;
- authority ceiling;
- benchmark qualification;
- signature where applicable;
- revocation/retirement state.

Declarative rules should have no ambient process/network/secret authority by default. Privileged native integrations require explicit qualification.

### Gate K — Safe Verification remains bounded but becomes strategically central

R6 remains the home of full safe verification/fix validation. It should prove or disprove selected claims using explicit authorization, isolation, synthetic or explicitly allowed local data, network policy, resource limits, and reproducible execution evidence.

LLM review or diff inspection alone MUST NOT produce `FIX_VERIFIED`.

### Gate L — Continuous Security Research/Learning Plane

After benchmark and verification foundations are mature enough, add a dedicated roadmap slice for controlled continuous improvement inspired by iterative research loops:

`observe -> distill -> hypothesize -> generate candidate -> replay -> benchmark -> protected holdout -> shadow -> approve/sign -> active`

Candidate mutation scope may include:

- rules;
- graph heuristics;
- fixtures;
- fuzz targets;
- Security Pack checks;
- remediation guidance.

Immutable/non-candidate authority includes:

- benchmark evaluator for the run;
- protected holdout labels;
- kernel invariants;
- epistemic authority rules;
- reconciler authority;
- verification semantics;
- release gates.

Every experiment should have a durable ledger including baseline, candidate digest, evaluator version, corpus revision, metrics, result, and keep/discard/promotion decision.

## Product moat after this amendment

Sentrdel should not position itself as "another AI security scanner" or compete on rule count. The defensible category is:

> **The open-source security evidence, control, and continuously evaluated judgment plane for AI-built software projects — from agent instruction and action to production.**

The differentiating assets are:

- Evidence Before Verdict;
- ASEL and agent-action provenance;
- explicit coverage truth;
- independent reconciliation;
- context/instruction provenance;
- provider-aware Security Packs;
- project security invariants and scoped security memory;
- safe verification;
- immutable evaluation and controlled learning;
- local-first Rust distribution.

## Work that remains explicitly out of R1 unless separately specified

- autonomous self-modification of trusted core;
- automatic candidate promotion to production authority;
- production/third-party exploitation or probing;
- broad credentialed provider posture by default;
- hidden cloud training requirement;
- universal CPG construction;
- remote MCP transport without a dedicated threat-model/spec;
- opaque organizational memory that can suppress evidence.

## Mapping to repository artifacts

- Binding R1 architecture details: `specs/001-v0-1-evidence-guard-foundation/implementation-amendment-002-evaluation-learning.md`
- R1 sequencing: `specs/001-v0-1-evidence-guard-foundation/plan.md`
- R1 executable work order: `specs/001-v0-1-evidence-guard-foundation/tasks.md`
- Multi-release sequencing: `specs/000-sentrdel-roadmap/roadmap.md`

This file is intentionally the human-readable entry point. Future continuations should read it after the Constitution and before deciding whether a proposed improvement belongs in R1 or a later dedicated spec.
