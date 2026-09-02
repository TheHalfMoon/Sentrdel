# Sentrdel Strategic Roadmap Amendment — Semantic Security Graph

**Status:** PROPOSED_BINDING_ROADMAP_AMENDMENT  
**Research date:** 2026-09-02  
**Planning base:** `main@f4c72f1fdf9a6d817c2349578d3cd7993aeacd8a`  
**Scope:** Product category, architecture, sequencing, ecosystem interoperability, evaluation, distribution, and long-term moat.  
**Authority if merged:** This amendment refines the spec-of-specs roadmap. It does not override the Constitution or any active Spec Kit authority. In particular, it MUST NOT reorder, widen, or bypass the active R3 `spec.md`, `plan.md`, or `tasks.md` sequence.

## Executive decision

Sentrdel MUST NOT become an open-source clone of a broad AppSec platform.

Sentrdel SHOULD become the **open-source security-invariant regression and evidence judgment engine for AI-built software**.

The **Sentrdel Semantic Security Graph (SSG)** is the bounded reasoning substrate that makes this possible; it is not the category by itself.

The durable product wedge is:

> **Understand which security property changed, prove what is known, expose what is not known, and show exactly which invariant became weaker, stronger, contradicted, or no longer provable.**

This keeps the existing constitutional thesis intact:

- reuse mature scanners and security infrastructure where possible;
- own the canonical evidence, graph, invariant, reconciliation, guard, verification, conformance, and developer-judgment layers;
- remain local-first and useful without a proprietary cloud;
- keep uncertainty and coverage gaps explicit;
- never let a model, external scanner, graph edge, vendor integration, severity score, or reachability score silently upgrade security authority.

## Why this amendment exists

A current review of Aikido Security is strategically useful because it demonstrates several product truths that are now visible across modern AppSec:

1. developer adoption is increasingly won at the pull-request and developer-workstation seams, not by adding another dashboard;
2. full-repository context, graph/reachability analysis, triage, remediation, and verification are more valuable than raw scanner count;
3. broad scanner aggregation is commercially useful but is not a defensible open-source core by itself;
4. validated findings and retesting reduce trust-destroying false positives;
5. supply-chain intelligence and pre-install controls can become a strong adoption flywheel;
6. a generous free product can be a distribution strategy rather than a demo.

A second competitive triangulation against Semgrep, Endor Labs, Socket, GitHub Code Security/CodeQL, and XBOW materially changed the initial conclusion: **diff-aware PR scanning, cross-file context, graph/reachability, agent-action policy, package interception, autofix, and proof-oriented offensive validation are already emerging as table stakes across the market.** They are valuable capabilities but are not sufficient standalone moats.

These are research observations, not authority. Vendor claims are not benchmark truth and do not change Sentrdel's evidence model.

### Research inputs

Observed on 2026-09-02 and recorded in the companion competitive research artifact:

- Aikido PR Review: `https://www.aikido.dev/code/pr-review`
- Aikido AI Pentesting: `https://www.aikido.dev/attack/aipentest`
- Aikido pricing: `https://www.aikido.dev/pricing`
- Aikido Intel research: `https://www.aikido.dev/blog/aikido-intel-detects-malware-vulnerabilities-first`
- Aikido Safe Chain: `https://github.com/AikidoSec/safe-chain`
- current official product/documentation references for Semgrep, Endor Labs, Socket, GitHub Code Security/CodeQL, and XBOW as recorded in `competitive-triangulation-2026-09-02.md`.

## Competitive conclusion

### What broad platforms are good at

Modern platforms can create value by combining or deeply implementing many surfaces:

- SAST;
- SCA and dependency risk;
- secret detection;
- IaC and cloud posture;
- container/VM scanning;
- attack-surface discovery;
- runtime protection;
- diff-aware PR review;
- cross-file context and reachability;
- coding-agent action controls;
- package/firewall controls;
- autofix;
- offensive verification;
- threat intelligence.

Trying to recreate all of those engines inside Sentrdel would violate Principle VII in spirit even if the code were technically permissive.

### Capabilities that are not enough to define the category

Sentrdel must not mistake the following for a durable category moat by themselves:

- "we scan the PR diff";
- "we use full-repository context";
- "we have a code graph";
- "we calculate reachability";
- "we review AI-generated code";
- "we guard coding agents";
- "we block suspicious packages";
- "we autofix findings";
- "we verify vulnerabilities offensively".

Sentrdel may implement or integrate some of these, but the market already contains serious versions of each.

### What Sentrdel should own instead

Sentrdel's moat should be the security meaning that sits **between** observations and across revisions:

- which route changed;
- which actor reaches it;
- which authentication source is statically recognized;
- which guard dominates the operation;
- which tenant/resource selector is request-controlled;
- which provider authority is used;
- which data operation is reachable;
- which invariant applies;
- which evidence supports or contradicts the path;
- which coverage dimension is missing;
- what changed relative to the trusted base;
- whether losing analysis capability made a formerly provable property uncertain;
- whether a separately authorized verifier proved or disproved a stronger claim.

The product must answer questions that raw scanners, generic graph engines, and generic AI reviewers usually cannot answer as an open deterministic contract:

> Did this PR weaken tenant isolation?

> Did an ownership guard disappear from the supported path to a mutation?

> Did elevated provider authority become reachable from request-controlled input?

> Did a protected-property mutation become broader?

> Did coverage fall because a formerly supported path became dynamic?

> Did the security property become genuinely safer, or did the detector merely lose visibility?

## The Sentrdel Semantic Security Graph

The long-term canonical graph direction should be named explicitly:

> **Sentrdel Semantic Security Graph (SSG)**

This is a product/architecture name for the existing and future bounded canonical graph work. It is **not** authority to create a universal CPG or a second graph runtime.

### Initial semantic node families

The SSG should progressively normalize bounded observations into stable node families such as:

- repository revision / trusted base;
- file and symbol;
- route / entry point;
- actor context;
- authentication source;
- authorization guard;
- value origin;
- data operation;
- resource / protected property;
- provider/client authority;
- dependency/package;
- CI/agent action;
- runtime observation;
- invariant;
- Evidence;
- Coverage Gap;
- Finding reference;
- verification result.

R3 already owns the first important application-semantic subset: route, actor, guard, value origin, data operation, resource, provider authority, invariant, cross-layer path, Evidence, and Coverage.

### Initial semantic edge families

The graph should progressively represent bounded relationships such as:

- `CALLS`;
- `FLOWS_TO`;
- `READS_FROM`;
- `WRITES_TO`;
- `GUARDED_BY`;
- `AUTHENTICATES_AS`;
- `SELECTS_BY`;
- `USES_AUTHORITY`;
- `CROSSES_TRUST_BOUNDARY`;
- `SUPPORTS`;
- `CONTRADICTS`;
- `VERIFIED_BY`;
- `INTRODUCED_BY`;
- `CHANGED_FROM`.

Names are design direction only until frozen by the applicable schema/spec.

### Graph authority rule

A graph is a reasoning substrate, not an epistemic upgrade mechanism.

No graph node, edge, confidence score, path score, model annotation, or external-engine relationship may independently promote Evidence from one epistemic class to another. The existing reconciler remains the only canonical Finding authority.

## First post-R3 product wedge: Security Invariant Regression

After R3 is canonical and post-merge proven, the highest-value product slice should be a **security-invariant regression engine**, not broad provider-pack proliferation and not generic diff-aware scanning.

The engine compares a trusted base semantic state with a candidate/head semantic state and reports **security-property changes** rather than dumping every current observation.

### Required comparison classes

At minimum, future specifications should evaluate evidence-backed states such as:

- `NEW`;
- `PRE_EXISTING`;
- `WORSENED`;
- `MITIGATED`;
- `MOVED` only where semantic identity is sufficiently proven;
- `REINTRODUCED`;
- `UNCERTAIN`;
- `COVERAGE_LOST`;
- `COVERAGE_GAINED`.

These labels must be graph/evidence-diff backed. They must not invent causality merely because two commits are adjacent.

### Coverage regression is a security result

Coverage regression is not a secondary diagnostic.

If the trusted base had a supported route → actor → guard → data path and the candidate refactors that path into unsupported/dynamic semantics, Sentrdel must not report the disappearance of a violation or guard observation as improvement. It must expose that the security property is no longer provable under the current bounded analysis.

This is one of the project's most important differentiators because it operationalizes Evidence Before Verdict at the change boundary.

### Example target developer output

A useful PR result should look conceptually like:

```text
SECURITY INVARIANT REGRESSION

POST /org/:org_id/invoices

Base:
  authenticated actor
  organization ownership guard
  invoice query constrained by organization_id

Head:
  authenticated actor
  ownership guard no longer dominates the supported data path
  invoice query still uses request-controlled organization_id

Invariant:
  actor.organization_id == resource.organization_id

State:
  WORSENED

Proof status:
  deterministic static evidence

Coverage:
  route: covered
  actor: covered
  guard: partial
  data operation: covered
  runtime verification: unavailable
```

The actual output contract must be separately specified and benchmarked.

### UX principle

The default PR experience should optimize for **change relevance**, not total backlog size.

The primary summary should answer:

1. what security property changed;
2. whether it became safer, weaker, contradicted, or unknown;
3. why Sentrdel believes that;
4. where the evidence came from;
5. what analysis was unsupported or lost;
6. what stronger claim, if any, was separately verified;
7. what action is required before merge.

Existing/pre-existing findings may remain accessible without dominating the PR signal.

## Open Evidence + Coverage conformance as a moat

The project should not keep its strongest semantics as undocumented implementation detail.

R9 should mature into an open conformance ecosystem for:

- canonical Evidence producer behavior;
- provenance completeness;
- Coverage truthfulness;
- invariant evaluation states;
- trusted-base/candidate regression pairs;
- external importer authority ceilings;
- verification/evidence-upgrade boundaries;
- deterministic semantic identity and replay.

A third-party producer should eventually be able to prove that it emits valid Sentrdel-compatible evidence without becoming trusted judgment authority.

This can create an ecosystem moat that proprietary platforms are structurally less incentivized to standardize openly: Sentrdel becomes both an implementation and an inspectable contract for how security claims, uncertainty, and change-relative evidence should behave.

Public conformance corpora do not replace protected holdouts for release qualification.

## External Evidence Interop: import, do not rebuild

Sentrdel should define a versioned **External Evidence Import Protocol** in a later bounded spec.

The purpose is to consume useful outputs from mature tools while preserving the Rust judgment boundary.

Candidate inputs include:

- SARIF producers;
- CycloneDX/SPDX SBOMs;
- OSV-compatible vulnerability data;
- Trivy/Grype/Syft outputs;
- Semgrep/Opengrep results;
- user-supplied CodeQL results;
- Gitleaks/secret-scanner results;
- Checkov/Terrascan/IaC results;
- later DAST or runtime observations from qualified engines.

Rules:

1. imported records are untrusted external observations;
2. producers must be identified by exact version/config/digest when available;
3. imports must be schema-validated and resource-bounded;
4. external severity does not automatically become Sentrdel Finding severity;
5. external reachability/confidence does not become FACT/VERIFIED authority;
6. unavailable or failed producers create coverage state, not PASS;
7. the same imported evidence should be linkable into the SSG and explain output;
8. no external engine receives ambient network, process, secret, or repository-rule authority merely because an importer exists.

This allows Sentrdel to become the open judgment layer above the security ecosystem rather than scanner number forty-seven.

## Verification and fix loop

Current proof-oriented offensive and verification products reinforce an existing constitutional decision: strong claims become more trustworthy when a separate verifier can reproduce them.

Sentrdel's R6 should therefore be framed as an **Evidence Upgrade and Fix Validation Plane**.

Conceptual lifecycle:

```text
static observation
    -> deterministic inference / hypothesis
    -> separately authorized bounded verifier
    -> runtime/verification evidence
    -> reconciler
    -> verified or contradicted result
```

For remediation:

```text
finding
    -> candidate fix
    -> ordinary code review
    -> re-analysis
    -> bounded verification where authorized
    -> FIX_VERIFIED only with execution evidence
```

A model-generated patch is never proof that the issue is fixed.

Verification remains opt-in, isolated, target-scoped, resource-bounded, and non-autonomous. Escalated exploitation, third-party probing, production mutation, or credential access remain separately gated even if competitors provide those features.

## Supply-chain and developer-action control

Package-firewall products demonstrate the product value of protecting the package-install seam before malicious code executes.

Sentrdel should learn from that adoption pattern, but not copy a proprietary or third-party implementation into the trusted core merely for parity.

A later R7/agent-control spec should evaluate a bounded **dependency-action guard** that can protect controllable package/install/build actions from coding agents and CI. It should prefer existing ecosystem intelligence and qualified package metadata rather than building a proprietary malware-analysis engine first.

Potential evidence/control inputs include:

- package identity and requested version;
- lockfile delta;
- package age where trustworthy metadata exists;
- known vulnerability/malware intelligence;
- install-script/build authority;
- new `build.rs`/proc-macro/native-code surfaces;
- dependency provenance and checksum;
- project policy/approval state.

Repository-controlled configuration must not silently weaken the kernel authority ceiling.

## Open Security Intelligence direction

Continuously refreshed security intelligence can improve detection and prevention faster than static vulnerability databases alone.

Sentrdel should not respond by making a proprietary threat feed mandatory.

Instead, later R7/R11 work should define an **open security intelligence ingestion and qualification model** that can consume multiple signed/versioned sources, community research, advisory feeds, package metadata, and internally generated research candidates.

Intelligence remains evidence/context until validated under Sentrdel rules.

A future community intelligence artifact should ideally carry:

- source/publisher;
- digest/version;
- observation time;
- ecosystem/package/project identity;
- confidence/proof basis;
- expiry or supersession state;
- license/redistribution terms;
- signature where available;
- benchmark/calibration metadata where applicable.

The Research/Learning Plane may propose new intelligence-derived rules or fixtures, but cannot self-promote them into trusted authority.

## Open-source distribution strategy

Sentrdel's open-source advantage should be architectural, not merely price-based.

The default installation should remain useful without account creation, cloud upload, or proprietary API keys.

Core community assets should remain inspectable and portable:

- Rust CLI/core;
- canonical Evidence and event contracts;
- SSG schemas/projections when frozen;
- benchmark and conformance contracts and public corpus portions;
- Security Pack manifests;
- external evidence import contracts;
- local explain output;
- local invariant-regression analysis;
- rule/pack qualification metadata.

A future hosted service may add collaboration, managed intelligence, fleet policy, storage, or scale, but MUST NOT become required for the core security judgment promised by the open-source project.

## Revised strategic sequencing after R3

Roadmap IDs remain stable; this section describes priority, not permission to bypass active specs. The detailed dependency-ordered decomposition is recorded in `post-r3-execution-blueprint-2026-09-02.md`.

### P0 — Finish R3 exactly as currently governed

Do not change the canonical `R3-T009 -> ... -> R3-T038` order because of this amendment.

R3 is already building the crucial semantic substrate. Its graph/link/correlation tasks are the foundation for the strategy described here.

### P1 — R5 first productization slice: Security Invariant Regression + Forge integration

After R3 closeout, prioritize the R5 path that turns SSG/invariant base-head comparison into a first-class developer workflow.

R5 should depend on R3 for the semantic regression capability. The local CLI/protocol should freeze before forge/IDE integrations so vendor adapters consume one judgment implementation instead of forking semantics.

### P2 — R9 open conformance + benchmark expansion

Before broadening detector/provider support aggressively, freeze benchmark/conformance dimensions for:

- invariant-regression precision;
- known-ground-truth misses;
- clean-PR false-positive rate;
- coverage-loss visibility;
- provenance completeness;
- deterministic graph-diff replay;
- explanation correctness;
- authority correctness;
- latency/resource bounds.

### P3 — R6 Evidence Upgrade + Fix Verification

Build bounded verification around a small number of high-value invariant classes before attempting generic autonomous security testing.

### P4 — R7 standards-first External Evidence Import Protocol

Gain breadth by importing qualified mature evidence before deciding to build equivalent scanner engines.

### P5 — R4 provider/auth expansion through graph semantics

New packs must improve semantic judgment, not merely add checklist count.

A provider pack should preferentially contribute nodes/relationships/coverage that make cross-layer invariants stronger.

### P6 — R7 supply-chain/action controls and open intelligence

Protect dependency/build actions only at genuinely controllable seams and prefer qualified multi-source intelligence over a proprietary mandatory feed.

### P7 — R8 runtime evidence correlation

Runtime observations should attach to the same semantic identities where possible and must remain distinguishable from static evidence.

### P8 — R10 full-project semantic posture

R10 becomes the point where application semantics, dependencies, provider posture, CI, agent actions, deployment, and runtime observations converge into the mature SSG-backed project posture.

### P9 — R11 controlled learning/intelligence flywheel

Only after benchmark, conformance, and verification maturity should Sentrdel automate candidate discovery at scale.

## Roadmap mapping

| Roadmap slice | Strategy contribution after this amendment |
|---|---|
| R1 | Evidence, guard, trusted-head, evaluation, and local judgment foundation |
| R2 | Provider/static posture evidence feeding cross-layer semantics |
| R3 | First application-semantic graph: route x actor x guard x data x invariant |
| R4 | Framework/provider semantic expansion, not shallow rule proliferation |
| R5 | Security invariant regression, local developer contract, GitHub/forge delivery, IDE/agent presentation |
| R6 | Evidence upgrade, bounded verification, fix validation |
| R7 | External evidence imports, supply-chain/dependency/build security, open intelligence ingestion |
| R8 | Runtime evidence and enforceable runtime tiers |
| R9 | Public semantic-security conformance, benchmark and open judgment specifications |
| R10 | Mature SSG-backed A-to-Z project posture |
| R11 | Controlled research/intelligence/learning candidate flywheel |

## Competitive response matrix

| Competitor/platform strength | Sentrdel response |
|---|---|
| Broad scanner aggregation | Import mature evidence; do not rebuild every engine |
| Diff-aware/full-codebase PR review | Deterministic **security-invariant regression** plus explicit coverage-loss semantics |
| Reachability/code graph | Evidence-backed bounded SSG with explicit authority separation; graph is substrate, not category |
| Coding-agent action policy | Keep monotonic local guard seams, but differentiate through invariant/evidence judgment and provenance |
| Package firewall | Later bounded dependency/build action guard using qualified external intelligence |
| Autofix | Candidate remediation + re-analysis + verification before `FIX_VERIFIED` |
| AI/offensive validation | R6 bounded opt-in verification; no autonomous third-party/production exploitation authority |
| Threat-intelligence feed | Multi-source open intelligence ingestion with provenance and qualification |
| Proprietary platform correlation | Open Evidence/Coverage/Invariant/Regression conformance plus local SSG judgment |

## Four proof-of-category demos

Before broad feature expansion, Sentrdel should prove these cases end-to-end through the same contracts:

1. **Tenant isolation regression** — a supported tenant/ownership guard is removed or weakened while request-controlled resource selection still reaches the data operation.
2. **Elevated provider-authority regression** — a path becomes request-reachable through elevated/service-role authority without a corresponding supported application guard.
3. **Protected-property mutation regression** — an explicit safe allowlist becomes a broad request-controlled mutation capable of including protected fields.
4. **Coverage regression** — a formerly supported auth/ownership path becomes dynamic/unresolved and Sentrdel reports `COVERAGE_LOST`/uncertainty rather than a false improvement.

Demo 4 is mandatory because it proves Sentrdel's Evidence Before Verdict thesis more clearly than another vulnerability screenshot.

## Defensibility filter for future features

A major feature should normally be deferred or imported rather than built if:

1. a mature external engine already provides the raw capability well;
2. importing its evidence would preserve the security value needed by Sentrdel;
3. building the engine would not materially improve invariant semantics, Evidence/Coverage truth, verification, or conformance;
4. the new engine introduces significant dependency, credential, network, runtime, or supply-chain authority;
5. it does not materially strengthen the four proof-of-category demos or another frozen benchmark dimension.

This filter prevents roadmap drift back into scanner-count competition.

## Product scorecard

Strategic success should be measured using at least:

- invariant-regression precision;
- supported-case recall;
- clean-PR false-positive rate;
- coverage-loss truthfulness;
- provenance completeness;
- authority correctness;
- deterministic replay;
- warm/cold latency;
- memory/resource bounds;
- explanation usefulness;
- false-block rate at enforcement seams;
- local/offline usability;
- conformance stability across producer/importer implementations.

Rule count and alert count are not success metrics by themselves.

## Explicit non-goals from this amendment

This amendment does not authorize:

- a generic CSPM platform in the near term;
- a full in-house DAST scanner;
- an autonomous pentest swarm;
- a proprietary vulnerability/advisory database as a core dependency;
- a universal CPG;
- LLM-only PR judgment;
- automatic self-approved remediation;
- target execution or provider credentials inside R3;
- a hosted control plane required for local Sentrdel analysis;
- bypassing R3 task order to implement the strategy early.

## Merge and successor boundary

This amendment should not move protected `main` while the active R3 implementation PR depends on the current canonical base for exact-head qualification.

After R3 becomes canonical and post-merge proven:

1. reconcile this amendment and its companion artifacts against the new canonical `main`;
2. qualify and independently review the planning PR normally;
3. merge it only when repository governance permits;
4. create the first post-R3 successor Spec Kit separately;
5. do not treat the roadmap text itself as implementation authority.

## Companion artifacts

- `competitive-triangulation-2026-09-02.md` — records the broader market comparison that sharpened the moat.
- `post-r3-execution-blueprint-2026-09-02.md` — decomposes the strategy into bounded future Spec Kit slices and gates.
- `README.md` — navigation and authority index for the roadmap corpus.
