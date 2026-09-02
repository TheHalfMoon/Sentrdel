# Sentrdel Strategic Roadmap Amendment — Semantic Security Graph

**Status:** PROPOSED_BINDING_ROADMAP_AMENDMENT  
**Research date:** 2026-09-02  
**Planning base:** `main@f4c72f1fdf9a6d817c2349578d3cd7993aeacd8a`  
**Scope:** Product category, architecture, sequencing, ecosystem interoperability, evaluation, distribution, and long-term moat.  
**Authority if merged:** This amendment refines the spec-of-specs roadmap. It does not override the Constitution or any active Spec Kit authority. In particular, it MUST NOT reorder, widen, or bypass the active R3 `spec.md`, `plan.md`, or `tasks.md` sequence.

## Executive decision

Sentrdel MUST NOT become an open-source clone of a broad AppSec platform.

Sentrdel SHOULD become the **open-source semantic security graph and evidence judgment layer for software changes**, with a first-class PR security-regression workflow.

The durable product wedge is:

> **Understand the security meaning of a change, prove what is known, expose what is not known, and show exactly which security invariant became weaker or stronger.**

This keeps the existing constitutional thesis intact:

- reuse mature scanners and security infrastructure where possible;
- own the canonical evidence, graph, invariant, reconciliation, guard, verification, and developer-judgment layers;
- remain local-first and useful without a proprietary cloud;
- keep uncertainty and coverage gaps explicit;
- never let a model, external scanner, graph edge, or vendor integration silently upgrade security authority.

## Why this amendment exists

A current review of Aikido Security is strategically useful because it demonstrates several product truths that are now visible across modern AppSec:

1. developer adoption is increasingly won at the pull-request and developer-workstation seams, not by adding another dashboard;
2. full-repository context, graph/reachability analysis, triage, remediation, and verification are more valuable than raw scanner count;
3. broad scanner aggregation is commercially useful but is not a defensible open-source core by itself;
4. validated findings and retesting reduce trust-destroying false positives;
5. supply-chain intelligence and pre-install controls can become a strong adoption flywheel;
6. a generous free product can be a distribution strategy rather than a demo.

These are research observations, not authority. Vendor claims are not benchmark truth and do not change Sentrdel's evidence model.

### Primary research inputs

Observed on 2026-09-02:

- Aikido PR Review: `https://www.aikido.dev/code/pr-review`
- Aikido AI Pentesting: `https://www.aikido.dev/attack/aipentest`
- Aikido pricing: `https://www.aikido.dev/pricing`
- Aikido Intel research: `https://www.aikido.dev/blog/aikido-intel-detects-malware-vulnerabilities-first`
- Aikido Safe Chain: `https://github.com/AikidoSec/safe-chain`

Aikido describes PR review that uses full-codebase context, a pentest flow where additional agents validate candidate findings, a broad free/product-led distribution surface, a threat-intelligence pipeline, and an open-source package-install protection tool. Sentrdel should learn from the product shape without copying the platform breadth.

## Competitive conclusion

### What broad platforms are good at

Platforms such as Aikido can create value by combining many surfaces:

- SAST;
- SCA and dependency risk;
- secret detection;
- IaC and cloud posture;
- container/VM scanning;
- attack-surface discovery;
- runtime protection;
- PR review;
- autofix;
- offensive verification;
- threat intelligence.

Trying to recreate all of those engines inside Sentrdel would violate Principle VII in spirit even if the code were technically permissive.

### What Sentrdel should own instead

Sentrdel's moat should be the security meaning that sits **between** these observations:

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
- whether a separately authorized verifier proved or disproved the claim.

The product must answer questions that raw scanners usually cannot answer deterministically:

> Did this PR weaken tenant isolation?

> Did an ownership guard disappear from the supported path to a mutation?

> Did elevated provider authority become reachable from request-controlled input?

> Did a protected-property mutation become broader?

> Did coverage fall because a formerly supported path became dynamic?

## The Open Semantic Security Graph

The long-term canonical graph should be named explicitly:

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

## First post-R3 product wedge: Semantic PR Regression

After R3 is canonical and post-merge proven, the highest-value product slice should be a **semantic PR regression engine**, not broad provider-pack proliferation.

The engine compares a trusted base graph with a candidate/head graph and reports security-relevant state changes rather than dumping every current observation.

### Required comparison classes

At minimum, future specifications should support evidence-backed states such as:

- `NEW`;
- `PRE_EXISTING`;
- `WORSENED`;
- `MITIGATED`;
- `MOVED`;
- `REINTRODUCED`;
- `UNCERTAIN`;
- `COVERAGE_LOST`;
- `COVERAGE_GAINED`.

These labels must be graph/evidence-diff backed. They must not invent causality merely because two commits are adjacent.

### Example target developer output

A useful PR result should look conceptually like:

```text
SECURITY REGRESSION

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
2. whether it became safer, weaker, or unknown;
3. why Sentrdel believes that;
4. where the evidence came from;
5. what analysis was unsupported;
6. what action is required before merge.

Existing/pre-existing findings may remain accessible without dominating the PR signal.

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

Aikido's product direction reinforces an existing constitutional decision: strong claims become more trustworthy when a separate verifier can reproduce them.

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

Aikido Safe Chain demonstrates the product value of protecting the package-install seam before malicious code executes.

Sentrdel should learn from that adoption pattern, but not copy its implementation into the trusted core.

A later R7/agent-control spec should evaluate a bounded **dependency-action guard** that can protect controllable package/install actions from coding agents and CI. It should prefer existing ecosystem intelligence and qualified package metadata rather than building a proprietary malware-analysis engine first.

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

Aikido Intel illustrates a real moat: continuously refreshed security intelligence can improve detection and prevention faster than static vulnerability databases alone.

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
- benchmark contracts and public corpus portions;
- Security Pack manifests;
- external evidence import contracts;
- local explain output;
- local PR regression analysis;
- rule/pack qualification metadata.

A future hosted service may add collaboration, managed intelligence, fleet policy, storage, or scale, but MUST NOT become required for the core security judgment promised by the open-source project.

## Revised strategic sequencing after R3

Roadmap IDs remain stable; this section describes priority, not permission to bypass active specs.

### P0 — Finish R3 exactly as currently governed

Do not change the canonical `R3-T009 -> ... -> R3-T038` order because of this amendment.

R3 is already building the crucial semantic substrate. Its graph/link/correlation tasks are the foundation for the strategy described here.

### P1 — R5 first productization slice: Semantic PR Regression + Forge integration

After R3 closeout, prioritize the R5 GitHub/forge path that turns SSG base/head comparison into a first-class developer workflow.

R5 should depend on R3 for the semantic regression capability. IDE/agent integrations may follow the same stable local protocol rather than each becoming a new judgment implementation.

### P2 — R9 benchmark expansion for semantic regressions

Before broadening detector/provider support aggressively, freeze benchmark dimensions for:

- semantic regression precision;
- known-ground-truth misses;
- clean-PR false-positive rate;
- coverage-loss visibility;
- provenance completeness;
- deterministic graph-diff replay;
- explanation correctness;
- latency/resource bounds.

### P3 — R6 Evidence Upgrade + Fix Verification

Build bounded verification around a small number of high-value invariant classes before attempting generic autonomous security testing.

### P4 — R4 provider/auth expansion through graph semantics

New packs must improve semantic judgment, not merely add checklist count.

A provider pack should preferentially contribute nodes/relationships/coverage that make cross-layer invariants stronger.

### P5 — R7 external evidence imports + supply-chain/action controls

Broaden security breadth by importing qualified mature evidence and protecting controllable dependency/build seams.

### P6 — R8 runtime evidence correlation

Runtime observations should attach to the same semantic identities where possible and must remain distinguishable from static evidence.

### P7 — R10 full-project semantic posture

R10 becomes the point where application semantics, dependencies, provider posture, CI, agent actions, deployment, and runtime observations converge into the mature SSG-backed project posture.

### P8 — R11 controlled learning/intelligence flywheel

Only after benchmark and verification maturity should Sentrdel automate candidate discovery at scale.

## Roadmap mapping

| Roadmap slice | Strategy contribution after this amendment |
|---|---|
| R1 | Evidence, guard, trusted-head, evaluation, and local judgment foundation |
| R2 | Provider/static posture evidence feeding cross-layer semantics |
| R3 | First application-semantic graph: route x actor x guard x data x invariant |
| R4 | Framework/provider semantic expansion, not shallow rule proliferation |
| R5 | Semantic PR regression, GitHub/forge delivery, IDE/agent presentation |
| R6 | Evidence upgrade, bounded verification, fix validation |
| R7 | External evidence imports, supply-chain/dependency/build security, open intelligence ingestion |
| R8 | Runtime evidence and enforceable runtime tiers |
| R9 | Public semantic-security benchmark and open judgment specifications |
| R10 | Mature SSG-backed A-to-Z project posture |
| R11 | Controlled research/intelligence/learning candidate flywheel |

## Competitive response matrix

| Competitor/platform strength | Sentrdel response |
|---|---|
| Broad scanner aggregation | Import mature evidence; do not rebuild every engine |
| Full-codebase AI PR review | Deterministic semantic PR regression plus optional bounded AI context |
| Reachability graph | Evidence-backed bounded SSG with explicit coverage and authority separation |
| AI pentest validation | R6 bounded opt-in verification; no autonomous exploitation authority |
| Autofix | Candidate remediation + re-analysis + verification before `FIX_VERIFIED` |
| Threat-intelligence feed | Multi-source open intelligence ingestion with provenance and qualification |
| Developer/package interception | Later bounded agent/dependency-action controls at enforceable seams |
| Proprietary platform correlation | Open local-first canonical evidence/graph/judgment contracts |
| Noise reduction | Benchmark precision, change relevance, coverage truth, and reconciler discipline |

## Product principles added by this amendment

These refine the roadmap but do not amend the Constitution:

1. **Security delta over security backlog.** PR workflows prioritize what changed.
2. **Semantic relationships over rule count.** A new detector is valuable when it improves judgment, not because it increases a marketing number.
3. **Coverage loss is a regression.** Moving from supported semantics to unknown/dynamic semantics must be visible.
4. **Graph context never upgrades authority.** Correlation helps reasoning but does not mint proof.
5. **Verification is an evidence upgrade, not a model opinion.**
6. **External engines are evidence producers, not judges.**
7. **Open contracts are distribution.** Evidence, graph, packs, benchmarks, and imports should be inspectable and reusable.
8. **One local trusted core, many optional producers.**
9. **No cloud dependency for core value.**
10. **Developer trust is a release metric.** Precision, latency, explainability, and low false-block rate are security properties.

## What Sentrdel should explicitly not build first

This amendment does not justify near-term work on:

- a generic CSPM platform;
- a full DAST scanner;
- an autonomous pentest swarm;
- endpoint/MDM fleet management;
- a proprietary vulnerability database as a prerequisite for usefulness;
- hundreds of shallow provider rules;
- a universal CPG;
- an LLM-only PR reviewer;
- automatic security-code mutation with self-approval;
- a hosted control plane required for local analysis.

Those may be integrated, imported, or separately specified later where justified.

## Success definition after this amendment

A mature Sentrdel should make the following workflow normal:

```text
coding agent / developer change
        -> bounded local analysis
        -> Semantic Security Graph update
        -> trusted-base vs candidate graph diff
        -> security invariant regression analysis
        -> canonical Evidence + Coverage
        -> reconciled high-signal Finding when justified
        -> explainable PR result
        -> optional separately authorized verification
        -> candidate fix
        -> re-analysis / re-verification
```

The project wins when a developer can ask:

> **"What security property did this change weaken, and can you prove it?"**

and Sentrdel can answer with deterministic provenance, explicit uncertainty, bounded authority, and reproducible evidence.

## Immediate execution boundary

This is a roadmap amendment only.

It MUST NOT modify or bypass the active R3 implementation sequence. As of the planning base, R3 remains the active canonical implementation line. Any implementation implied by this document requires its own future Spec Kit lifecycle and ordinary repository qualification.
