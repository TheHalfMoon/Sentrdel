# Sentrdel Competitive Triangulation — 2026-09-02

**Status:** STRATEGIC_RESEARCH_INPUT  
**Planning base:** `main@f4c72f1fdf9a6d817c2349578d3cd7993aeacd8a`  
**Related amendment:** `strategic-amendment-2026-09-02-semantic-security-graph.md`  
**Authority:** Research and roadmap reasoning only. This document does not override the Constitution, active Spec Kit artifacts, or task ordering.

## Purpose

The first 2026-09-02 strategic pass used Aikido Security as a primary product reference. A second pass compared the proposed Sentrdel strategy against Semgrep, Endor Labs, Socket, XBOW, and GitHub Code Security.

The result is a necessary correction:

> **Graph analysis, diff-aware PR scanning, AI review, reachability, agent policy, package firewalls, autofix, and proof-oriented pentesting are individually no longer sufficient moats.**

Sentrdel must compete at a more specific layer.

The strongest defensible category is:

> **Open, deterministic security-invariant regression with explicit evidence, coverage, authority, and conformance contracts.**

The Sentrdel Semantic Security Graph is the substrate. The product is the invariant/security-property judgment built on top of it.

## Research inputs

Observed on 2026-09-02 from current official product/documentation surfaces:

- Semgrep AppSec Platform and pricing: `https://semgrep.dev/products/semgrep-appsec-platform/`, `https://semgrep.dev/pricing/`
- Endor Labs platform and reachability documentation: `https://www.endorlabs.com/`, `https://docs.endorlabs.com/scan/sca/reachability-analysis`
- Socket behavior-based security: `https://socket.dev/glossary/behavior-based-security`
- XBOW result interpretation and validation: `https://docs.xbow.com/console/guidance/interpreting-results/`
- GitHub Code Security / Advanced Security: `https://github.com/security/advanced-security/code-security`, `https://docs.github.com/en/code-security/responsible-use/security-and-quality-ai-features`
- Aikido references recorded in `strategic-amendment-2026-09-02-semantic-security-graph.md`

Vendor performance claims remain vendor claims, not Sentrdel benchmark truth.

## Market reality by capability

### Diff-aware PR scanning is not a moat

Semgrep explicitly supports diff-aware scans focused on current changes and combines that workflow with cross-file analysis and AI triage/remediation.

Therefore Sentrdel cannot differentiate by merely saying:

> "We only show new PR findings."

The differentiator must be **what changed semantically about a security property**, not merely whether an alert is new.

### Graph/reachability is not a moat

Endor Labs performs function/dependency reachability and describes call-graph-based analysis. Other AppSec platforms increasingly use code graphs, data flow, repository context, or reachability to reduce noise.

Therefore Sentrdel cannot differentiate by merely saying:

> "We have a graph."

The graph matters only if it enables an open, deterministic, auditable security judgment competitors do not expose as a stable contract.

### Agent-action policy is not a moat by itself

Endor Labs currently positions coding-agent action policy as an explicit product surface: agent actions may be allowed, blocked, or escalated to a human and recorded. Other products are also moving toward developer/device/package interception.

Therefore Sentrdel's agent guard remains strategically important but cannot be the entire category definition.

Sentrdel's differentiator is that agent actions participate in the same canonical Evidence/authority model as source, dependency, provider, invariant, and later runtime observations.

### Package firewall/interception is not a moat by itself

Aikido Safe Chain and Endor Labs package-firewall positioning demonstrate that install-time dependency control is becoming an established product category. Socket performs deep behavior-oriented package analysis.

Sentrdel should integrate/package this evidence and protect controllable agent/build seams later, but should not spend its near-term roadmap rebuilding a malware-analysis laboratory.

### Autofix is not a moat

GitHub CodeQL + Copilot Autofix, Semgrep AI remediation, Aikido AutoFix, and other platforms already provide automated fix suggestions.

Sentrdel should treat remediation as a candidate artifact, then differentiate through:

- deterministic re-analysis;
- invariant regression comparison;
- explicit proof state;
- bounded verification;
- `FIX_VERIFIED` only when execution evidence exists.

### Proof-oriented offensive validation is not a moat

Aikido and XBOW both emphasize validation/reproduction before high-confidence offensive findings are reported.

Sentrdel should preserve its safe-verification architecture, but its core category should not be "AI pentesting." The open-source trusted core remains non-autonomous and local-first.

## Moat correction

The 2026-09-02 strategy should use the following hierarchy.

### Layer 1 — Open canonical evidence and coverage contracts

Sentrdel's first defensible asset is a strict representation of:

- what was directly observed;
- what was deterministically inferred;
- what remains a hypothesis;
- what was verified by separately authorized execution;
- what contradicts another observation;
- what analysis was unavailable, partial, unsupported, failed, or exceeded a resource cap.

This is more important than owning every scanner.

### Layer 2 — Open bounded semantic graph

The SSG links security-relevant identities across code and later other surfaces without pretending to be a universal compiler/CPG.

Its value is not node count. Its value is stable security semantics and provenance.

### Layer 3 — Security invariant engine

Sentrdel should own inspectable invariant families such as:

- actor/tenant/resource binding;
- role/privilege authorization;
- protected-property mutation;
- elevated-provider-authority boundaries;
- later payment/webhook/state-transition invariants;
- later agent/action and deployment invariants.

This is the key judgment layer.

### Layer 4 — Security Invariant Regression Engine

This is the primary post-R3 product moat.

Instead of only asking whether a finding exists, compare the trusted base and candidate and ask:

- Was a required guard removed or weakened?
- Did a request-controlled value gain a path to a protected operation?
- Did elevated authority become reachable from a lower-trust entry point?
- Did an invariant move from `SATISFIED` to `UNKNOWN`?
- Did analysis coverage disappear because code became dynamic?
- Did a supposedly fixed invariant become violated again?

The result is a **security-property delta with an evidence chain**, not a generic PR alert.

### Layer 5 — Open conformance benchmark

R9 should become more than an internal benchmark.

A long-term Sentrdel moat should be a public conformance corpus/spec that can test whether:

- a producer emits valid Evidence;
- coverage is honest;
- semantic identities are deterministic;
- invariant results match frozen ground truth;
- graph diff classifies regressions correctly;
- an importer preserves authority ceilings;
- a remediation actually removes the invariant violation without introducing another supported regression.

If third-party tools can emit Sentrdel-compatible Evidence and pass the conformance suite, Sentrdel can become a security interoperability standard rather than only an executable.

### Layer 6 — Local no-build/no-target-execution default

Endor's most precise reachability modes may require successful builds/call-graph generation. Sentrdel's current R3 deliberately avoids target builds, package-manager execution, repository helpers, provider access, and runtime execution.

That constraint should be treated as a product advantage for the default review path:

- fast startup;
- lower authority;
- safer use on untrusted/AI-generated repositories;
- reproducible static evidence;
- fewer environmental side effects.

Optional higher-authority verification may exist later through a separate R6 boundary.

## Defensibility filter for future roadmap proposals

Before adding a major feature, future specs should answer these questions:

1. **Does this strengthen Sentrdel's invariant/evidence judgment layer, or merely duplicate a mature scanner?**
2. **Could a broad commercial AppSec platform add the same feature as a checkbox without adopting Sentrdel's open evidence/authority model?** If yes, it is probably not core moat.
3. **Does the feature improve semantic regression precision, coverage truth, or verification?**
4. **Can the capability be imported as external Evidence instead of rebuilt?**
5. **Does it create a reusable open contract, benchmark, pack, or conformance asset?**
6. **Can it remain useful locally without a proprietary cloud?**
7. **Does it preserve fail-visible uncertainty rather than turning unsupported analysis into PASS?**
8. **Does it create a new authority surface that deserves a separate spec?**

A feature that fails this filter should normally be deferred or integrated externally.

## Revised killer demo

The first post-R3 public demo should not be:

> "Sentrdel found an SQL injection."

CodeQL, Semgrep, and many tools already demonstrate that category well.

The demo should show one or more invariant regressions that are understandable without security expertise.

### Demo A — Tenant isolation regression

```text
BASE
GET /org/:org_id/invoices
  actor = authenticated user
  guard = user.organization_id == request.org_id
  data = invoices where organization_id == request.org_id
  invariant = SATISFIED

PR
GET /org/:org_id/invoices
  actor = authenticated user
  guard = removed from supported path
  data = invoices where organization_id == request.org_id
  invariant = VIOLATED or UNKNOWN according to proven semantics

SENTRDEL
WORSENED: tenant isolation security property changed in this PR
```

### Demo B — Elevated provider authority regression

A normal user route begins using a service-role/elevated Supabase client after a refactor. R2 provider authority and R3 application semantics combine to show the new cross-layer risk.

### Demo C — Protected-property regression

A previously allowlisted update becomes a broad request-object mutation containing protected fields.

### Demo D — Coverage regression

A supported direct ownership check is replaced with an unresolved dynamic helper. Sentrdel reports `COVERAGE_LOST`/`UNKNOWN`, not "secure".

This fourth demo is strategically important because it demonstrates Sentrdel's honesty rather than only its detection ability.

## PR product contract direction

The post-R3 R5 specification should prioritize the following order:

1. trusted base selection and validation;
2. deterministic base/head SSG projection;
3. invariant-state diff;
4. coverage-state diff;
5. Evidence/Finding reconciliation;
6. compact PR summary;
7. `sentrdel explain` proof chain;
8. optional forge annotations/checks;
9. optional AI-generated explanation/remediation as non-authoritative assistance.

The semantic comparison must be usable without an LLM.

## R9 conformance direction

R9 should eventually publish at least four artifact classes:

1. **Evidence conformance fixtures** — validate producer/import semantics and authority ceilings.
2. **Invariant fixtures** — safe/unsafe/unknown/adversarial expected semantic results.
3. **Regression-pair fixtures** — frozen base/head repositories with expected `NEW/WORSENED/MITIGATED/COVERAGE_LOST/...` outcomes.
4. **Verification fixtures** — claims with bounded executable proof/contradiction where separately authorized.

Protected holdouts remain necessary for release qualification and must not be exposed to candidate-generation logic.

## Ecosystem strategy

The strongest open-source flywheel is:

```text
framework/provider adapters
        +
external evidence importers
        +
open Evidence/SSG schemas
        +
public invariant corpus
        +
conformance tooling
        +
local PR regression engine
        ->
community integrations and packs
        ->
more semantic coverage
        ->
stronger benchmark/evidence ecosystem
```

This is harder for a closed platform to neutralize than a list of scanner features because the interoperability contracts themselves become the community asset.

## Competitive positioning after triangulation

### Aikido

Reference for broad developer-first AppSec, full-context PR review, integrated validation/retesting, threat intelligence, and package-install protection.

### Semgrep

Reference for fast developer workflow, diff-aware scans, cross-file analysis, rules, supply-chain reachability, and AI-assisted triage/remediation.

### Endor Labs

Direct strategic competitor for agent security, code/dataflow analysis, dependency reachability, package firewall, and developer-risk reduction. Its current positioning proves that "agent guard + reachability + package firewall" cannot be Sentrdel's unique category.

### Socket

Reference for behavior-based package/supply-chain analysis. Prefer interoperability over rebuilding this expertise first.

### GitHub Code Security

Reference for native forge distribution, CodeQL semantic analysis, dependency review, security campaigns, and Copilot Autofix. Sentrdel must remain forge-neutral and prove value beyond a GitHub-only workflow.

### XBOW

Reference for offensive proof and explicit assessment-gap reporting. Sentrdel should preserve proof/coverage discipline while keeping verification bounded and non-autonomous by default.

## Final strategic statement

After market triangulation, the intended category should be stated precisely:

> **Sentrdel is the open-source security-invariant regression and evidence judgment engine for AI-built software.**

The SSG is how it understands the project.

Evidence and Coverage are how it remains honest.

Invariants are how it expresses the security property that matters.

Trusted-base semantic regression is how it becomes indispensable in every PR.

Verification is how stronger claims become proven.

Open contracts and conformance are how it becomes an ecosystem rather than another scanner.
