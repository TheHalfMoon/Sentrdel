# Developer Review Distribution Study — 2026-09-16

**Status:** `PRODUCT_WORKFLOW_RESEARCH / NO IMPLEMENTATION AUTHORITY`  
**Purpose:** study current developer-review distribution patterns and security-review baselines so Sentrdel can become a developer-native security reviewer without copying another product's trust model.  
**Scope:** public product/workflow behavior only; no implementation source is admitted by this document.

## 1. Product question

Sentrdel's security architecture is not enough by itself. A developer security reviewer becomes widely adopted only when it is available where developers already work, starts with minimal friction, produces useful feedback quickly, and earns trust through stable semantics rather than marketing claims.

The question for this study is:

> What workflow properties make a review product easy to adopt, and which security-review capabilities are already baseline expectations that Sentrdel must meet or integrate without surrendering canonical judgment?

## 2. Official public references observed

Observed on 2026-09-16:

### CodeRabbit

- IDE product page: `https://www.coderabbit.ai/ide`
- CLI announcement: `https://www.coderabbit.ai/blog/coderabbit-cli-free-ai-code-reviews-in-your-cli`
- Cursor plugin announcement: `https://www.coderabbit.ai/blog/coderabbit-plugin-for-cursor`

Observed workflow characteristics:

- review is available before a pull request inside the editor;
- review is also available in pull requests;
- CLI review supports local developer workflows;
- structured/agent-oriented CLI usage is treated as a first-class integration path;
- findings can be handed to coding agents for remediation while the review product remains a distinct reviewer;
- the same product category is distributed across several developer surfaces instead of requiring developers to leave their normal workflow.

Sentrdel adoption lesson:

> Distribution is part of the product contract, not a post-launch integration backlog.

This study does **not** adopt CodeRabbit model output, grouping, line relocation, reflection, or severity as Sentrdel security authority. Existing Sentrdel/OpenCodeReview planning remains controlling for those boundaries.

### GitHub Code Security / Secret Protection

Official references:

- `https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security`
- `https://docs.github.com/en/code-security/getting-started/quickstart-for-securing-your-repository`
- `https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review`

Observed baseline capabilities include code scanning, dependency review, secret scanning/push protection, and remediation assistance in supported product tiers/surfaces.

Sentrdel lesson:

> Developer security review cannot differentiate merely by having a scanner. It must unify change accounting, evidence, coverage, policy, regression, explanation, and bounded verification while remaining compatible with mature scanner/security outputs.

## 3. Product principles derived from the study

### 3.1 Meet developers where they work

The long-term Sentrdel surface set should converge toward:

```text
local CLI
  -> GitHub reference integration
  -> coding-agent handoff
  -> IDE integration
  -> GitLab/other forge adapters
  -> optional organization/control-plane views
```

These are delivery surfaces over one local security-review protocol, not separate judgment implementations.

### 3.2 First useful result must be cheap to obtain

A developer should not need to:

- create a hosted account to run local review;
- configure a cloud model;
- provision a server;
- select scanners manually;
- understand Sentrdel's internal Evidence/Coverage/SSG architecture;
- read logs to know whether review was complete.

Default local review should be useful with repository truth plus admitted built-in capabilities. Additional integrations deepen the result but cannot redefine what `COMPLETE`, a Finding, or a verified claim means.

### 3.3 Review and remediation are separate authorities

Coding agents may receive structured remediation context, propose patches, or explain findings. The agent that writes a change does not become the final authority that the change is safe.

Required loop:

```text
change
 -> Sentrdel review
 -> developer/agent remediation proposal
 -> changed revision identity
 -> fresh Sentrdel review/reuse validation
 -> optional bounded verification
 -> merge decision
```

### 3.4 Quiet does not mean hidden

A trusted review product should avoid noisy inline comments, but comment suppression must not become Finding suppression.

Sentrdel should distinguish:

- canonical result existence;
- inline annotation eligibility;
- summary visibility;
- advisory prioritization;
- notification policy.

Every canonical blocking result remains machine-readable and discoverable even when not emitted as a separate inline comment.

### 3.5 Trust comes from inspectability

Every developer-facing conclusion should make it possible to answer:

- what changed?
- what was reviewed?
- what was not reviewed?
- why is this result important?
- what exact evidence supports it?
- what scope/blast radius is affected?
- what authority produced the claim?
- can I reproduce/explain it locally?
- what must change before the result can become merge-ready?

## 4. Competitive non-goals

Sentrdel should not try to win by:

- claiming a larger scanner count;
- copying generic AI-review comments;
- turning all advisories into blocking security findings;
- requiring hosted inference for the core path;
- hiding uncertainty to make the UI look cleaner;
- replacing CodeQL, Semgrep, OSV, Syft, Trivy, Gitleaks, or other mature producers when bounded import/integration is stronger;
- becoming a forge-specific bot whose semantics do not exist locally.

## 5. Differentiated Sentrdel category

Recommended product category:

> **Agentic Software Security Review**

Recommended product promise:

> **Security review for every change.**

Longer positioning:

> Sentrdel is the evidence-first security reviewer for human- and AI-generated software changes. It proves what was reviewed, what security property changed, what evidence supports the result, what remains unknown, and whether stronger verification actually occurred.

This positioning is deliberately narrower than "all cybersecurity" and broader than "AI SAST."

## 6. Planning implications

This study supports the following roadmap changes:

1. Developer adoption/trust becomes a first-class product contract, not a final UI phase.
2. S2B must freeze the local developer experience, machine protocol, explainability, remediation handoff, zero-config behavior, diagnostics, and performance expectations.
3. S3 must ship one excellent GitHub reference experience before broad forge proliferation.
4. Agent and IDE integrations consume the same local protocol and cannot create stronger judgment.
5. S4 conformance must test semantic equivalence across surfaces and also product-quality properties such as noise, actionability, annotation quality, and time to first useful result.
6. Local usage should not require a hosted account or cloud model.
7. Open-source/public adoption should be treated as a product distribution mechanism, while optional hosted/enterprise layers remain projections over the local core.

## 7. Authority boundary

```text
PRODUCT_WORKFLOW_RESEARCH
  != SOURCE_QUALIFIED
  != IMPLEMENTATION_AUTHORIZED
  != SECURITY_AUTHORITY
```

Public product behavior is evidence for planning only. No external product claim, model output, integration, or workflow pattern can override Sentrdel's Constitution, active Spec Kit, Evidence/Coverage/Findings authority, completeness rules, or verification authorization.