# Source Candidate Assessment — 2026-09-12 Security Control Plane Study

**Status:** RESEARCH_CANDIDATE_ASSESSMENT  
**Sentrdel planning base:** `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`  
**Related roadmap supplement:** `specs/000-sentrdel-roadmap/security-control-plane-expansion-2026-09-12.md`  
**Founder permission statement:** `FOUNDER_ATTESTATION_2026-09-12` — the founder stated that Sentrdel has permission to copy code from the sources supplied for this study.  
**Authority:** Research, provenance, and planning only. This document does **not** qualify source/data/dependencies for reuse, authorize target execution, authorize production scanning, admit provider credentials, or grant implementation authority to any roadmap slice.

## Qualification rule

The founder permission statement is recorded as project-level authorization context, not invented source-specific legal evidence. Sentrdel does not currently store a private permission artifact naming each copyright holder, exact file/ref, commercial/relicensing scope, attribution terms, or sublicensing terms for every source below. Public repository licenses remain independently relevant.

Before copied, ported, vendored, linked, or embedded implementation source lands, the Source Qualification Ledger MUST bind:

- exact repository and full immutable ref;
- exact files/artifacts being reused;
- public license expression and required notices;
- `FOUNDER_ATTESTATION_2026-09-12` plus any available source-specific permission reference;
- integration mode (`NATIVE_RUST_PORT`, `EXTERNAL_ENGINE`, `UI_ONLY`, `REFERENCE_ONLY`, or another frozen mode);
- build/runtime dependencies and privileged surfaces;
- network, credential, filesystem, process, browser, container, and target-mutation authority;
- modifications and Sentrdel-owned replacement boundaries;
- security review and conformance evidence;
- maintenance/freshness and requalification triggers.

Repository-level licensing never proves rights for bundled datasets, third-party samples, PoCs, model weights, container images, exploit payloads, wordlists, templates, or generated artifacts.

## Assessment method

Each source was evaluated for:

1. product/architecture value to Sentrdel's Evidence/Coverage/SSG/invariant-regression moat;
2. exact observed source pin where the research surface exposed one;
3. license and permission risk;
4. dynamic authority and blast radius;
5. opportunities for selective reuse rather than wholesale adoption;
6. whether the source belongs in the trusted Rust core, an external producer, a verification worker, a benchmark/conformance fixture, an optional control plane, or research only;
7. failure/coverage behavior, resumability, evidence provenance, finding lifecycle, and remediation/retest patterns;
8. whether adopting the source would weaken local-first operation or introduce mandatory cloud/model/provider dependencies.

## Summary matrix

| ID | Source | Research pin | License observation | Primary Sentrdel value | Research disposition |
|---|---|---|---|---|---|
| SCP-2026-09-GLITCHTIP | GlitchTip backend / `glitchtip.com` | GitLab `master` displayed `94ce7924` on 2026-09-12; latest stable tag observed `v6.2.6` / `d3039088`; full immutable GitLab SHA MUST be captured before qualification | MIT stated by upstream | runtime error/log/trace/uptime correlation, releases/environments, retention, self-hosted operator UX | `HIGH_PRIORITY_RUNTIME_OBSERVABILITY_REFERENCE` |
| SCP-2026-09-HACKERAI | `hackerai-tech/hackerai` | `d9987f04f59237fdb613e1eaaa232454f982f87e` | Apache-2.0 text **plus commercial-use restrictions** | durable agent runs, sandbox/transport adapters, cancellation/recovery, provider abstraction, UX | `ARCHITECTURE_REFERENCE / SOURCE_REUSE_REQUIRES_SPECIFIC_PERMISSION_RECORD` |
| SCP-2026-09-HACKAGENT | `AISecurityLab/hackagent` | `b160ed13d6a7c66d60fe712374aabe22968a1b13` | Apache-2.0 | agent-security evaluation pipeline, generator/judge/target separation, datasets/reporting | `HIGH_PRIORITY_AGENT_VERIFICATION_AND_CONFORMANCE_REFERENCE` |
| SCP-2026-09-HEXSTRIKE | `0x4m4/hexstrike-ai` | `d689933ff579d839c676c82b231f8e98326c5f04` | MIT | large tool catalog, MCP/tool routing, process/resource/caching/progress patterns | `TOOL_REGISTRY_AND_ORCHESTRATION_REFERENCE_ONLY` |
| SCP-2026-09-SHANNON | `KeygraphHQ/shannon` | `25b90b0611f15ab945e051dfee8ae78600d3a002` | AGPL-3.0 | source→recon→verification pipeline, rules of engagement, resumability, exploit-backed proof, retest | `HIGH_VALUE_VERIFICATION_REFERENCE / COPY_BLOCKED_PENDING_SPECIFIC_RELICENSE_PERMISSION` |
| SCP-2026-09-HACKBOT | `yashab-cyber/hackbot` | `613a0c9d356f67dc7957eadcc67de105f9833b20` | MIT | finding lifecycle, assessment diff, campaigns, plugin/tool registry, reporting, safe-mode UX | `LIFECYCLE_AND_OPERATOR_UX_REFERENCE` |
| SCP-2026-09-STRIX | `usestrix/strix` | `95e085eb6ce29c72ff84313b012cd2c9e9c1cfe5` | Apache-2.0 | multi-agent orchestration, sandboxed dynamic testing, coverage discipline, proof artifact linkage, skills | `HIGH_PRIORITY_PROOF_AND_VERIFICATION_REFERENCE` |

## SCP-2026-09-GLITCHTIP — GlitchTip

### Observed source identity

The founder supplied `https://glitchtip.com`. The implementation project identified during research is the GlitchTip backend on GitLab (`glitchtip/glitchtip-backend`). The GitLab project page displayed `master` at short ref `94ce7924` on 2026-09-12 and described the backend as MIT. The tag page displayed stable `v6.2.6` at short ref `d3039088`.

Because the available research interface exposed only abbreviated GitLab refs, **neither short hash is an acceptable source-copy qualification pin**. A future qualification MUST resolve and record the full immutable commit SHA before any code reuse.

### Capabilities observed

GlitchTip is a self-hostable Sentry-compatible operational-observability platform with:

- error/issue tracking;
- release and environment context through Sentry-compatible SDKs;
- transaction/span performance monitoring;
- logs correlated to traces/issues;
- uptime/heartbeat monitoring;
- alerts and integrations;
- CLI and MCP access;
- PostgreSQL hot storage with optional cold-storage patterns;
- privacy-oriented self-hosting and lightweight deployment.

Its installation guidance defaults private/internal IP uptime targets off to reduce SSRF risk. Its logs/performance docs expose trace correlation and explicit retention/sampling concerns.

### What Sentrdel should learn

Sentrdel needs a future **Operational Evidence Bridge**, not a GlitchTip clone. The high-value pattern is to attach runtime errors, traces, logs, health checks, deployments, and release/environment identity to the same stable revision/SSG/invariant vocabulary used during development.

Runtime observations can corroborate or contradict static expectations, but must not retroactively rewrite static FACT records or independently create canonical Findings.

### Preferred boundary

```text
decision: HIGH_PRIORITY_RUNTIME_OBSERVABILITY_REFERENCE
source_copy_authorized_by_this_record: NO
preferred_integration:
  - standards-first telemetry/event import;
  - Sentry-compatible envelope import where useful;
  - OTLP-compatible runtime bridge where separately specified;
  - optional self-hosted control-plane UI only after core protocols are stable.
trusted_core_dependency: NO
network_ingest_in_base_cli: NO
default_private-target_uptime: DENY
```

## SCP-2026-09-HACKERAI — HackerAI

### Exact research pin

```text
repository: hackerai-tech/hackerai
exact_ref: d9987f04f59237fdb613e1eaaa232454f982f87e
head_date_observed: 2026-09-11
```

### License boundary

The observed LICENSE contains Apache-2.0 text plus additional terms prohibiting commercial use without a separate commercial license. Sentrdel MUST NOT describe this as ordinary Apache-2.0. The founder's permission statement is useful authorization context, but direct source reuse remains blocked until a source-specific permission/relicense record is stored and reconciled with the exact files being copied.

### Capabilities observed

HackerAI separates:

- Next.js UI/HTTP;
- Convex persisted state;
- Trigger.dev durable agent tasks;
- cloud/local sandbox transports, including E2B;
- shared model streaming logic;
- multiple model/search providers;
- cancellation/retry/reconnect and cross-transport recovery concerns;
- privacy-safe product analytics and rollout discipline.

### What Sentrdel should learn

High-value patterns are **durable run state**, **transport adapters**, **sandbox abstraction**, **cancellation/recovery**, **provider isolation**, and **explicit operational measurement**. Sentrdel should not inherit HackerAI's cloud service dependencies, model keys, or application stack into the base installation.

### Preferred boundary

```text
decision: ARCHITECTURE_REFERENCE
source_copy_authorized_by_this_record: NO
specific_permission_record_required: YES
base_cloud_dependency: NO
base_provider_key_requirement: NO
preferred_reuse:
  - independently authored durable-run contract;
  - sandbox transport interface;
  - cancellation/recovery semantics;
  - optional UI patterns only after exact qualification.
```

## SCP-2026-09-HACKAGENT — HackAgent

### Exact research pin

```text
repository: AISecurityLab/hackagent
exact_ref: b160ed13d6a7c66d60fe712374aabe22968a1b13
head_date_observed: 2026-09-09
license_observed: Apache-2.0
```

### Capabilities observed

HackAgent models agent-security testing as a pipeline with distinct roles:

- Attack Engine;
- Generator;
- Judge;
- Target Agent;
- dataset/benchmark inputs;
- local reporting/storage plus optional cloud sync;
- support for multiple agent/model frameworks.

Threat families include prompt injection, jailbreak, goal hijacking, and tool misuse.

### What Sentrdel should learn

This is a useful methodology for a later **Agent Security Verification Profile** and SentrdelBench cases. Sentrdel should preserve role separation so an attack generator cannot define its own success condition. An LLM judge remains `INFERENCE/HYPOTHESIS`; stronger verdicts require deterministic assertions or separately authorized execution evidence.

### Preferred boundary

```text
decision: HIGH_PRIORITY_AGENT_VERIFICATION_AND_CONFORMANCE_REFERENCE
normal_review_dynamic_attacks: NO
external_engine_possible: YES_AFTER_QUALIFICATION
judge_authority: INFERENCE_ONLY
target_scope: OWNED_OR_EXPLICITLY_AUTHORIZED_ISOLATED_TARGETS_ONLY
```

## SCP-2026-09-HEXSTRIKE — HexStrike AI

### Exact research pin

```text
repository: 0x4m4/hexstrike-ai
exact_ref: d689933ff579d839c676c82b231f8e98326c5f04
head_date_observed: 2026-08-03
license_observed: MIT
```

### Capabilities observed

HexStrike exposes a large MCP-driven catalog of security tools, decision/orchestration logic, specialized agents, process management, caching, resource optimization, error recovery, progress visualization, and extensive network/web/cloud/binary/OSINT tooling.

A substantial part of that catalog has exploitation, credential attack, brute-force, post-exploitation, or high-impact reconnaissance capability.

### What Sentrdel should learn

Sentrdel needs a **Tool Capability Registry** that can safely describe many external engines without granting them ambient authority. The registry should capture tool identity/version/digest, typed argv schema, output contract, required network/filesystem/credential/target-mutation privileges, resource limits, determinism, sandbox requirement, and epistemic ceiling.

Sentrdel must **not** inherit an autonomous tool-selection/exploitation loop into ordinary review.

### Preferred boundary

```text
decision: TOOL_REGISTRY_AND_ORCHESTRATION_REFERENCE_ONLY
copy_wholesale_tool_catalog: NO
autonomous_exploitation: NO
ordinary_review_external_execution: NO
future_verification_tools: ALLOWLISTED_PER_TOOL_AFTER_QUALIFICATION
```

## SCP-2026-09-SHANNON — Shannon

### Exact research pin

```text
repository: KeygraphHQ/shannon
exact_ref: 25b90b0611f15ab945e051dfee8ae78600d3a002
head_date_observed: 2026-09-08
license_observed: AGPL-3.0
```

### Capabilities observed

Shannon combines source analysis with live reconnaissance/exploitation and reports only exploitation-backed vulnerabilities. Useful architecture/product patterns include:

- source analysis before dynamic testing;
- candidate reconciliation/deduplication before verification;
- authenticated testing and rules-of-engagement configuration;
- resumable workspaces;
- CI/CD artifacts and explicit distinction between incomplete scans and completed clean scans;
- SARIF/report output;
- staging/development emphasis and explicit warnings against production use;
- remediation/retest concepts in the broader platform.

### License and safety boundary

The public repository is AGPL-3.0. Direct copying/linking into Sentrdel's permissive trusted core is prohibited absent a documented, source-specific permission/relicense basis that actually covers the selected files and intended distribution. The founder attestation alone is not substituted for missing terms.

Shannon explicitly performs live exploitation and can mutate target state. This conflicts with Sentrdel's default static/local review boundary and may only inform a separately authorized R6 verification tier.

### Preferred boundary

```text
decision: HIGH_VALUE_VERIFICATION_REFERENCE
source_copy_authorized_by_this_record: NO
specific_relicense_permission_required: YES_FOR_PERMISSIVE_CORE_COPY
normal_review_target_execution: NO
preferred_reuse:
  - rules-of-engagement contract ideas;
  - resumable run/workspace model;
  - incomplete-vs-clean semantics;
  - proof-backed verification and point-retest methodology.
```

## SCP-2026-09-HACKBOT — HackBot

### Exact research pin

```text
repository: yashab-cyber/hackbot
exact_ref: 613a0c9d356f67dc7957eadcc67de105f9833b20
head_date_observed: 2026-07-07
license_observed: MIT
```

### Capabilities observed

HackBot combines agent/chat/planning modes with:

- persistent vulnerability database and remediation status;
- diff reports across assessments;
- multi-target campaigns;
- plugin/tool registry;
- reports and dashboards;
- CVE/OSINT/topology/compliance/ATT&CK views;
- HTTP proxy and traffic capture;
- remediation generation;
- safe-mode confirmation patterns;
- multi-provider model abstraction.

### What Sentrdel should learn

The best fit is not its exploit-generation features. The strongest gap signal is Sentrdel's need for an explicit **Finding Lifecycle + Remediation Workflow** and eventually a portfolio/campaign view. Finding creation remains reconciler-only, but once created it needs ownership, acknowledgement, risk acceptance, fix-candidate, retest, verified closure, reopen, stale, and suppression history.

### Preferred boundary

```text
decision: LIFECYCLE_AND_OPERATOR_UX_REFERENCE
finding_creation_authority: SENTRDEL_RECONCILER_ONLY
agent_generated_fix_authority: UNTRUSTED_CANDIDATE_ONLY
future_campaign_execution: REQUIRES_RULES_OF_ENGAGEMENT_AND_VERIFICATION_TIER
```

## SCP-2026-09-STRIX — Strix

### Exact research pin

```text
repository: usestrix/strix
exact_ref: 95e085eb6ce29c72ff84313b012cd2c9e9c1cfe5
head_date_observed: 2026-09-10
license_observed: Apache-2.0
```

### Capabilities observed

Strix combines multi-agent pentesting with Docker isolation, browser/proxy/terminal/Python tools, static and dynamic analysis, skills, CI/CD, reporting, remediation, and proof-of-concept validation.

At the exact research pin, reporting state includes `http_exchange_ids`, and the agent reporting guidance requires proxy-validated findings to retain the HTTP request IDs that prove them. This is directly aligned with Sentrdel's Evidence Before Verdict architecture.

### What Sentrdel should learn

The strongest transferable pattern is **proof artifact identity**: verification evidence should bind to immutable request/response exchanges, browser captures, process/test records, or other concrete artifacts instead of a prose claim that an exploit succeeded.

Strix also reinforces:

- coverage accounting before a run is considered complete;
- specialist skill loading rather than one giant prompt/tool surface;
- remediation followed by retest;
- local run artifacts and operator-visible progress.

The autonomous exploitation loop is outside ordinary Sentrdel authority.

### Preferred boundary

```text
decision: HIGH_PRIORITY_PROOF_AND_VERIFICATION_REFERENCE
proof_artifact_pattern: ADOPT_CONCEPTUALLY
external_engine_possible: YES_AFTER_QUALIFICATION
autonomous_exploitation_in_core: NO
skills_as_trusted_instruction: NO
```

## Cross-source conclusions

### Highest-value contribution by Sentrdel domain

| Sentrdel domain | Strongest source signal | Design consequence |
|---|---|---|
| Runtime/operational correlation | GlitchTip | Build standards-first Operational Evidence Bridge; correlate release/env/trace/log/error/uptime without granting runtime telemetry Finding authority |
| Durable security-agent work | HackerAI, Shannon | Freeze run/workspace/checkpoint/cancellation/recovery contracts independent of any cloud worker vendor |
| Agent-security testing | HackAgent | Separate generator/judge/target; benchmark deterministic outcomes; dynamic tests only in authorized isolation |
| Tool breadth | HexStrike, HackBot | Build typed Tool Capability Registry instead of hard-coding a giant shell-command catalog |
| Rules of engagement | Shannon | Make authorized target/scope/mutation/network budgets machine-readable before dynamic verification |
| Proof provenance | Strix, Shannon | Require immutable proof artifact references; distinguish baseline and candidate exchanges; do not accept prose-only success |
| Finding lifecycle | HackBot, GlitchTip, Shannon platform patterns | Add ownership/triage/risk/fix/retest/reopen history while preserving reconciler-only Finding creation |
| Skills/packs | Strix | Signed/versioned/capability-declared Security Packs; no ambient instruction authority |
| Self-hosted operator UX | GlitchTip, HackBot, Strix | Optional control plane over stable local protocols; base CLI remains useful without server/account/cloud |

### Shared anti-patterns Sentrdel must not inherit

Sentrdel must not become:

- a mandatory cloud SaaS;
- an LLM-required security judge;
- a generic shell executor for security tools;
- an autonomous exploitation bot;
- a scanner whose `clean` result hides crashed/skipped tools;
- a platform where external severity/confidence becomes canonical Finding authority;
- a system where source-code text can instruct the security agent to widen its permissions;
- a framework that stores provider credentials or production secrets in ordinary evidence;
- a mega-runtime that requires Python, Node, Docker, browsers, and dozens of scanners for the base installation;
- a UI/database fork whose value is scanner count rather than Sentrdel judgment.

## Additional mature references identified by the gap review

These are **references/import candidates only**; no founder permission statement is assumed for them by this document.

### OpenTelemetry / OTLP

Use as the primary standards reference for future traces, logs, metrics, resources, service/deployment identity, and collector interoperability. OTLP should be preferred over inventing a Sentrdel-only telemetry transport. Imported telemetry remains runtime observation until reconciled.

### DefectDojo

Use as a vulnerability-management workflow reference for import/reimport, deduplication, finding triage, risk acceptance, SLAs, asset/engagement context, connectors, and reporting. Do not reproduce hundreds of bespoke scanner parsers if Sentrdel's generic producer/import contracts can cover them.

### Sigstore / Cosign / in-toto

Use as a supply-chain attestation reference for signed Security Packs, external-engine images/binaries, benchmark artifacts, release evidence, and provenance bundles. Cryptographic validity proves integrity/identity under a trust policy; it does not prove security correctness.

### Falco

Use as a future optional runtime producer reference for Linux syscall/plugin events. Sentrdel should import bounded runtime observations and correlate them through stable identities rather than embedding a privileged kernel/eBPF runtime in the base installation.

### Existing mature scanner ecosystem

Continue the current standards-first approach for Semgrep/Opengrep, CodeQL, Trivy, Syft/Grype, Gitleaks, Checkov/Terrascan, OSV-compatible advisories, Nuclei/ZAP and comparable engines: prefer qualified external evidence or bounded verification adapters over rebuilding mature raw detection capability.

## Source-reuse priority

Direct source copying is **not** the first objective. The recommended order is:

1. freeze Sentrdel-owned contracts from the demonstrated patterns;
2. benchmark independently authored implementations;
3. reuse standards/protocols where available;
4. integrate external engines behind typed boundaries;
5. selectively port/copy implementation only when it materially reduces risk/effort and exact qualification is complete;
6. preserve attribution/notices and modification history;
7. requalify on source ref, license, dependency, model, ruleset, network behavior, or privileged-surface changes.

## Final research decision

The source study supports expanding Sentrdel into a **security control plane** that spans development, bounded verification, deployment, runtime, remediation, and re-verification while preserving the Rust judgment core.

It does **not** support changing Sentrdel's category into an autonomous pentesting platform. The defensible product remains the system that knows what changed, what security property is at risk, what evidence exists, what coverage is missing, what was actually verified, what happened after deployment, and whether the remediation was truly proven.