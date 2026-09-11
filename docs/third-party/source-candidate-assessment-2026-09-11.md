# Source Candidate Assessment — 2026-09-11 Security Platform Study

**Status:** RESEARCH_CANDIDATE_ASSESSMENT  
**Sentrdel planning base:** `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`  
**Related roadmap supplement:** `specs/000-sentrdel-roadmap/security-platform-study-2026-09-11.md`  
**Authority:** Research/provenance and roadmap input only. This record does **not** authorize implementation, copy donor source into Sentrdel, vendor dependencies, import datasets/images, execute target systems, access credentials, enable network scanning, or perform autonomous exploitation. Any source reuse still requires the exact qualification required by the Constitution, `AGENTS.md`, and `docs/third-party/source-qualification-ledger.md`.

## Founder reuse attestation

On 2026-09-11 the founder stated that Sentrdel has permission to copy code from the sources named in this assessment. Sentrdel records that statement for planning purposes as:

`FOUNDER_ATTESTATION_2026-09-11_SECURITY_PLATFORM_SOURCES`

This is a founder attestation, not invented source-owner documentation. The repository does not currently store source-specific private permission evidence identifying the granting owner, exact ref/files, license override if any, attribution terms, redistribution scope, or commercial-use scope for every source below. Public repository licenses remain independently applicable. Before copied or ported implementation code lands, a qualification record MUST bind the exact upstream repository/ref/files, permission basis, applicable license/notice obligations, modifications, dependency/build/runtime authority, security review, and requalification triggers.

No donor implementation source is copied by this assessment.

## Assessment method

Each source was evaluated against Sentrdel's current category and trust model using:

- exact upstream default-branch commit where GitHub provided it;
- repository license observation;
- product and architecture documentation;
- representative implementation seams where they materially clarified sandbox/runtime behavior;
- fit with Sentrdel Evidence, Coverage, SSG, invariant-regression, verification and runtime-evidence strategy;
- build/runtime/dependency/network/credential authority;
- whether reuse should be native code, an optional external engine, a protocol/import adapter, a benchmark reference, a UX reference, or research only;
- whether the source strengthens Sentrdel's judgment moat or merely increases scanner/tool count.

Repository-level licensing is not treated as proof that every embedded dataset, template, model, container image, exploit sample, third-party tool, generated artifact or copied upstream file has identical reuse rights.

## Summary matrix

| ID | Source | Research pin | License observation | High-value lesson | Research decision |
|---|---|---|---|---|---|
| SRC-2026-09-HACKERAI | `hackerai-tech/hackerai` | `054a16464999c2a9f649d745dd44684e9f468d9d` | Apache-2.0 text with additional commercial restrictions; treat as non-standard/restricted unless separate permission terms are documented | durable agent runs; sandbox provider/health/recovery seams; resource-pressure telemetry | `SANDBOX_AND_DURABLE_RUN_REFERENCE` |
| SRC-2026-09-HACKAGENT | `AISecurityLab/hackagent` | `b160ed13d6a7c66d60fe712374aabe22968a1b13` | Apache-2.0 | modular generator/target/judge pipeline; AI-agent security benchmark adapters; local run reporting | `AI_AGENT_SECURITY_CONFORMANCE_REFERENCE` |
| SRC-2026-09-HEXSTRIKE | `0x4m4/hexstrike-ai` | `d689933ff579d839c676c82b231f8e98326c5f04` | MIT | large tool registry; process/resource/error-management patterns; live progress UX | `TOOL_CAPABILITY_AND_PROCESS_MANAGEMENT_REFERENCE` |
| SRC-2026-09-SHANNON | `KeygraphHQ/shannon` | `25b90b0611f15ab945e051dfee8ae78600d3a002` | AGPL-3.0 at repository level | sealed resumable run state; reconciliation/checkpoints; incomplete-vs-clean distinction; evidence-rich SARIF/reporting | `RESUMABLE_VERIFICATION_AND_REPORTING_REFERENCE` |
| SRC-2026-09-HACKBOT | `yashab-cyber/hackbot` | `613a0c9d356f67dc7957eadcc67de105f9833b20` | MIT | finding database/lifecycle; assessment diff; campaigns; plugin UX; ATT&CK/compliance-derived views | `FINDING_LIFECYCLE_AND_WORKBENCH_REFERENCE` |
| SRC-2026-09-STRIX | `usestrix/strix` | `95e085eb6ce29c72ff84313b012cd2c9e9c1cfe5` | Apache-2.0 | digest-bound source authorization; pluggable per-run sandboxes; explicit run completeness/budgets; structured local artifacts | `VERIFICATION_AUTHORIZATION_AND_RUN_COMPLETENESS_REFERENCE` |
| SRC-2026-09-GLITCHTIP | GlitchTip official backend/frontend on GitLab + `glitchtip.com` | GitLab backend `master` short SHA `94ce7924` observed 2026-09-11; stable `v6.2.6` short SHA `d3039088`; full exact Git object not established by this record | backend MIT; exact frontend/file-level qualification still required before reuse | Sentry-compatible error/log/CSP/performance/uptime ingestion; local-first operational telemetry | `RUNTIME_TELEMETRY_INGEST_REFERENCE` |

## SRC-2026-09-HACKERAI — HackerAI

### Observed architecture

At the research pin, HackerAI presents a cloud-assisted AI penetration-testing assistant with durable Agent mode. Its documented runtime combines a Next.js application, Convex persistence, Trigger.dev durable tasks, cloud/local sandbox transports, model-provider adapters and file/storage services.

Representative implementation seams show useful operational discipline:

- sandbox-provider resolution rejects unsupported provider values instead of silently choosing an unknown backend;
- sandbox tools are explicitly identified as environment-bound capabilities;
- a sandbox manager tracks readiness/health failures and marks the environment unavailable after a bounded failure count;
- recovery can drop/rebuild a client connection without indiscriminately killing a shared underlying sandbox;
- the codebase separates sandbox identity, command options, readiness failures, fallback behavior, file transfer and resource-pressure analytics;
- agent guidance requires checking cancellation, retry and reconnect behavior across transports rather than assuming one successful backend proves another.

### Why it fits Sentrdel

The useful lesson is not HackerAI's cloud stack or pentest behavior. It is the **execution-environment contract** around long-running agent work.

Future Sentrdel verification can benefit from:

- explicit verifier-runtime backend identity;
- capability-to-runtime mapping;
- bounded readiness/retry state;
- visible unavailable/degraded state;
- cleanup/reconnect semantics;
- resource-pressure metrics;
- durable run ownership without granting the runtime judgment authority.

### Explicit non-adoption

Sentrdel MUST NOT inherit:

- a proprietary-cloud requirement for the base product;
- ambient model/provider credentials;
- unrestricted terminal authority;
- remote browsing/search as an implicit analysis dependency;
- provider-selection logic that can widen Sentrdel authority;
- any mechanism intended to route around model-provider cyber safeguards.

### Planning decision

```text
decision: SANDBOX_AND_DURABLE_RUN_REFERENCE
source_copy_authorized_by_this_record: NO
runtime_dependency_authorized: NO
cloud_dependency_authorized: NO
credential_mode_authorized: NO
autonomous_attack_authorized: NO
preferred_future_boundary:
  - independently specify a Rust-owned VerificationRun contract;
  - qualify sandbox providers separately behind a narrow runtime interface;
  - make readiness/retry/cleanup/resource state observable Coverage/diagnostic input;
  - retain local-first operation and no ambient credential inheritance.
```

## SRC-2026-09-HACKAGENT — HackAgent

### Observed architecture

HackAgent is an AI-agent security red-team toolkit. Its documented pipeline separates an attack/generation stage, target adapter, evaluator/judge and datasets, with framework adapters and local reporting. It focuses on prompt injection, jailbreaking, goal hijacking and tool misuse.

### Why it fits Sentrdel

The valuable pattern is **role separation**, not attack automation. Sentrdel can invert the pipeline into a defensive verification/conformance architecture:

`candidate hypothesis/evidence -> bounded verifier -> deterministic evidence normalizer -> Sentrdel reconciler -> Finding/verification state`

An LLM may help generate hypotheses or test cases, but it MUST remain structurally unable to mint `FACT`, `VERIFIED` or canonical Finding authority.

HackAgent also reinforces the need for future SentrdelBench profiles covering:

- prompt/instruction authority confusion;
- tool misuse/capability mismatch;
- indirect prompt injection;
- memory/context poisoning;
- adapter/provider variation;
- deterministic evaluator independence from the generator.

### Explicit non-adoption

Do not import an automated jailbreak/attack engine into the trusted core. Dynamic adversarial testing, if ever used, belongs only in an explicitly authorized isolated verification tier and remains bounded by target ownership, network policy, resource limits and evidence authority.

### Planning decision

```text
decision: AI_AGENT_SECURITY_CONFORMANCE_REFERENCE
source_copy_authorized_by_this_record: NO
attack_runtime_authorized: NO
llm_judge_authority: NONE
preferred_future_boundary:
  - use modular target/verifier adapter ideas for conformance and bounded verification;
  - keep generators and judges outside canonical epistemic authority;
  - prefer independently authored Sentrdel fixtures before adopting donor attack datasets.
```

## SRC-2026-09-HEXSTRIKE — HexStrike AI

### Observed architecture

HexStrike presents an MCP-oriented cybersecurity automation platform with a large catalog of external security tools, multiple specialized agents, process management, caching/resource controls and real-time visualization. Its public architecture also includes autonomous attack-chain discovery and exploit-oriented agents.

### Why it fits Sentrdel

Sentrdel should study the **tool registry and process-management plane**, not the autonomous offensive logic.

A future Sentrdel `ToolCapabilityManifest` should be stronger than a generic tool name. It should declare at minimum:

- exact tool/binary/container/source identity and digest;
- input/output protocol and schema version;
- deterministic/probabilistic classification;
- filesystem read/write scope;
- process-spawn authority;
- network destination policy;
- browser authority;
- credential/secret requirements;
- target-mutation/side-effect class;
- timeout, memory, CPU and output limits;
- cleanup behavior;
- evidence/coverage authority ceiling;
- qualification/revocation state.

Tool selection may decide **which qualified producer/verifier runs**; it may not upgrade the truth of that producer's result.

### Explicit non-adoption

Sentrdel MUST NOT adopt autonomous attack-chain discovery, exploit generation, credential harvesting, brute-force/post-exploitation workflows, or a blanket "all installed tools are agent-callable" model.

### Planning decision

```text
decision: TOOL_CAPABILITY_AND_PROCESS_MANAGEMENT_REFERENCE
source_copy_authorized_by_this_record: NO
external_tool_bundle_authorized: NO
autonomous_attack_authorized: NO
preferred_future_boundary:
  - Rust-owned capability manifests and admission policy;
  - per-run least-authority tool binding;
  - external output remains untrusted Evidence;
  - explicit failure/timeout/cap state becomes Coverage/diagnostic truth.
```

## SRC-2026-09-SHANNON — Shannon

### Observed architecture

Shannon combines source analysis, candidate reconciliation, live testing, report finalization and CI delivery. Its repository contains explicit run/workspace state, report checkpoints, finalization manifests and resume logic. The public documentation distinguishes incomplete assessments from completed scans with no findings and emits evidence-rich PDF/Markdown/JSON/SARIF outputs.

The repository-level license is AGPL-3.0. The founder attestation above does not create an invented alternative license grant. Any copied source would require exact source-specific permission documentation or compliance with the applicable public license. Clean-room design/reference or a qualified external-process boundary remains the conservative default.

### Why it fits Sentrdel

The strongest transferable pattern is **sealed resumability**:

- a resumed run must preserve the original run contract;
- checkpoint/finalization state must be coherent with the run that produced it;
- report publication should be idempotent and manifest-bound;
- incomplete, failed, cancelled or ambiguous runs must remain distinguishable from complete clean runs.

Sentrdel should freeze these semantics before long-running verification becomes normal.

A `VerificationRun` resume MUST fail closed when any security-relevant contract field changes, including target snapshot digest, verifier identity, verification profile, authorization scope, network policy, credential policy, resource budget, tool capability set or evidence schema.

### Explicit non-adoption

Sentrdel MUST NOT adopt Shannon's autonomous exploitation model or "exploit required for report" as the general judgment rule. Sentrdel intentionally preserves static FACT/INFERENCE, Coverage and contradiction states even when stronger verification is unavailable.

### Planning decision

```text
decision: RESUMABLE_VERIFICATION_AND_REPORTING_REFERENCE
source_copy_authorized_by_this_record: NO
agpl_code_in_permissive_core_authorized: NO
live_exploitation_authorized: NO
preferred_future_boundary:
  - sealed VerificationRun + CheckpointManifest contracts;
  - idempotent finalization and explicit incomplete/cancelled/ambiguous states;
  - SARIF/report export derived from canonical Sentrdel judgment, never vice versa.
```

## SRC-2026-09-HACKBOT — HackBot

### Observed architecture

HackBot exposes a broad desktop/CLI security assistant with a persistent SQLite vulnerability database, assessment diff reports, multi-target campaigns, plugin management, remediation tracking, ATT&CK/compliance mappings, reports and a graphical workbench. It also includes active/offensive features that are outside Sentrdel's ordinary authority.

### Why it fits Sentrdel

Sentrdel already has a stronger semantic basis than a generic "new/fixed/persistent vulnerability" diff. The useful lesson is the **developer workbench and lifecycle layer** around canonical results.

Future Sentrdel product UX should support a durable lifecycle without weakening authority:

- canonical Finding/regression identity;
- first-seen/last-seen/trusted-base/candidate history;
- remediation candidate state;
- separately proven fix-verification state;
- suppression/risk-acceptance record with author, reason, scope and expiry;
- reopen/regression state;
- links to Evidence, Coverage and verification runs;
- derived ATT&CK/compliance mappings clearly labeled as mappings, not proof;
- portfolio/campaign grouping that never merges authorization or coverage across targets.

### Explicit non-adoption

Do not adopt "zero-day exploit chain" automation, credential attack workflows, unrestricted proxy replay or autonomous remediation/merge authority into the trusted core.

### Planning decision

```text
decision: FINDING_LIFECYCLE_AND_WORKBENCH_REFERENCE
source_copy_authorized_by_this_record: NO
autonomous_exploitation_authorized: NO
auto_merge_authority: NO
preferred_future_boundary:
  - local-first workbench over canonical Sentrdel records;
  - lifecycle events are auditable and cannot rewrite historical Evidence;
  - compliance/ATT&CK are derived views with explicit provenance.
```

## SRC-2026-09-STRIX — Strix

### Observed architecture

Strix is an autonomous pentesting system with Docker-based local execution, pluggable runtime backends, per-run shell/filesystem capabilities, structured run artifacts and CI/cloud modes. Its agent guide contains several operational safeguards that map well to defensive verification design:

- an exit code indicating "clean" is not sufficient to claim complete coverage; run status and budget consumption must also be inspected;
- local runs persist a structured run record plus findings/report/SARIF artifacts;
- cloud source uploads support a dry-run manifest followed by digest-bound approval, and reject a changed source snapshot;
- uploads and source selection use explicit file/expanded/compressed-size caps;
- ambiguous launch or cleanup outcomes remain explicit rather than being blindly retried;
- runtime backends are pluggable, and shell/filesystem capabilities are bound to a live sandbox session per run.

### Why it fits Sentrdel

These patterns directly strengthen Sentrdel's Evidence Before Verdict principle:

1. **Run completeness is separate from outcome.** A verifier that found nothing may still be incomplete, capped, failed or partially authorized.
2. **Authorization should bind an exact snapshot digest.** Human or policy approval for one source/target snapshot must not silently apply after the snapshot changes.
3. **Ambiguous launch/cleanup is a real state.** Unknown side effects or unclear execution state must remain visible.
4. **Capabilities are per-run.** A verifier receives only the tools/files/network/credentials its exact profile permits.

### Explicit non-adoption

Do not import the autonomous pentest/exploit graph, unrestricted shell/browser authority, cloud credential model or post-exploitation behavior.

### Planning decision

```text
decision: VERIFICATION_AUTHORIZATION_AND_RUN_COMPLETENESS_REFERENCE
source_copy_authorized_by_this_record: NO
autonomous_exploitation_authorized: NO
preferred_future_boundary:
  - digest-bound authorization receipts;
  - explicit RunCompleteness state independent of findings;
  - pluggable but separately qualified sandbox backends;
  - bounded per-run capabilities and resource budgets;
  - explicit launch/cleanup uncertainty.
```

## SRC-2026-09-GLITCHTIP — GlitchTip

### Source observation

GlitchTip is an open-source Sentry-compatible operational telemetry platform. Official project material describes error tracking plus performance, uptime and logs. Error intake includes exceptions/log messages and CSP violations. The backend is MIT-licensed and self-hostable.

The official backend is hosted on GitLab rather than GitHub. At research time, GitLab exposed backend `master` at short SHA `94ce7924` and stable tag `v6.2.6` at short SHA `d3039088`; this record does not pretend those short identifiers are a complete immutable source qualification. Full Git object identity, selected files, NOTICE obligations and frontend/license details must be resolved before any source reuse.

The backend's own agent guidance also emphasizes clean-room compatibility with Sentry: Sentry-compatible behavior must not justify reading or copying non-open server code. That discipline is compatible with Sentrdel's source-governance model.

### Why it fits Sentrdel

GlitchTip is valuable primarily as a **runtime evidence ingestion reference**, not as code Sentrdel should fork into an observability product.

Future R8 runtime evidence can consume qualified telemetry such as:

- exceptions/errors;
- security-relevant logs;
- CSP violation events;
- route/transaction timing and selected performance anomalies;
- uptime/heartbeat observations;
- deployment/release identifiers;
- sanitized runtime tags useful for SSG correlation.

A Sentry-compatible intake adapter is attractive because many existing SDKs can emit the data without requiring a proprietary service. However, runtime telemetry remains `RUNTIME_OBSERVATION` or equivalent Evidence, not a repository FACT and not automatic causality proof.

### Explicit non-adoption

Sentrdel should not become a general APM/error-tracking replacement. It should not ingest secrets/raw user content by default, and it must freeze redaction, sampling, retention, tenant binding, replay/dedup, event size and cardinality limits before runtime telemetry can affect security posture.

### Planning decision

```text
decision: RUNTIME_TELEMETRY_INGEST_REFERENCE
source_copy_authorized_by_this_record: NO
exact_source_pin_complete: NO
runtime_telemetry_authority: RUNTIME_OBSERVATION_ONLY
preferred_future_boundary:
  - versioned runtime-evidence adapter, preferably compatible with open Sentry SDK envelopes where justified;
  - local/self-hosted first;
  - strict redaction, retention, cardinality and resource caps;
  - correlate to stable SSG identities only when provenance is sufficient.
```

## Cross-source conclusions

### What Sentrdel should own

The study reinforces that Sentrdel's defensible core is not "more offensive agents" or "more bundled scanners." It should own:

1. canonical Evidence, Coverage, invariant, regression and verification contracts;
2. exact run/target/tool identity and provenance;
3. a Rust-owned judgment/reconciliation layer;
4. explicit RunCompleteness and uncertainty;
5. bounded authorization and least-authority capability manifests;
6. trusted-base/candidate semantic security regression;
7. verification evidence upgrades that cannot erase weaker or contradictory evidence;
8. runtime-to-static correlation through stable SSG identities;
9. deterministic developer/CI/reporting contracts;
10. open conformance that lets external engines prove they obey Sentrdel authority boundaries.

### What Sentrdel should normally reuse/import

Prefer qualified external engines or protocol-compatible adapters for:

- generic SAST/DAST/tool execution;
- browser automation;
- vulnerability/advisory databases;
- SBOM/SCA/IaC/secret scanners;
- error/log/performance/uptime collection;
- PDF/report rendering;
- generic sandbox infrastructure;
- model-based attack generation or classification when separately justified.

Their output remains untrusted input until canonical validation and reconciliation.

### What Sentrdel should explicitly reject as a product direction

The research does not justify:

- autonomous exploitation of third-party or production systems;
- attack-chain discovery as canonical judgment authority;
- unrestricted shell/browser/network access for agents;
- bundling hundreds of offensive tools into the base installation;
- LLM judge output as verified truth;
- "no exploit = no issue" as a general epistemic rule;
- cloud/provider credentials as a base requirement;
- scanner count as a success metric;
- plugins/packs with ambient process/network/secret authority;
- silent retry after ambiguous execution/cleanup;
- calling a partial/capped/failed run clean.

## Source-reuse sequencing

If implementation later chooses to reuse donor code, qualify the smallest useful source surface in this order:

1. prefer protocol/data-contract ideas that can be independently implemented;
2. prefer permissively licensed, narrowly bounded utility code over whole runtimes;
3. prefer external-process/container adapters when a donor runtime would expand the Rust trusted base;
4. require exact file/ref/license/NOTICE/modification records before copying;
5. require a capability and side-effect inventory for any executable donor path;
6. require tests proving the donor cannot mint Sentrdel authority or turn failure into PASS;
7. require a requalification delta for version, features, model, container, rules, dataset, license, network behavior or credential-scope changes.

The founder attestation is preserved, but no source enters Sentrdel merely because this research record found it useful.
