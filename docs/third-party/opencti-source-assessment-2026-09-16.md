# OpenCTI Source Assessment — 2026-09-16

**Status:** RESEARCH_CANDIDATE_ASSESSMENT  
**Sentrdel planning base:** `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`  
**Research repository:** `OpenCTI-Platform/opencti`  
**Research pin:** `c22668461981ac9602e8e16527ef613428c34c3c`  
**Observed backend package version:** `7.260914.0`  
**Permission context:** `FOUNDER_ATTESTATION_2026-09-16_OPENCTI`  
**Related roadmap:** `specs/000-sentrdel-roadmap/opencti-intelligence-interoperability-2026-09-16.md`  
**Authority:** Research, provenance, architecture, and planning only. This document grants no implementation authority and does not alter active Spec 004 task ordering.

## Executive conclusion

OpenCTI is a high-value architecture and UX reference for the future Sentrdel control plane, but Sentrdel should **not** become an OpenCTI clone and should not import OpenCTI's full runtime stack into the trusted local base.

The highest-value lessons are:

1. a provenance-rich knowledge graph for external context;
2. STIX 2.1 / TAXII interoperability;
3. typed connector roles and asynchronous ingestion;
4. analyst workbench staging before publication;
5. explicit source reliability and confidence metadata;
6. investigations/cases as collaborative projections over canonical knowledge;
7. data markings, sharing policy, and least-privilege access controls;
8. event streams and filtered data sharing;
9. inference rules with visible provenance;
10. automation/playbooks separated from ordinary read/write workflows;
11. strong source attribution and relationship-rich exploration;
12. horizontal scaling patterns for an optional server mode.

Sentrdel should translate these ideas into its own security-evidence authority model:

> **External threat intelligence enriches context; it never creates a canonical Finding, upgrades proof state, authorizes a target, or widens execution authority by itself.**

## Source and license boundary

The OpenCTI repository is mixed-license at the research pin.

Observed repository policy:

- Community Edition: Apache License 2.0;
- Enterprise Edition: OpenCTI Enterprise Edition License;
- files/directories may carry explicit Enterprise Edition headers;
- repository files without the Enterprise Edition indication are described by upstream as Community Edition under Apache-2.0.

The repository contains clearly marked Enterprise Edition code, including enterprise-specific backend/frontend areas and features. Therefore:

```text
source_copy_policy:
  community_apache_files: EXACT_FILE_QUALIFICATION_REQUIRED
  enterprise_files: COPY_BLOCKED_UNLESS_SPECIFIC_COMPATIBLE_PERMISSION_IS_STORED
  mixed_or_unknown_files: COPY_BLOCKED_PENDING_CLASSIFICATION
  architecture_patterns: REFERENCE_ALLOWED
  protocol_interoperability: PREFERRED_WHERE_STANDARDS_EXIST
```

The founder's permission statement is durable project context, not a substitute for exact file-level qualification or missing Enterprise Edition permission evidence.

## What OpenCTI is architecturally

OpenCTI is a cyber-threat-intelligence platform centered on a STIX 2.1-oriented knowledge graph. Its platform exposes a GraphQL API and web application, stores/searches knowledge through Elasticsearch/OpenSearch, uses Redis, RabbitMQ, and S3-compatible object storage, and scales writes through standalone workers. Its integration ecosystem uses connectors for import, enrichment, file import/export, and stream processing.

This is a capable server architecture, but it is intentionally heavier than Sentrdel's local-first Rust base. Sentrdel should preserve that distinction.

### OpenCTI pattern

```text
UI / GraphQL API
      |
      +--> knowledge/search storage
      +--> Redis
      +--> object storage
      +--> RabbitMQ --> workers
      |
      +--> connectors / feeds / streams
```

### Preferred Sentrdel translation

```text
Rust trusted judgment core
      |
      +--> stable local protocol/event journal
      |
      +--> optional control-plane projection
               |
               +--> optional database/search/object storage
               +--> qualified import/connectors
               +--> filtered streams/sharing
```

The optional server may scale independently later. It must not become required for local review, canonical Evidence/Coverage/Finding judgment, policy, regression, or deterministic replay.

## Capability study and Sentrdel disposition

### 1. STIX 2.1 knowledge graph

OpenCTI structures cyber-threat knowledge as entities and relationships based on STIX 2.1 concepts and uses graph exploration as a primary analyst workflow.

**Sentrdel value:** high.

Sentrdel already has a bounded Semantic Security Graph (SSG), but the SSG is optimized for software security semantics rather than general threat intelligence. The correct improvement is not to replace the SSG with STIX. Instead, add a future **External Intelligence Context Graph** or equivalent bounded projection that can reference Sentrdel identities without redefining them.

Recommended mapping principles:

- `Vulnerability` / CVE context may support Evidence, but does not become a Finding by import alone.
- `Indicator` / `Observable` objects remain external intelligence observations until independently correlated.
- `AttackPattern` can enrich technique/taxonomy context.
- `Identity`, `Infrastructure`, `Malware`, `Tool`, `Campaign`, and similar objects remain contextual external knowledge.
- STIX relationships remain producer-attributed relationships; they do not silently become exact SSG semantic facts.
- STIX IDs are external stable identifiers, not automatically trusted Sentrdel identities.
- imported intelligence must preserve source, confidence/reliability, marking, timestamps, and transformation provenance.

**Disposition:** `HIGH_PRIORITY_INTEROPERABILITY_REFERENCE`.

### 2. STIX/TAXII import, export, and live sharing

OpenCTI supports STIX-based exchange, TAXII collections, live streams, CSV feeds, and filtered data sharing.

**Sentrdel value:** high after the generic external-evidence import boundary exists.

A future Sentrdel adapter should support bounded security-intelligence interchange without requiring STIX internally.

Minimum future requirements:

- strict bundle/object/depth/string/relationship count caps;
- deterministic parser normalization;
- unsupported STIX object types remain visible diagnostics;
- external source identity and exact fetch/import run identity;
- producer timestamp versus Sentrdel ingestion timestamp separation;
- marking and sharing metadata preservation;
- duplicate/conflict handling without silent overwrite;
- no remote fetch in base offline mode;
- tokens stored only as secret references, never in Evidence;
- network fetch endpoints subject to SSRF/rebinding/redirect policy;
- import failure, truncation, stale cursor, and partial page state remain visible Coverage/diagnostics;
- exported context must respect project/tenant/marking policy.

**Disposition:** `FUTURE_STIX_TAXII_ADAPTER_AFTER_S6`.

### 3. Connectors

OpenCTI connectors are a strong example of a decentralized integration model. Different connector classes ingest, enrich, import/export files, or consume streams. Connectors authenticate through dedicated platform credentials and can be separated operationally from the core platform.

**Sentrdel value:** very high as a design reference for its existing future Evidence Producer / Import Adapter and Runtime Telemetry Adapter classes.

Sentrdel should improve the connector concept with stricter security contracts:

- connector/adapter ID, version, digest, publisher, license, qualification state;
- declared input/output schema;
- exact capability manifest;
- network/filesystem/process/credential requirements;
- source scopes/endpoints;
- redaction/classification behavior;
- retry/checkpoint/cursor semantics;
- output caps;
- authority ceiling;
- dedicated service identity;
- per-adapter secret references;
- explicit revocation/requalification.

A connector must not receive a generic all-powerful token merely because it integrates with the control plane.

**Disposition:** `HIGH_PRIORITY_ADAPTER_LIFECYCLE_REFERENCE`.

### 4. Analyst workbench

OpenCTI workbenches allow data to be manipulated before official import/publication.

**Sentrdel value:** extremely high.

This pattern solves a future Sentrdel problem: external intelligence, runtime imports, scanner results, or manually supplied artifacts may be useful but ambiguous, conflicting, oversized, incorrectly scoped, or untrusted.

A future **Sentrdel Intake Workbench** should stage imported material before it can affect durable project context.

Workbench semantics should include:

- raw import run identity;
- normalized candidate objects;
- parser warnings/errors;
- unsupported relationships;
- duplicates/conflicts;
- source/reliability/confidence/marking;
- proposed links to Asset/Deployment/Finding/Incident/SSG identities;
- analyst accept/reject/merge decisions with provenance;
- immutable original digest where retention policy allows;
- explicit statement that workbench acceptance does not bypass reconciler-only Finding creation.

**Disposition:** `HIGH_PRIORITY_CONTROL_PLANE_UX_PATTERN`.

### 5. Reliability and confidence

OpenCTI models source reliability and confidence separately from the underlying data.

**Sentrdel value:** high if authority separation is preserved.

Sentrdel needs a future vocabulary for:

- producer reliability history;
- source confidence;
- transformation confidence;
- correlation confidence;
- exact/attested/ambiguous/unmapped identity strength.

These metadata must remain distinct from Sentrdel epistemic authority:

```text
source_reliability != FACT
producer_confidence != VERIFIED
high_confidence_intelligence != canonical_Finding
low_confidence_intelligence != discard
```

**Disposition:** `ADOPT_SEPARATE_METADATA_MODEL`.

### 6. Inference and reasoning

OpenCTI can infer new relationships through rules and visibly distinguish inferred relationships.

**Sentrdel value:** high, with stricter authority semantics.

Sentrdel should preserve a relationship derivation record containing:

- rule identity/version;
- exact input relationship/object IDs;
- output relationship;
- timestamp;
- deterministic or probabilistic class;
- confidence where applicable;
- invalidation/recompute state.

A derived relation must never silently become a stronger epistemic class than its rule permits. External/inference relationships cannot establish stable semantic identity or a Finding unless the canonical Sentrdel contract explicitly allows the required evidence path.

**Disposition:** `ADOPT_VISIBLE_DERIVATION_PROVENANCE`.

### 7. Investigations and graph workspaces

OpenCTI supports analyst investigations that pivot through the knowledge graph and can be privately staged/shared.

**Sentrdel value:** high for the optional operator surface.

A future **Investigation Workspace** should allow analysts/developers to collect and pivot across:

- Findings;
- Evidence;
- Coverage gaps;
- SSG nodes/edges;
- Assets/services/APIs;
- deployments/releases;
- runtime observations;
- operational incidents;
- proof artifacts;
- external intelligence objects;
- remediation/retest records.

A workspace is a projection/collection, not a truth authority. Adding or removing an item from a workspace cannot create/delete underlying canonical security records.

**Disposition:** `HIGH_PRIORITY_OPERATOR_UX_REFERENCE`.

### 8. Case management

OpenCTI cases organize incident response, requests for information, takedown workflows, tasks, context, and collaboration.

**Sentrdel value:** high for later operational workflows.

Sentrdel should generalize this into bounded **Security Case** semantics rather than copy OpenCTI's CTI-specific case taxonomy wholesale.

Potential case classes:

- Security Regression Investigation;
- Verification Campaign;
- Operational Incident;
- Remediation Program;
- Supply-Chain Qualification Review;
- Security Exception / Risk Acceptance Review.

Case membership never changes Finding truth, Evidence authority, or verification status. State transitions need actor/time/reason provenance.

**Disposition:** `ADOPT_CASE_PROJECTION_LATER`.

### 9. RBAC, markings, authorized sharing, and organization segmentation

OpenCTI combines roles/capabilities, marking access, organizations, and authorized-member restrictions. Some organization-segregation functionality is Enterprise Edition.

**Sentrdel value:** very high conceptually, but implementation must be independently specified and file/license qualified.

Sentrdel needs a future `DataHandlingMarking` / `DisclosurePolicy` model for sensitive security data such as:

- exploit proof;
- source snippets;
- secret-adjacent evidence;
- runtime telemetry;
- customer/tenant incidents;
- proprietary source metadata;
- vulnerability embargo information.

Principles:

- access control and security truth are separate;
- marking controls who may view/export/share a record, not whether the record is true;
- object-level restrictions must be explicit and auditable;
- export/stream filters must apply marking/tenant/project rules;
- no “system” bypass identity should be used for ordinary connectors;
- service accounts should be least-privilege and adapter-specific;
- cross-tenant denial tests are release gates.

**Disposition:** `HIGH_PRIORITY_SECURITY_CONTROL_PLANE_PATTERN / EE_CODE_COPY_REQUIRES_SPECIFIC_PERMISSION`.

### 10. Native feeds and streams

OpenCTI provides filtered live streams and TAXII/CSV sharing with access-control semantics.

**Sentrdel value:** high for team/server mode.

A future Sentrdel event/data sharing layer should be built over an immutable/bounded event journal and stable object IDs. Consumers may filter by:

- tenant/project/repository;
- object/event class;
- severity/lifecycle state;
- producer/source;
- asset/environment;
- marking/classification;
- time/cursor.

Streams are delivery mechanisms, not a separate source of canonical truth.

**Disposition:** `ADOPT_FILTERED_EVENT_STREAM_CONTRACT`.

### 11. Playbooks / automation

OpenCTI playbooks demonstrate useful event-driven automation and execution traces. The observed playbook feature is Enterprise Edition.

**Sentrdel value:** high only after the capability/authorization model is mature.

A future Sentrdel automation engine must be more constrained than a generic workflow runner:

- typed trigger;
- typed condition;
- typed action;
- action capability manifest;
- exact target/project/tenant scope;
- secret reference scope;
- budget/rate/expiry;
- deterministic audit trail;
- dry-run/simulation where possible;
- fail-visible partial execution;
- no arbitrary shell action;
- no Finding creation shortcut;
- no verification/runtime-response authorization derived from an automation rule alone.

**Disposition:** `LATE_STAGE_PATTERN_ONLY / NO CURRENT IMPLEMENTATION AUTHORITY`.

### 12. Dashboards and sharing

OpenCTI's dashboards and public sharing demonstrate useful analyst-facing projections and controlled publication.

**Sentrdel value:** medium-high.

Future dashboards should include:

- invariant regression trends;
- coverage regression;
- open/fixed/reopened Findings;
- verification proof state;
- accepted-risk expiry;
- deployment/runtime contradictions;
- asset/project posture;
- adapter/pack/source qualification health;
- data freshness and intelligence-source coverage.

A published dashboard must be a snapshot/projection with explicit redaction/marking policy, never an alternate data store.

**Disposition:** `OPTIONAL_CONTROL_PLANE_UX_REFERENCE`.

### 13. Storage and horizontal scaling

OpenCTI's Elastic/OpenSearch + Redis + RabbitMQ + S3 architecture is optimized for a large multi-user CTI server with high ingestion volume.

**Sentrdel value:** architectural reference, not a base dependency plan.

Do **not** make these services mandatory for Sentrdel local mode. A later server may use equivalent technologies when demonstrated scale requirements justify them, but canonical contracts must stay storage-agnostic.

**Disposition:** `REFERENCE_ONLY_FOR_OPTIONAL_SERVER_SCALE`.

## Product improvements derived from the study

### Improvement A — External Intelligence Context Bridge

Add a future adapter class for STIX 2.1/TAXII and other structured intelligence. Imported objects are contextual Evidence/intelligence records with explicit source/marking/confidence—not Findings.

### Improvement B — Intelligence/Import Workbench

Create a staging surface before external context is promoted into durable project relationships.

### Improvement C — Data Handling Markings

Add classification/disclosure metadata that controls display/export/streaming without altering truth authority.

### Improvement D — Investigation Workspace

Allow graph-based pivoting across security evidence, runtime, assets, external intelligence, and lifecycle records.

### Improvement E — Security Cases

Add collaborative operational containers that link canonical objects without mutating them.

### Improvement F — Producer Reliability + Confidence

Track producer/source reliability and confidence independently from epistemic class and verification state.

### Improvement G — Filtered Security Event Streams

Expose bounded team/server streams over canonical event/object projections with tenant/project/marking enforcement.

### Improvement H — Connector Service Identity

Each integration gets a dedicated service identity, secret scope, capability manifest, and explicit revocation/requalification state.

### Improvement I — Derived Relationship Provenance

Every inferred/correlated external relationship remains visibly derived with rule/provenance/authority metadata.

### Improvement J — Bounded Automation

Later add typed event-driven automation only after action/authorization contracts are canonical.

## Gaps OpenCTI exposes in the current Sentrdel roadmap

This study adds the following planning gaps after G42 in the 2026-09-12 blueprint.

### G43 — No security-intelligence interoperability boundary

Sentrdel has external analyzer/runtime import plans but no explicit contract for CTI/intelligence objects, STIX 2.1/TAXII, or intelligence-source provenance.

**Required correction:** freeze a bounded external-intelligence envelope and STIX/TAXII adapter profile after the generic S6 importer exists.

### G44 — Data handling and disclosure markings are not first-class

Tenant/project RBAC alone is insufficient for embargoed vulnerabilities, sensitive proof, runtime data, and cross-organization sharing.

**Required correction:** define `DataHandlingMarking` / disclosure semantics independently from security truth.

### G45 — External imports lack a human staging/workbench state

Directly mapping imported intelligence into durable context can create hidden conflicts or mistaken identity joins.

**Required correction:** add a bounded workbench lifecycle for normalization, conflict review, proposed links, acceptance/rejection, and provenance.

### G46 — Investigation/workspace semantics are absent

Operators need a temporary collaborative graph/pivot surface without mutating canonical records.

**Required correction:** define `InvestigationWorkspace` as a projection/collection with explicit access and audit semantics.

### G47 — Case collaboration is underspecified

Finding lifecycle alone does not model multi-record investigations, incidents, verification campaigns, or remediation programs.

**Required correction:** add a case container that links canonical records without inheriting their authority.

### G48 — Source reliability/confidence and epistemic authority are not explicitly separated

Future intelligence sources need reliability/confidence metadata, but those values could be accidentally treated as proof.

**Required correction:** freeze separate reliability/confidence/correlation fields and tests proving they cannot mint FACT/VERIFIED or canonical Findings.

### G49 — Filtered data sharing/stream semantics are incomplete

The roadmap has events and an optional control plane but does not yet freeze filtered stream/export behavior under tenant/project/marking rules.

**Required correction:** define cursoring, replay, filter, marking, authorization, revocation, and redaction semantics for server-mode streams/feeds.

### G50 — Connector service identity and least privilege need stronger semantics

`ToolCapabilityManifest` handles execution capabilities, but long-running import/runtime integrations also need durable service identity, token/secret scope, rotation, and revocation.

**Required correction:** define `IntegrationServiceIdentity` linked to adapter manifest, source scope, secret references, and audit records.

### G51 — Derived graph relationships need explicit provenance/invalidations

As external intelligence and runtime correlation grow, rule-derived edges could be mistaken for directly observed semantic facts.

**Required correction:** every derived relationship requires derivation identity, inputs, rule/version, authority ceiling, timestamps, and recompute/invalidation state.

### G52 — Automation authority could bypass the trusted control plane

A future playbook engine could become a generic privilege escalation path.

**Required correction:** automation must compose only pre-authorized typed actions and cannot create its own verification/response authority or arbitrary shell execution.

## Recommended source-reuse posture

### Prefer protocol/idea reuse over code copy when standards already exist

Prefer independent Sentrdel implementations for:

- STIX 2.1 mapping;
- TAXII 2.1 client/server adapter contracts;
- generic RBAC/capability semantics;
- markings/disclosure model;
- Sentrdel-native graph and event contracts.

This reduces coupling to OpenCTI's Node/Python/server architecture and mixed licensing.

### Candidate selective code reuse after exact qualification

Community Edition Apache-2.0 files may be considered selectively for:

- parsing/normalization edge-case logic;
- filtering/query UX patterns;
- graph/investigation UI interaction patterns;
- connector lifecycle/manifest patterns;
- STIX relationship handling tests/fixtures where their own data licenses permit;
- import/workbench UX mechanics;
- stream/cursor handling patterns.

Every exact file still requires qualification, attribution, security review, and a decision that direct reuse is better than a smaller Rust-native implementation.

### Do not copy by default

- Enterprise Edition files without a stored compatible source-specific permission record;
- OpenCTI's entire backend/frontend architecture;
- generic credentials/tokens handling patterns without Sentrdel least-privilege redesign;
- server storage dependencies into base local mode;
- CTI inference rules as Sentrdel security judgments;
- OpenCTI object taxonomy wholesale into the SSG;
- any connector that brings ambient network or provider authority into ordinary local review.

## Adoption priority

```text
P0  Preserve current S1 implementation order. No OpenCTI-driven code changes now.
P1  Canonicalize this research as roadmap-only.
P2  After S6, specify External Intelligence Context Bridge + bounded STIX/TAXII import.
P3  With optional control plane, specify DataHandlingMarking + IntegrationServiceIdentity.
P4  Add Intake Workbench + Investigation Workspace + Security Case projections.
P5  Add filtered streams/export only after tenant/project/marking policy is canonical.
P6  Add bounded automation only after action authorization and audit contracts are proven.
```

## Final decision

OpenCTI should materially influence Sentrdel's future operator/control-plane design, especially interoperability, provenance-rich graph context, staging, collaboration, access/marking controls, and integration lifecycle.

It should **not** change Sentrdel's product category or trusted kernel.

Sentrdel remains the system that answers:

> **What security property changed, what evidence supports that judgment, what analysis is missing, what was independently verified, what shipped, what runtime reality says, what external intelligence adds, who may see/share it, and whether remediation truly held?**

OpenCTI provides mature patterns for managing external intelligence around that question. Sentrdel must keep the answer itself under its own evidence, coverage, invariant, verification, and policy authority.
