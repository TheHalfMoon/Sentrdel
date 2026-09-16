# OpenCTI Source Reuse Map — 2026-09-16

**Status:** SOURCE_RESEARCH_MAP / NO IMPLEMENTATION AUTHORITY  
**Repository:** `OpenCTI-Platform/opencti`  
**Research pin:** `c22668461981ac9602e8e16527ef613428c34c3c`  
**Related assessment:** `docs/third-party/opencti-source-assessment-2026-09-16.md`  
**Permission context:** `FOUNDER_ATTESTATION_2026-09-16_OPENCTI`  
**Purpose:** Identify exact upstream implementation areas worth future qualification without copying OpenCTI wholesale or confusing architecture study with current Sentrdel authority.

## Classification rules

This map uses four dispositions:

- `QUALIFY_FOR_SELECTIVE_REUSE` — exact source may be worth copying/porting after file-level license, security, dependency, and architecture qualification.
- `REFERENCE_AND_REIMPLEMENT` — learn from behavior/contracts but prefer a smaller Sentrdel-native implementation.
- `PROTOCOL_REFERENCE` — use the external standard and Sentrdel contracts as primary authority; upstream code is test/reference material, not the target architecture.
- `COPY_BLOCKED_PENDING_SPECIFIC_PERMISSION` — direct reuse is blocked because the observed file is Enterprise Edition or otherwise lacks a compatible stored source-specific permission/license basis.

At the research pin, upstream's repository license states that files without an Enterprise Edition indication are Community Edition under Apache-2.0 and that Enterprise Edition files carry separate licensing. That repository rule is still only the first step: every selected file must be re-fetched at its exact immutable ref and qualified before reuse.

## High-value Community Edition candidates

### 1. STIX domain-object schema registry

```text
path: opencti-platform/opencti-graphql/src/schema/stixDomainObject.ts
blob_sha: 59e4c7ac42c42ad451f9dba624ccb3a5b4c08f11
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: PROTOCOL_REFERENCE + SELECTIVE_TEST/TYPE_PATTERN_REUSE
```

Observed responsibilities include STIX domain-object type registration, entity constants, container categories, and type predicates.

**Sentrdel use:** useful when freezing `ExternalIntelligenceEnvelope` type mappings and STIX interoperability fixtures. Sentrdel should not adopt OpenCTI's entire internal object taxonomy as its own trusted SSG taxonomy.

### 2. STIX 2.1 conversion layer

```text
path: opencti-platform/opencti-graphql/src/database/stix-2-1-converter.ts
blob_sha: 4f1c0dcc63dff52759afcc7a33e4392fcd0ab733
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: PROTOCOL_REFERENCE / QUALIFY_FOR_SELECTIVE_REUSE
```

Observed responsibilities include conversion from OpenCTI store objects to STIX 2.1 objects, type dispatch, relationship/reference handling, and OpenCTI extension mapping.

**Sentrdel use:** strong source of edge cases and interoperability behavior. Prefer implementing the future Sentrdel STIX boundary from the STIX 2.1 specification plus Sentrdel authority rules, then selectively reuse or port only proven edge-case logic/tests where it reduces risk.

**Do not copy wholesale:** the converter is deeply coupled to OpenCTI store types, extensions, identifiers, and database semantics.

### 3. Connector domain and typed connector metadata

```text
path: opencti-platform/opencti-graphql/src/connector/connector-domain.ts
blob_sha: 9b9a23c718b3310fd619b9ff44a2fa1bcbbfdc7c
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: REFERENCE_AND_REIMPLEMENT
```

Observed responsibilities include connector registration surfaces, connector type/scope metadata, built-in connector enumeration, and queue-backed runtime registration.

**Sentrdel use:** architectural reference for `IntegrationServiceIdentity`, adapter manifests, declared scope, runtime registration, and connector lifecycle.

**Required redesign:** Sentrdel connectors/adapters need stricter least-privilege capability manifests, exact source/endpoint scope, secret-reference scope, authority ceilings, rotation/revocation, and no generic platform-wide service token.

### 4. Python connector helper/runtime lifecycle

```text
path: client-python/pycti/connector/opencti_connector_helper.py
blob_sha: cd89a01846cec5a0332715beaa95e2a7755d4ba5
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: REFERENCE_AND_REIMPLEMENT / SELECTIVE_ALGORITHM_REUSE_AFTER_QUALIFICATION
```

Observed responsibilities include connector registration, RabbitMQ consumption, SSE stream listening, scheduling, heartbeat/liveness, STIX bundle processing, temporary-file handling, TLS/JWT helpers, concurrency, and metrics.

**Sentrdel use:** valuable lifecycle reference for long-running import/runtime adapters and checkpoint/recovery semantics.

**Do not make it a base dependency:** the helper carries a broad Python/server dependency surface (`boto3`, RabbitMQ client, FastAPI/Uvicorn, JWT, SSE, threads, temp files). The Sentrdel local trusted base should remain Rust-first and materially smaller.

### 5. Analyst Workbench creation flow

```text
path: opencti-platform/opencti-front/src/private/components/common/files/workbench/WorkbenchCreation.tsx
blob_sha: 1fb2cf133bdbeed28fab7db98ab7cdc07b02a8db
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: QUALIFY_FOR_SELECTIVE_UI_PATTERN_REUSE
```

Observed responsibilities include staging a workbench file, labels, object markings, optional entity binding, validation, upload mutation, and UI state handling.

**Sentrdel use:** strong UI pattern source for `IntakeWorkbench`: stage imported intelligence/evidence, show markings and proposed associations, preserve explicit submit/error state, and keep staged content separate from canonical judgment.

**Required redesign:** Sentrdel's workbench must expose parser diagnostics, duplicate/conflict state, authority ceiling, source reliability/confidence, proposed identity links, accept/reject/partial-accept decisions, and immutable provenance.

### 6. Investigation workspace export/domain behavior

```text
path: opencti-platform/opencti-graphql/src/modules/workspace/investigation-domain.ts
blob_sha: d0b7d24abf07a1503b826ebafa3f76409f7f048d
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: REFERENCE_AND_REIMPLEMENT
```

Observed responsibilities include investigation workspace creation from a container, filtered investigated-entity membership, and STIX report/bundle export.

**Sentrdel use:** reference for `InvestigationWorkspace` membership, graph pivots, and export projections.

**Authority constraint:** workspace membership and export composition must never create/delete Findings, change Evidence authority, upgrade verification state, or rewrite SSG identity.

### 7. SSE / live-stream delivery and access filtering

```text
path: opencti-platform/opencti-graphql/src/graphql/sseMiddleware.js
blob_sha: a5dfa723c84ff30b2e4764cb7657dcd72e47a092
observed_header: no Enterprise Edition header in fetched file prefix
upstream_classification_basis: unmarked-file rule in repository LICENSE
candidate_disposition: REFERENCE_AND_REIMPLEMENT / SELECTIVE_STREAM_EDGE_CASE_REUSE
```

Observed responsibilities include authenticated live streams, OTP checks, access/capability checks, marking-aware filtering, organization restrictions, stream cursors/events, heartbeat/cache behavior, STIX conversion, and stream-consumer tracking.

**Sentrdel use:** one of the strongest references for future `SecurityEventStreamSubscription` and filtered server-mode sharing.

**Required redesign:** Sentrdel must enforce tenant/project/marking/redaction policy before delivery, preserve replay/cursor/partial-state semantics, avoid global bypass identities for ordinary integrations, and keep streams as projections over canonical events rather than independent security truth.

## Enterprise Edition boundaries observed

### Playbook automation

```text
representative_path: opencti-platform/opencti-graphql/src/modules/playbook/playbook.ts
observed_file_header: explicit OpenCTI Enterprise Edition license notice
candidate_disposition: COPY_BLOCKED_PENDING_SPECIFIC_PERMISSION
```

Additional observed files under the playbook module and frontend also carry explicit Enterprise Edition notices, including:

- `opencti-platform/opencti-graphql/src/modules/playbook/playbook-resolvers.ts`
- `opencti-platform/opencti-graphql/src/modules/playbook/playbook-types.ts`
- `opencti-platform/opencti-graphql/src/modules/playbook/playbook-converter.ts`
- `opencti-platform/opencti-graphql/src/modules/playbook/playbook-enrollment.ts`
- `opencti-platform/opencti-graphql/src/modules/playbook/playbook-domain.ts`
- `opencti-platform/opencti-graphql/src/modules/playbook/playbook-components.ts`
- `opencti-platform/opencti-front/src/private/components/data/playbooks/Playbook.tsx`
- `opencti-platform/opencti-front/src/private/components/data/playbooks/PlaybookEdition.tsx`

Upstream documentation also identifies playbook automation as Enterprise Edition.

**Sentrdel decision:** the automation concept remains valuable, but direct reuse of these files is blocked unless a compatible source-specific permission/license record is stored. Even with permission, Sentrdel should independently freeze a more restrictive `AutomationRule` model rather than inherit generic workflow authority.

## Reuse priority by Sentrdel milestone

### Before S6

`REFERENCE_ONLY`

No OpenCTI implementation source should land merely because it is useful. Active S1 work remains governed by Spec 004 and dependency order.

### After S6 generic external-import boundary is canonical

Highest-priority qualification targets:

1. STIX schema/type mapping behavior;
2. STIX 2.1 conversion edge cases and fixtures;
3. connector manifest/lifecycle patterns;
4. connector checkpoint/retry/stream handling patterns.

Primary output should be a small Rust-native `ExternalIntelligenceEnvelope` + STIX/TAXII adapter, not an embedded OpenCTI runtime.

### After optional control-plane identity/authz is canonical

Highest-priority qualification targets:

1. workbench interaction patterns;
2. investigation workspace behavior;
3. marking-aware stream filtering;
4. controlled export/share projections.

### After typed action authorization is canonical

Automation/playbook behavior may be studied further. Enterprise source remains separately permission-gated and automation remains constrained by Sentrdel-native action manifests and authorization records.

## Exact qualification checklist for any selected OpenCTI file

Before copied or substantially derived implementation source lands, record:

```text
repository: OpenCTI-Platform/opencti
repository_pin: c22668461981ac9602e8e16527ef613428c34c3c or newer explicitly approved pin
path: <exact path>
blob_sha: <exact blob>
edition_class: COMMUNITY | ENTERPRISE | UNKNOWN
observed_license_header: <exact classification summary>
license_expression: <qualified expression>
permission_reference: <public license and/or stored source-specific grant>
notices_required: <exact notices>
transitive_dependencies: <reviewed set>
security_review: <evidence>
integration_mode: <PORT | COPY | REIMPLEMENT | FIXTURE_ONLY | REFERENCE_ONLY>
authority_ceiling: <explicit>
network/filesystem/process/credential requirements: <explicit>
data_retention_and_marking_behavior: <explicit>
requalification_triggers: <explicit>
```

No `UNKNOWN` or `ENTERPRISE` file may move to direct-copy implementation without closing its permission/license gate.

## Rejected wholesale-adoption paths

Do not:

- vendor OpenCTI's entire Node/Python platform into Sentrdel;
- make Elasticsearch/OpenSearch, Redis, RabbitMQ, S3, Python, or Node mandatory for local Sentrdel;
- replace the SSG with OpenCTI's STIX graph;
- let a connector token inherit platform-wide ambient privileges;
- map OpenCTI confidence directly to Sentrdel FACT/VERIFIED;
- map imported OpenCTI relations directly to trusted SSG semantics without an explicit Sentrdel correlation contract;
- copy Enterprise Edition automation code based only on project-level permission context;
- import OpenCTI's server scaling architecture before measured Sentrdel requirements justify it.

## Bottom line

OpenCTI contains several excellent, separable implementation references. The strongest future reuse candidates are its STIX conversion edge cases, connector lifecycle concepts, workbench UX, investigation projection behavior, and access-filtered streaming mechanics.

Sentrdel should reuse them selectively and defensibly while keeping its own Rust trusted judgment core, deterministic evidence/coverage semantics, reconciler-only Finding authority, and local-first operating model intact.
