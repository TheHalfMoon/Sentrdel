# OpenCTI-Informed Intelligence Interoperability Strategy — 2026-09-16

**Status:** STRATEGIC_SUPPLEMENT / NO IMPLEMENTATION AUTHORITY  
**Planning base:** protected `main@b6dafbb31b61d067f19177a86ba2179c9b8783b3`  
**Active implementation authority remains:** `specs/004-security-invariant-regression/`  
**OpenCTI research pin:** `OpenCTI-Platform/opencti@c22668461981ac9602e8e16527ef613428c34c3c`  
**Related research:** `docs/third-party/opencti-source-assessment-2026-09-16.md`  
**Permission context:** `docs/third-party/founder-source-reuse-attestation-2026-09-16-opencti.md`  
**Strengthens:** `security-control-plane-expansion-2026-09-12.md`; it does not reorder S1-S11 or authorize implementation.

## 1. Strategic decision

OpenCTI demonstrates how a mature security-intelligence platform can organize heterogeneous external knowledge, provenance, relationships, cases, sharing, integrations, and analyst workflows.

Sentrdel should adopt those **control-plane patterns** without changing its trusted product kernel.

The durable split is:

```text
Sentrdel trusted security judgment
  Evidence + Coverage + SSG + invariants + regression
  reconciler-only Findings + policy + proof-state semantics
                 |
                 v
Optional intelligence and operations control plane
  external intelligence context
  runtime/deployment context
  investigations/cases/workbenches
  sharing/markings
  connectors/streams
  remediation/retest workflow
```

The optional control plane may add context and workflow. It does not own the truth semantics below it.

## 2. OpenCTI lessons Sentrdel should adopt

### 2.1 Knowledge graph as an analyst projection

OpenCTI makes relationships first-class and supports graph-based pivoting. Sentrdel should extend operator exploration around its existing bounded SSG rather than mutate the SSG into a universal intelligence graph.

Use two related but distinct graph classes:

- **Semantic Security Graph:** trusted bounded software-security semantics owned by Sentrdel.
- **External/Operational Context Graph:** imported threat intelligence, assets, incidents, runtime observations, cases, external entities, and derived context relationships.

An edge can reference SSG identities, but the context graph cannot create stable SSG identity or invariant truth merely through imported similarity/relationship data.

### 2.2 Standards-first intelligence interoperability

STIX 2.1 and TAXII 2.1 are useful external exchange boundaries.

Sentrdel should support them as adapters after the generic external-evidence/import contract is canonical. Sentrdel should not adopt STIX as its internal Evidence/Finding/SSG schema.

### 2.3 Workbench before durable promotion

Untrusted imports need a staging lifecycle before durable linking. A workbench is the safest future place to resolve:

- duplicates;
- conflicting identities;
- unsupported object types;
- ambiguous asset mappings;
- uncertain revision/deployment relationships;
- marking/classification conflicts;
- invalid or partial imports.

### 2.4 Cases and investigations are projections, not truth authorities

A case/workspace should collect, annotate, assign, and investigate records without rewriting their underlying canonical state.

### 2.5 Reliability/confidence are metadata, not authority

Sentrdel must model source reliability, confidence, and correlation strength separately from epistemic classes such as FACT, INFERENCE, RUNTIME_OBSERVATION, and VERIFIED.

### 2.6 Markings and sharing policy are independent from truth

Sensitive security records need view/export/share controls that do not change whether a Finding or Evidence record is valid.

### 2.7 Connectors need durable service identity

Long-running imports should use dedicated least-privilege service identities tied to exact adapter manifests and source scopes.

### 2.8 Streams need policy-aware filtering

Server-mode event/data streams should enforce tenant/project/marking scope and preserve cursor/replay/partial-state semantics.

### 2.9 Automation needs a stronger safety model than generic playbooks

Sentrdel may eventually support event-driven automation, but only by composing typed pre-authorized actions. Automation cannot manufacture verification authority, runtime-response authority, or shell access.

## 3. Gap register additions

The 2026-09-12 blueprint defined G15-G42. This supplement adds G43-G52.

### G43 — Security-intelligence interoperability boundary missing

**Correction:** define a bounded external-intelligence envelope plus STIX/TAXII adapter profile after S6.

### G44 — Data handling/disclosure marking missing

**Correction:** define markings independently from Evidence/Finding truth and enforce them in optional server display/export/stream paths.

### G45 — Import workbench missing

**Correction:** stage normalized candidate objects and proposed links before durable promotion.

### G46 — Investigation workspace missing

**Correction:** define temporary/private/shared graph workspaces as non-authoritative projections.

### G47 — Collaborative case container missing

**Correction:** add case semantics for investigations, verification campaigns, incidents, remediation programs, and qualification reviews without creating Findings.

### G48 — Reliability/confidence authority confusion risk

**Correction:** separate producer reliability, source confidence, transformation confidence, and correlation strength from Sentrdel epistemic authority.

### G49 — Filtered sharing/stream contract incomplete

**Correction:** define cursor, replay, tenant/project/marking filters, redaction, authorization, and revocation behavior.

### G50 — Integration service identity underspecified

**Correction:** long-running adapters get dedicated service identities, secret scopes, source scopes, rotation/revocation state, and immutable audit linkage.

### G51 — Derived relationship provenance underspecified

**Correction:** every derived edge records rule/version, exact inputs, authority ceiling, timestamps, recompute/invalidation status, and derivation identity.

### G52 — Automation can become a privilege escalation plane

**Correction:** allow only typed actions with explicit manifests/authorizations; no arbitrary shell action and no authority self-generation.

## 4. Future contracts

Names are planning names only.

### 4.1 `ExternalIntelligenceEnvelope`

Minimum semantics:

- envelope/import ID;
- source identity and source class;
- producer/adapter identity/version/digest;
- upstream object ID/type/version;
- raw-content digest where retention policy permits;
- normalized object/relationship form;
- producer/source timestamps;
- Sentrdel ingestion timestamp;
- source reliability metadata;
- producer confidence metadata;
- marking/classification metadata;
- transformation history;
- parser/validation diagnostics;
- duplicate/conflict state;
- authority ceiling;
- proposed/accepted Sentrdel identity links.

No external intelligence object creates a canonical Finding by ingestion alone.

### 4.2 `DataHandlingMarking`

Minimum semantics:

- marking ID/type/value;
- source and policy namespace;
- record/object scope;
- view/export/share constraints;
- tenant/project applicability;
- actor/service requirements;
- downgrade/removal authority;
- immutable audit provenance.

Marking affects disclosure, not truth.

### 4.3 `IntegrationServiceIdentity`

Minimum semantics:

- service identity ID;
- adapter manifest ID/digest;
- tenant/project/source scope;
- allowed endpoints/source classes;
- secret-reference scope;
- network/filesystem/process capability ceiling;
- issue/rotation/expiry/revocation state;
- last qualification/revalidation state;
- immutable access/audit linkage.

### 4.4 `IntakeWorkbench`

Minimum semantics:

- workbench ID;
- import/run source;
- normalized candidate object IDs;
- diagnostics/conflicts/unsupported objects;
- proposed canonical/context links;
- analyst decisions;
- actor/timestamp/reason provenance;
- terminal state: `OPEN`, `ACCEPTED`, `PARTIALLY_ACCEPTED`, `REJECTED`, `EXPIRED` or future frozen equivalent.

Acceptance into context does not bypass reconciler-only Finding creation.

### 4.5 `InvestigationWorkspace`

Minimum semantics:

- workspace ID/title/owner;
- tenant/project scope;
- authorized members/roles;
- linked object IDs;
- graph layout/annotations as presentation state;
- sharing/marking restrictions;
- immutable membership/change audit.

Workspace membership cannot alter underlying security truth.

### 4.6 `SecurityCase`

Minimum semantics:

- case ID/type/lifecycle state;
- tenant/project scope;
- owner/participants;
- linked Findings/Evidence/Coverage/proof/runtime/intelligence/assets/deployments;
- task/action references;
- due/SLA metadata;
- marking/access policy;
- immutable lifecycle events.

A case may link Findings but cannot create or rewrite them.

### 4.7 `DerivedRelationshipRecord`

Minimum semantics:

- relationship ID;
- exact source/target identities;
- relation type;
- derivation rule ID/version;
- input IDs;
- deterministic/probabilistic class;
- confidence if applicable;
- authority ceiling;
- created/recomputed/invalidated timestamps;
- invalidation reason/provenance.

### 4.8 `SecurityEventStreamSubscription`

Minimum semantics:

- subscription ID;
- principal/service identity;
- tenant/project scope;
- object/event filters;
- marking/disclosure ceiling;
- cursor/replay window;
- redaction policy;
- rate/size limits;
- expiry/revocation;
- delivery/incomplete diagnostics.

Streams are projections over canonical events/objects, not independent judgment sources.

### 4.9 `AutomationRule`

Minimum semantics:

- automation rule ID/version/digest;
- trusted owner/publisher;
- typed trigger;
- typed predicates;
- typed action manifest IDs;
- exact tenant/project/asset scope;
- secret-reference scope;
- time/rate/concurrency/resource budget;
- required authorization references;
- dry-run/simulation support where possible;
- immutable execution trace;
- explicit inability to mint VerificationAuthorization or RuntimeResponseAuthorization.

## 5. Security hardening correction — `VerificationAuthorization`

The 2026-09-12 blueprint's minimum `VerificationAuthorization` semantics are strengthened by this supplement.

Any future canonical verification authorization contract MUST also require:

- a trusted issuer/operator identity;
- an explicit trust-anchor or issuer-validation reference;
- canonical serialization before digest/signature/integrity verification;
- integrity/authenticity verification appropriate to the issuer mechanism;
- nonce/run binding or equivalent replay defense;
- exact start/expiry validation using a declared clock policy;
- exact target/environment/tool/profile/action scope matching;
- fail-closed rejection of forged, altered, replayed, expired, revoked, or scope-mismatched authorizations;
- immutable validation result/provenance in the `VerificationRunManifest`;
- no fallback from invalid authorization to a broader interactive/default permission.

The existing `authorization ID/digest` linkage is necessary but not sufficient.

Required adversarial conformance includes:

- forged issuer;
- modified authorization after signing/digesting;
- reused authorization on another run;
- expired authorization;
- revoked authorization;
- target/environment mismatch;
- tool/profile mismatch;
- action/mutation-budget mismatch;
- duplicated nonce/run binding;
- missing trust anchor;
- ambiguous issuer identity.

All must fail closed before target execution.

## 6. STIX/TAXII mapping rules

A future interoperability spec should follow these principles.

### Imported vulnerabilities

A vulnerability/CVE object is context. It may support dependency/advisory Evidence after independent package/revision correlation. It is not a repository Finding merely because the upstream feed says the vulnerability exists.

### Indicators and observables

Indicators/observables may enrich runtime/security context. A match can create imported/runtime Evidence subject to the applicable producer contract. Indicator confidence does not equal proof of exploitation or a canonical Finding.

### Attack patterns and techniques

These are useful taxonomy/context links for Findings, invariants, incidents, and cases. They do not determine Sentrdel severity or verdicts by themselves.

### Threat actors, campaigns, malware, tools, infrastructure

These remain external intelligence context. They must not authorize scanning, verification, blocking, or response actions.

### Reports/groupings

These map naturally to external context containers or workbench/case inputs. Imported membership does not imply trusted semantic identity.

### Relationships

Preserve upstream relationship identity and source. If Sentrdel derives a stronger relationship, create a separate `DerivedRelationshipRecord` rather than rewriting the imported edge.

## 7. Intake and correlation pipeline

Recommended future flow:

```text
external source
   |
   v
qualified adapter + service identity
   |
   v
bounded parser / ExternalIntelligenceEnvelope
   |
   v
Intake Workbench
   |  reject / accept / partially accept
   v
context graph projection
   |
   +--> candidate correlation to AssetIdentity
   +--> candidate correlation to DeploymentIdentity
   +--> candidate correlation to Evidence/Finding/Incident/SSG
   |
   v
canonical reconciler / policy only where existing contracts authorize it
```

No stage above may silently convert external confidence into Sentrdel FACT/VERIFIED authority.

## 8. Optional control-plane UX improvements

OpenCTI demonstrates valuable interaction patterns that should influence future Sentrdel UX.

### Global exploration

Provide fast search/filter/pivot over:

- Findings;
- Evidence;
- Coverage gaps;
- assets/services/APIs;
- releases/deployments;
- incidents;
- runtime observations;
- external intelligence;
- verification runs/proof;
- packs/adapters/source qualification.

### Graph investigation

Allow a user to start from any canonical/context object and progressively expand relationships. Visually distinguish:

- canonical semantic edge;
- imported external edge;
- deterministic derived edge;
- probabilistic/inferred edge;
- runtime temporal edge;
- case/workspace-only presentation relationship.

### Workbench

Show raw import source, normalized candidates, conflicts, unsupported objects, and proposed identity links before acceptance.

### Case view

Combine timeline, graph, tasks, owners, Findings, proof, remediation, runtime, and external intelligence in one collaborative projection.

### Trust badges

Every object/relationship should expose whether it is:

- observed FACT;
- imported external intelligence;
- deterministic inference;
- heuristic/model inference;
- runtime observation;
- execution verified;
- contradicted;
- unsupported/missing Coverage;
- stale/revoked/expired.

## 9. Access, marking, and sharing rules

Future multi-user/server mode should enforce:

1. tenant/project isolation before object lookup results are revealed;
2. role/capability checks on action type;
3. object-level authorized-member restrictions where configured;
4. data-handling marking/disclosure ceiling;
5. adapter/service identity scope;
6. export/stream filters after all access restrictions;
7. immutable allow/deny audit events for sensitive operations;
8. cross-tenant denial tests as release gates;
9. no global connector/system bypass for ordinary integrations;
10. explicit break-glass identity and audit for exceptional administration.

## 10. Storage/deployment boundary

OpenCTI's server stack proves that large knowledge graphs and high-volume integrations may eventually justify search clusters, queues, caches, and object storage.

Sentrdel should not adopt those dependencies prematurely.

### Local base

Keep existing lightweight/local persistence and deterministic export/replay.

### Optional server

A future server may introduce relational/search/object/queue infrastructure only after measurement proves it necessary. Canonical IDs/events and trusted judgment remain implementation-independent.

### Migration rule

No server-side storage technology may redefine:

- Evidence identity;
- Coverage truth;
- Finding authority;
- invariant semantics;
- verification proof state;
- authorization scope;
- lifecycle transition validity.

## 11. Dependency-ordered adoption

This strategy does not reorder S1-S11.

### Now — while Spec 004 / S1 is active

Allowed:

- research documentation;
- exact source/license recording;
- roadmap refinement;
- no OpenCTI-inspired product code in active S1 unless independently required by Spec 004.

### After S6 generic import contracts are canonical

Eligible planning:

- `ExternalIntelligenceEnvelope`;
- STIX 2.1 parser/mapping profile;
- TAXII 2.1 import profile;
- import conformance/adversarial fixtures;
- `IntegrationServiceIdentity`.

### After optional control-plane principal/tenant/authz contracts are canonical

Eligible planning:

- `DataHandlingMarking`;
- `IntakeWorkbench`;
- `InvestigationWorkspace`;
- `SecurityCase`;
- filtered event/data sharing.

### After typed action/authorization contracts are canonical

Eligible planning:

- bounded automation/playbooks;
- connector lifecycle management UI;
- controlled enrichment triggers.

## 12. Future Spec Kit candidates

### Candidate I — Security Intelligence Interoperability Foundation

**Entry:** S6 canonical.  
**Outputs:** `ExternalIntelligenceEnvelope`, STIX/TAXII mapping, parser caps, reliability/confidence separation, adapter conformance, service identity.  
**No-go:** imported intelligence directly creating Findings or target authority.

### Candidate J — Intelligence Intake Workbench

**Entry:** Candidate I + optional control-plane identity/authz.  
**Outputs:** workbench staging, conflict/duplicate resolution, proposed links, audit.  
**No-go:** workbench acceptance minting FACT/VERIFIED or bypassing reconciler.

### Candidate K — Investigations and Security Cases

**Entry:** stable object/event APIs + control-plane authz.  
**Outputs:** workspaces, cases, graph/timeline/task projections, access restrictions.  
**No-go:** container membership rewriting underlying truth.

### Candidate L — Security Sharing and Streams

**Entry:** tenant/project/marking contracts canonical.  
**Outputs:** filtered event streams, exports, cursor/replay, revocation, public/shareable projections only where explicitly authorized.  
**No-go:** data leakage through dependencies/relationships not covered by policy.

### Candidate M — Bounded Security Automation

**Entry:** typed actions + action authorization + immutable audit canonical.  
**Outputs:** trigger/condition/action graph, dry-run, execution traces, budgets.  
**No-go:** arbitrary shell, self-created authorization, autonomous production response.

## 13. OpenCTI source adoption rules

At research pin `c22668461981ac9602e8e16527ef613428c34c3c`:

- Community Edition source is described by upstream as Apache-2.0;
- Enterprise Edition code is separately licensed and visibly marked.

Therefore:

1. exact file-level qualification is mandatory before copy/port/vendor/link;
2. files without a compatible public-license classification are blocked;
3. Enterprise Edition files require a stored source-specific compatible permission/license basis before direct reuse;
4. architecture/UX ideas may be independently reimplemented without copying implementation source;
5. STIX/TAXII standards should generally be implemented from the standard and Sentrdel requirements rather than copied wholesale from OpenCTI;
6. copied Apache-2.0 Community Edition material must retain required notices/attribution and pass Sentrdel security/source qualification;
7. third-party datasets, fixtures, assets, dependencies, and generated artifacts require their own license/source review.

## 14. Explicit non-goals

This strategy does not authorize:

- replacing Sentrdel with a CTI platform;
- adopting STIX as the internal trusted security model;
- making Elasticsearch/OpenSearch, Redis, RabbitMQ, S3, Node, or Python mandatory for local mode;
- importing Enterprise Edition source without exact compatible permission evidence;
- external intelligence confidence becoming a Finding/verdict;
- imported assets becoming verification targets;
- connector tokens with platform-wide ambient authority;
- generic playbook shell execution;
- autonomous enrichment/response against third-party systems;
- hiding partial/failed imports as clean state;
- graph inference becoming stable semantic identity without explicit proof.

## 15. Success criteria

The OpenCTI-informed expansion is successful when Sentrdel can eventually demonstrate all of the following while preserving its trusted kernel:

1. import a bounded STIX/TAXII intelligence set through a qualified adapter;
2. preserve exact source, reliability, confidence, markings, transformation, and partial/failure state;
3. stage ambiguous/conflicting data in a workbench;
4. link accepted external context to assets/deployments/incidents/findings without changing their canonical authority;
5. pivot across those relationships in an investigation graph;
6. manage a collaborative security case without rewriting underlying Findings;
7. stream/export authorized filtered context without cross-tenant/marking leakage;
8. keep local Sentrdel fully useful with the entire intelligence/control-plane layer absent;
9. prove every derived relationship and automation action through immutable provenance;
10. keep imported intelligence structurally incapable of minting VERIFIED, a canonical Finding, target authorization, or runtime-response authority.

That yields a stronger Sentrdel: not only a precise security-regression engine, but eventually a trustworthy, interoperable security evidence and intelligence control plane whose broader context can never outrank its proof model.
