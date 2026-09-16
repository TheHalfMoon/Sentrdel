# Founder Source Reuse Attestation — OpenCTI — 2026-09-16

**Record ID:** `FOUNDER_ATTESTATION_2026-09-16_OPENCTI`  
**Status:** PROJECT_GOVERNANCE_ATTESTATION  
**Authority:** Permission context only; not source qualification, legal opinion, or implementation authorization.

## Founder statement recorded

On 2026-09-16 the founder stated that Sentrdel has permission to copy source code from:

- `https://github.com/OpenCTI-Platform/opencti`

The founder explicitly characterized the permission as permission to copy all source code from the supplied OpenCTI project.

## Repository licensing boundary observed during research

The OpenCTI repository is mixed-license.

At research pin `c22668461981ac9602e8e16527ef613428c34c3c`:

- the repository LICENSE states that OpenCTI Community Edition is Apache-2.0;
- the repository LICENSE states that OpenCTI Enterprise Edition is governed by the OpenCTI Enterprise Edition License;
- the repository states that source files carry headers indicating the applicable license, and files without an Enterprise Edition header belong to Community Edition under Apache-2.0;
- Enterprise Edition directories/files visibly contain explicit Enterprise Edition copyright/license headers.

This attestation MUST NOT be used to erase that distinction.

## What this record does

This record preserves the founder's 2026-09-16 permission statement in repository governance so future qualification work does not depend on chat history alone.

It does **not** by itself prove:

- which OpenCTI/Filigran copyright owner or authorized representative granted any private permission;
- whether a private grant covers Community Edition only, Enterprise Edition, bundled third-party material, assets, datasets, generated files, or dependencies;
- the exact commercial, redistribution, relicensing, patent, trademark, sublicensing, duration, or revocation terms of a private grant;
- that Enterprise Edition source may be copied into Sentrdel without storing source-specific permission evidence compatible with the intended distribution;
- that any OpenCTI code is secure, architecturally appropriate, or authorized by the current Sentrdel Spec Kit;
- that OpenCTI network, connector, ingestion, automation, multi-user, or runtime authority may be inherited by Sentrdel.

Sentrdel MUST NOT invent missing source-specific permission evidence.

## Required binding before copied source lands

Any future Source Qualification Ledger entry that copies, ports, vendors, links, or substantially derives OpenCTI implementation source MUST bind at least:

```text
permission_basis: FOUNDER_ATTESTATION_2026-09-16_OPENCTI + applicable public license and/or stored source-specific permission
source_specific_permission_reference: <stored reference or NOT_STORED>
repository: OpenCTI-Platform/opencti
exact_ref: <full immutable commit>
files_or_artifacts: <exact set>
edition_class: COMMUNITY | ENTERPRISE | MIXED | UNKNOWN
license_expression_per_file: <observed expression/header>
notices: <required attribution/notices>
integration_mode: <NATIVE_RUST_PORT | UI_PATTERN_PORT | EXTERNAL_ADAPTER | REFERENCE_ONLY | other frozen mode>
modifications: <Sentrdel changes>
build_runtime_authority: <enumerated>
network_credential_target_authority: <enumerated>
security_review: <evidence>
requalification_triggers: <enumerated>
```

If `source_specific_permission_reference` is `NOT_STORED`, direct reuse into Sentrdel defaults to the public-license boundary of each exact selected file. Community Edition Apache-2.0 files may be considered for exact qualification under Apache-2.0 obligations. Enterprise Edition files remain copy-blocked unless a sufficiently specific compatible permission/license record is stored for the selected material and intended use.

## Safety and authority boundary

Permission to reuse source does not authorize:

- autonomous exploitation or third-party target scanning;
- ambient connector credentials or service tokens;
- ingestion from arbitrary external endpoints;
- production mutation or automated response;
- arbitrary playbook/shell execution;
- Enterprise Edition feature adoption without source/license qualification;
- replacing Sentrdel's Evidence/Coverage/Finding/verification authority model with OpenCTI confidence, inference, graph, or case-management semantics.

All future implementation remains governed by the Sentrdel Constitution, active Spec Kit, canonical task order, exact source qualification, capability boundaries, local-first constraints, and Evidence/Finding authority model.
