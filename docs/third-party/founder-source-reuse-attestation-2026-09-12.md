# Founder Source Reuse Attestation — 2026-09-12

**Record ID:** `FOUNDER_ATTESTATION_2026-09-12`  
**Status:** PROJECT_GOVERNANCE_ATTESTATION  
**Authority:** Permission context only; not source qualification, legal opinion, or implementation authorization.

## Founder statement recorded

On 2026-09-12 the founder stated that Sentrdel has permission to copy code from the following sources supplied for the security-platform planning study:

- `https://glitchtip.com` / the GlitchTip source projects identified from that product;
- `https://github.com/hackerai-tech/hackerai`;
- `https://github.com/AISecurityLab/hackagent`;
- `https://github.com/0x4m4/hexstrike-ai`;
- `https://github.com/KeygraphHQ/shannon`;
- `https://github.com/yashab-cyber/hackbot`;
- `https://github.com/usestrix/strix`.

The founder explicitly characterized the permission as permission to copy code.

## What this record does

This record allows future source-qualification work to cite a durable founder attestation instead of relying on chat history alone.

It does **not** by itself prove:

- which upstream copyright owner or authorized representative granted permission;
- the exact date, text, scope, duration, revocability, sublicensing rights, relicensing rights, patent terms, trademark rights, or commercial-use terms of each private grant;
- which exact repository, branch, commit, file, dataset, model, container image, PoC, template, asset, or generated artifact is covered;
- that a grant overrides third-party material embedded in an upstream repository;
- that AGPL/copyleft, additional commercial restrictions, NOTICE obligations, or other public-license conditions may be ignored;
- that donor code is safe or architecturally appropriate for Sentrdel;
- that donor runtime/network/credential/exploitation behavior is authorized in Sentrdel;
- that any current Spec Kit implementation scope may be widened.

Sentrdel MUST NOT invent missing source-specific permission evidence.

## Required binding before source reuse

Any future Source Qualification Ledger entry that relies on this attestation MUST bind at least:

```text
permission_basis: FOUNDER_ATTESTATION_2026-09-12 + applicable public license and/or stored source-specific permission
source_specific_permission_reference: <stored reference or NOT_STORED>
repository: <exact upstream repository>
exact_ref: <full immutable commit/tag object>
files_or_artifacts: <exact set>
license_expression: <observed expression>
notices: <required attribution/notices>
integration_mode: <bounded mode>
modifications: <Sentrdel changes>
build_runtime_authority: <enumerated>
network_credential_target_authority: <enumerated>
security_review: <evidence>
requalification_triggers: <enumerated>
```

If `source_specific_permission_reference` remains `NOT_STORED`, public license compatibility remains the default legal distribution boundary. For sources whose public terms are not compatible with the intended Sentrdel integration mode, copying into the permissive trusted core remains blocked until a sufficiently specific separate permission/relicense record is stored.

## Source-specific cautions observed during the 2026-09-12 research

- **HackerAI:** the observed LICENSE contains Apache-2.0 text plus additional commercial-use restrictions. Treat it as restricted, not ordinary Apache-2.0, until separate permission is documented for the intended use.
- **Shannon:** the observed repository LICENSE is AGPL-3.0. Direct copying/linking into the permissive trusted core requires a source-specific separate permission/relicense basis covering the selected material and intended distribution.
- **GlitchTip:** the founder supplied the product site rather than an exact source repository. The backend project identified during research is MIT, but exact source repository/ref/files still must be resolved before reuse.
- **HackAgent / Strix:** Apache-2.0 was observed at the research pins; file/artifact-level qualification is still required.
- **HexStrike AI / HackBot:** MIT was observed at the research pins; file/artifact-level qualification is still required.

## Safety boundary

Permission to reuse code does not authorize autonomous exploitation, third-party target scanning, production mutation, credential attacks, brute force, unbounded reconnaissance, or provider/production credential access.

All future dynamic security behavior remains governed by the Sentrdel Constitution, active Spec Kit, explicit rules of engagement, isolation tier, target authorization, resource/network policy, and Evidence/Finding authority model.