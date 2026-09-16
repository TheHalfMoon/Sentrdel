# Founder Source-Reuse Attestation — GitHub Source Universe — 2026-09-16

**Status:** FOUNDER_PERMISSION_CONTEXT  
**Repository:** `TheHalfMoon/Sentrdel`  
**Planning branch:** `docs/security-control-plane-2026-09-12`  
**Implementation authority:** NONE  

## Founder statement

On 2026-09-16, the founder stated that Sentrdel may use/copy source code from all sources present in the founder's GitHub source universe and asked Sentrdel to mine those sources for reusable implementation and architecture material.

This record captures that founder authorization context for planning and future source qualification.

## Scope

The statement covers, as founder-supplied permission context:

- repositories owned by the founder's connected GitHub account;
- source repositories referenced, pinned, or studied in those repositories where the founder states permission to use the source code;
- OpenCTI, separately supplied in the same Sentrdel improvement program;
- future bounded reuse evaluations derived from this GitHub source-mining pass.

The statement does **not** by itself:

- admit any dependency or source file into Sentrdel;
- prove copyright ownership of third-party material;
- erase public license, NOTICE, attribution, trademark, patent, dataset, model, or bundled third-party obligations;
- establish rights for material not actually covered by the founder's permission;
- authorize implementation before the dependency-ordered Sentrdel Spec Kit gate permits it;
- authorize target execution, external scanning, exploitation, credentials, production mutation, network egress, or sandbox execution;
- convert research pins into release/admission pins.

## Required future qualification

Before any bounded source reuse lands, the adopting change MUST record at minimum:

1. exact repository and immutable commit/tree;
2. exact files/symbols/artifacts selected;
3. founder permission reference to this attestation and any more specific permission evidence available;
4. observed public license and applicable NOTICE/attribution obligations;
5. bundled/generated/third-party provenance for the selected paths;
6. integration mode (`SELECTIVE_PORT`, `NATIVE_RUST_REIMPLEMENTATION`, `OUT_OF_PROCESS_ADAPTER`, `PROTOCOL_REFERENCE`, `BENCHMARK_ONLY`, or another frozen mode);
7. dependency/build/runtime closure;
8. filesystem, process, network, credential, browser, container, model/provider, telemetry, and target-mutation surfaces;
9. resource bounds and failure behavior;
10. independent security/semantic review and Sentrdel-owned tests;
11. maintenance, freshness, revocation/removal, and requalification triggers.

## Authority rule

```text
FOUNDER_PERMISSION_CONTEXT
  != SOURCE_QUALIFIED
  != DEPENDENCY_ADMITTED
  != IMPLEMENTATION_AUTHORIZED
  != RUNTIME_AUTHORITY
```

The permission statement enables serious source qualification and selective reuse. Sentrdel's Constitution, active Spec Kit, Evidence/Coverage authority boundaries, and protected-main governance remain controlling.
