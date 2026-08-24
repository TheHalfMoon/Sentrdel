# Implementation Readiness Checklist — R1

**Feature:** Sentrdel v0.1 Evidence + Guard Foundation  
**Date:** 2026-08-24  
**Major review:** APPLIED

## Scope and product

- [x] R1 is bounded under the A-to-Z roadmap.
- [x] Rust-first trusted core is explicit.
- [x] Category is evidence/control plane, not generic AI scanner.
- [x] Vendor-neutral/local-first behavior is explicit.
- [x] Guard enforcement vs advisory fidelity is explicit.
- [x] Universal CPG is out of scope.
- [x] R1 MCP is bounded stdio only; remote/Streamable HTTP is deferred.
- [x] Supabase deep static posture is moved to immediate roadmap R2; R1 only detects/provides pack contract.
- [x] Verification execution, IDE/GitHub App and runtime enforcement are out of R1.

## Requirements quality

- [x] Five user stories independently testable.
- [x] 35 functional requirements testable/numbered.
- [x] Direct Evidence observation is separated from security interpretation.
- [x] Coverage gaps and provider coverage modes are first-class.
- [x] LLM authority restrictions are explicit/testable.
- [x] Security of Sentrdel itself is covered.
- [x] Performance/FP/false-block criteria are measurable.
- [x] CLI exit semantics remain frozen by contract.

## Architecture

- [x] Nine-crate workspace responsibilities explicit.
- [x] Rust 1.98.0 exact R1 toolchain selected.
- [x] Apache-2.0 core license frozen.
- [x] Only `sentrdel-engine` may spawn external evidence engines.
- [x] Engine environment is deny-by-default/allowlisted.
- [x] Only reconciler creates canonical Findings.
- [x] SQLite + BLAKE3 + thin petgraph evidence graph documented.
- [x] gix/regorus/rmcp are qualified as dependencies requiring security wrappers, not blindly trusted foundations.
- [x] Regorus >=0.11.0 + byte/depth/subset bounds planned.
- [x] MCP stdio framing/version/payload caps planned; SDK defaults are not security authority.
- [x] Security Pack modes distinguish detection/static/live/business-logic/runtime.

## Security invariants

- [x] No shell-string command construction.
- [x] No target build/install/Cargo/package-manager execution during analysis.
- [x] No target hooks/external diff/textconv/filter/submodule/network/credential-helper execution during Git analysis.
- [x] Engine/MCP/Rego/repo inputs are bounded.
- [x] Secret plaintext and value-only unkeyed secret digest are forbidden in persistence.
- [x] ASEL is hash-linked with honest trusted-head semantics.
- [x] Kernel-invariant DENY is absorbing.
- [x] Repo policy may narrow, never widen.
- [x] LLM cannot emit FACT/VERIFIED through reasoner API.
- [x] Missing engine/provider-pack dimension cannot imply clean/secure.

## Source reuse / self supply chain

- [x] Core license: Apache-2.0.
- [x] Donor strategy documented.
- [x] SourceQualificationRecord includes privileged dependency properties.
- [x] Rust 1.98.0 avoids Cargo versions affected by CVE-2026-5223.
- [x] cargo-audit/cargo-deny required for release CI.
- [x] build.rs/proc-macro/native/download-at-build dependencies require elevated review.
- [x] cargo-vet, if later used, is only for the trusted Sentrdel workspace and not arbitrary target repositories.
- [ ] **PRE-REUSE GATE:** every copied/vendored donor source/data item has exact qualification.

## Testing strategy

- [x] Unit/contract/integration/adversarial/benchmark tiers defined.
- [x] MCP malformed/oversized/unterminated/version fixtures defined.
- [x] Engine inherited-secret environment canary defined.
- [x] Hostile Git config/Cargo config fixtures defined.
- [x] Regorus deep/oversized input tests defined.
- [x] Policy monotonicity proof defined.
- [x] Secret persistence canary defined.
- [x] Supabase detected-but-not-covered fixture defined.
- [x] Cross-platform base CI intent defined.

## Implementation gate

**Planning status:** READY_FOR_FINAL_ANALYZE  
**Coding status:** AUTHORIZED_AFTER_FINAL_ANALYZE

Implementation may proceed with Sentrdel-owned Rust code after the final consistency pass. Donor source/data reuse remains separately gated by exact source qualification. No R1 authority exists for live exploitation, remote MCP, provider credentials, production mutation, target build execution, or universal CPG work.
