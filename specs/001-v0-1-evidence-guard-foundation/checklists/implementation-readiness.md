# Implementation Readiness Checklist — R1

**Feature:** Sentrdel v0.1 Evidence + Guard Foundation  
**Date:** 2026-08-24

## Scope and product

- [x] R1 is bounded and linked to the A-to-Z spec-of-specs roadmap.
- [x] Rust-first trusted core is explicit.
- [x] Vendor-neutral/local-first behavior is explicit.
- [x] Guard enforcement vs advisory fidelity is explicit.
- [x] Universal CPG construction is explicitly out of scope.
- [x] Full Supabase/provider security is deferred to R3 while provider detection/pack contract is in R1.
- [x] Verification execution is explicitly out of R1.
- [x] IDE/GitHub App/runtime enforcement are explicitly out of R1.

## Requirements quality

- [x] User stories are independently testable.
- [x] Functional requirements are testable and numbered.
- [x] Coverage gaps are first-class requirements.
- [x] LLM authority restrictions are explicit and testable.
- [x] Security of Sentrdel itself is covered.
- [x] Performance/FP/false-block success criteria are measurable.
- [x] CLI exit semantics are frozen in a contract.

## Architecture

- [x] Nine-crate Rust workspace has explicit responsibilities.
- [x] Only `sentrdel-engine` may spawn external security engines.
- [x] Only reconciler creates canonical Findings.
- [x] SQLite + content-addressed local store decision is documented.
- [x] Thin evidence/property graph decision is documented.
- [x] Tree-sitter/ast-grep native baseline is researched.
- [x] `gix`, `regorus`, and official MCP Rust SDK are researched with current maturity/version observations.
- [x] External-engine and Security Pack contracts are documented.
- [x] Supabase future capability requirements fit the pack contract.

## Security invariants

- [x] No shell-string target command construction.
- [x] Target build/install scripts do not run during analysis.
- [x] Target repository hooks do not run during analysis.
- [x] Untrusted engine output is bounded/validated.
- [x] Secret plaintext is redacted before persistence.
- [x] ASEL is append-only and hash chained.
- [x] Kernel-invariant DENY is absorbing.
- [x] Repository policy may narrow, never widen, core/user policy.
- [x] LLM cannot emit FACT/VERIFIED authority through reasoner API.
- [x] Missing engines cannot yield an implicit clean result.

## Source reuse / licensing

- [x] Donor strategy is documented.
- [x] Graphify/code-graph-rag/DeepSeek Harness/Continue are classified as selective reference/adaptation rather than wholesale runtime foundations.
- [x] SourceQualificationRecord is part of the data model.
- [ ] **PRE-IMPLEMENTATION GATE:** founder freezes the repository/core license before any donor source/data is copied or vendored.
- [ ] **PRE-REUSE GATE:** every copied/vendored donor source/data item has an exact source qualification record.

## Testing strategy

- [x] Unit tests defined.
- [x] Contract tests defined.
- [x] Integration fixture repositories defined.
- [x] MCP gateway fixture test defined.
- [x] Adversarial prompt-injection tests defined.
- [x] Engine malformed/oversized/path-escape tests defined.
- [x] Policy monotonicity property test defined.
- [x] Secret persistence canary test defined.
- [x] Supabase detected-but-not-covered fixture defined.
- [x] Cross-platform base review/init CI intent defined.

## Implementation gate

**Planning status:** READY_FOR_TASKS_AND_CONSISTENCY_ANALYSIS  
**Coding status:** NOT_STARTED

Coding MUST NOT copy donor source before the license/source-reuse gates above are satisfied. Pure Sentrdel-owned bootstrap/schema implementation can start once `tasks.md` and consistency analysis are complete and the founder authorizes implementation.
