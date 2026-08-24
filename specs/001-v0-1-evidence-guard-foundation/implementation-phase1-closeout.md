# R1 Implementation Phase 1 Closeout — Governance + Workspace Bootstrap

**Date:** 2026-08-24  
**Branch:** `impl/001-v0-1-foundation`  
**Base:** `489f6372a07fdd042320fddbd059158c15d80e4d`  
**Status:** IMPLEMENTED_PENDING_FINAL_EXACT_HEAD_CI

## Tasks completed

The implementation satisfies the substance of Spec Kit Phase 1 tasks **T001–T007**:

- T001 — Apache-2.0 core license verified; third-party adoption policy created.
- T002 — Rust 1.98.0 nine-crate workspace created; bootstrap `Cargo.lock` committed.
- T003 — workspace format/check/test/clippy gates and Bootstrap CI created.
- T004 — `deny.toml` and dependency security policy created with privileged dependency review rules.
- T005 — source qualification ledger created with donor projects retained as STUDY/ADAPT only; no donor source/data copied.
- T006 — fixture/test directory skeleton created.
- T007 — root `AGENTS.md` and `SECURITY.md` created with implementation/security boundaries.

Task checkboxes in the authoritative `tasks.md` should be reconciled in the next Spec Kit progress update; this closeout is the exact implementation evidence for T001–T007.

## Exact implementation decisions

- Rust toolchain: `1.98.0` exact.
- Edition: 2024.
- Workspace resolver: 3.
- Trusted core crates: nine, exactly as planned.
- Third-party Rust crate dependencies: **none** at Phase 1 closeout.
- External scanners/engines: **none**.
- Donor source/data copied: **none**.
- Target repository execution: **none**.
- Unsafe Rust: forbidden by workspace/crate policy.
- Remote MCP: not implemented.
- Verification/exploitation/provider credentials: not implemented or accessed.

## CI and workflow self-security

Bootstrap CI runs pinned Rust 1.98.0 and the canonical gates:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo test --workspace --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`

`actions/checkout` is pinned to immutable commit:

`11d5960a326750d5838078e36cf38b85af677262`

with `persist-credentials: false`.

A prior exact-head run at `cce8782379cc7bf10746d7fea929ce2f1aa3ce3a` passed before the final workflow/ledger/closeout hardening. The final head must receive its own successful CI run before this PR is Ready or merged.

## Security review notes

The bootstrap intentionally avoids adding convenience dependencies early. Later crates such as `gix`, `ast-grep-core`, `regorus`, `rmcp`, `rusqlite`, `petgraph`, `serde`, and others enter only through their corresponding Spec Kit task with exact feature/license/supply-chain qualification.

The repository already applies to itself one planned R1 rule: GitHub Actions dependencies are pinned by immutable SHA rather than a mutable major-version tag.

## Remaining gate

`PHASE1_CLOSED_CANONICAL` requires:

1. final exact-head Bootstrap CI PASS;
2. PR changed-file review against constitution/spec/tasks;
3. no new unqualified dependency/source introduced after this closeout;
4. merge using the exact reviewed head.
