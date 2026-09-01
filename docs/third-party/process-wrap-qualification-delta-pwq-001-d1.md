# PWQ-001-D1 — macOS post-reap process-group absence proof

**Parent qualification:** `PWQ-001`  
**Scope:** T027 external-engine process lifecycle containment on macOS only  
**Dependency identities:** unchanged — `process-wrap = 9.1.0`, `nix = 0.31.3`  
**Status:** `CANONICAL_QUALIFIED`

## Why this delta exists

Issue #138 exposed a macOS race in the already-qualified T027 process-group boundary. A short-lived process-group leader can exit while Sentrdel is handling an output-cap event, leaving process-group lifecycle state in which `process-wrap` 9.1.0 can report a group-kill error while the root/group teardown is still being reconciled.

The original `PWQ-001` record allowed Sentrdel's direct `nix` use only for structured `ESRCH` identity. PR #250 additionally uses safe `nix` process/signal wrappers on macOS to prove that the exact process group is absent after the existing `process-wrap` wrapper has reaped an exited root, plus a test-only current-process-group lookup for the live-group fail-closed canary. This is a privileged-use-boundary change and therefore receives this explicit qualification delta instead of being treated as covered implicitly by the original record.

## Exact dependency and feature analysis

No package identity, checksum, lockfile package graph, build script, proc-macro closure, native library closure, download path, or license expression changes.

The direct Unix dependency declaration becomes:

```toml
nix = { version = "=0.31.3", default-features = false, features = ["process", "signal"] }
```

This declaration does **not** introduce a new effective `nix` feature into the resolved T027 Unix build. `process-wrap` 9.1.0 already depends on `nix` with `signal`, and `nix` 0.31.3 defines `signal = ["process"]`. Cargo feature unification therefore already compiled both `signal` and `process` in the qualified closure. The delta changes Sentrdel's **direct safe API use**, not the resolved package/feature closure.

Relevant upstream identities remain those frozen by `PWQ-001`:

- `watchexec/process-wrap` `v9.1.0` / `3d856eebd02799d025237134db51d05bbc4f1434`;
- `nix-rust/nix` `v0.31.3` / `b5933ca178802b558a667514f717a86b3a1cedcc`;
- `nix` crate checksum `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d`.

`Cargo.lock` is unchanged by this delta.

## Admitted canonical direct API surface

On `target_os = "macos"` only, Sentrdel directly uses the following `nix` API surface, and no broader surface is implied:

- `nix::errno::Errno::{ESRCH, EPERM}` only for structured OS-error identity: initial group-kill `ESRCH`/`EPERM` select the fail-closed post-reap proof path, while only signal-zero-probe `ESRCH` proves absence;
- `nix::unistd::Pid`, including `Pid::from_raw(...)` to encode the exact negative process-group identifier captured from the spawned child and `Pid::as_raw()` in the test canary;
- `nix::sys::signal::kill` only with signal zero and the exact negative captured process-group PID to probe group existence without delivering a signal;
- `nix::sys::signal::Signal` only as the type parameter for `None::<Signal>` passed to `kill` to express signal zero; naming this type grants no additional signal-delivery or process-selection authority;
- `nix::unistd::getpgrp()` **only under `cfg(test)`** to obtain the test process's current live process-group ID for `signal_zero_probe_never_masks_a_live_process_group`, proving the absence probe cannot classify a known-live group as drained.

The production containment path does not call `getpgrp()`. The test-only lookup accepts no repository-controlled identifier, grants no process-selection authority, and exists solely as the owning-seam live-group fail-closed canary.

No signal is delivered by the signal-zero probe. In production, no arbitrary PID or process group comes from repository data: the identifier is captured from the already-admitted child created by the T027 containment wrapper. In the canary, the process-group identifier comes from the test runner's own current process group.

The delta grants no direct use of `nix` for filesystem access, networking, credentials, executable selection, process spawning, non-zero signal delivery, arbitrary process/group selection, policy decisions, repository traversal, target execution, or provider access.

## Fail-closed lifecycle rule

On macOS, neither an initial group-kill `ESRCH` nor an initial group-kill `EPERM` is accepted as quiescence by itself.

The only admitted recovery path for either error is:

1. the original `process-wrap` group kill reports `ESRCH` or `EPERM`;
2. the existing `process-wrap` child wrapper must return `Ok(Some(_))` from `try_wait()`, proving/reaping an exited root through its process-group wait path;
3. Sentrdel probes the exact captured process-group ID with signal `0`;
4. only `ESRCH` from that **post-reap signal-zero probe** is accepted as an absent/drained process boundary;
5. a running root, failed reap, live process group, inaccessible process group, conversion failure, or any indeterminate result preserves the original kill failure.

On Unix targets other than macOS, the previously qualified direct group-kill `ESRCH` handling remains unchanged.

`sentrdel-engine` continues to enforce `#![forbid(unsafe_code)]`; all platform FFI/unsafe implementation remains inside the already-qualified dependency boundary.

## Deterministic recovery qualification

The macOS owning seam includes deterministic unit coverage for the recovery classifier itself, not only a live process-group canary:

- `process_tree::tests::kill_error_recovery_requires_reap_then_absence_proof` exercises both initial `ESRCH` and `EPERM`, proves the absence probe is not invoked when reap fails, proves successful classification requires reap before the absence proof, and proves a reaped root with a non-absent/live group remains rejected;
- `process_tree::tests::signal_zero_result_accepts_only_esrch_as_absence` proves that only signal-zero `Err(ESRCH)` means absent, while success, `EPERM`, and other errors remain fail-closed;
- `process_tree::tests::signal_zero_probe_never_masks_a_live_process_group` retains the real macOS known-live process-group canary;
- `runner::tests::runner_enforces_wall_clock_output_caps_and_kills_descendants` retains the owning runner lifecycle proof.

The deterministic helpers exist only to make the production ordering and classification rules directly testable. They do not add a new process-control capability or authority surface.

## Qualification evidence and candidate discipline

Earlier candidate heads are historical diagnostic evidence only. They do not qualify the final PR head:

- unsafe direct FFI was rejected by `#![forbid(unsafe_code)]`;
- pre-reap signal-zero probing was rejected by macOS lifecycle qualification;
- cross-platform cfg warnings were rejected by `clippy -D warnings`;
- incomplete macOS live-group qualification coverage was found by independent review;
- a later exact-head review found that accepting initial macOS group-kill `ESRCH` before reap/probe was inconsistent with this fail-closed lifecycle rule;
- an exact-head governance review then found that the test-only `getpgrp()` canary API was omitted from the admitted direct API record;
- the next exact-head review found that the directly named `nix::sys::signal::Signal` type was also omitted;
- the subsequent live review found two additional qualification defects: the recovery branch lacked deterministic post-reap ordering/classification tests, and the source ledger described PWQ-001-D1 as already qualified before canonicalization. The final candidate added the deterministic tests and kept PWQ-001-D1 candidate-only until protected-main canonicalization and post-merge governance verification.

The final candidate then received a fresh exact-current-head qualification cycle. Historical CI or review did not substitute for that gate.

Required final-head evidence was satisfied by:

- `Cross-platform CI` success on Linux, macOS, and Windows;
- macOS `process_tree::tests::kill_error_recovery_requires_reap_then_absence_proof` success;
- macOS `process_tree::tests::signal_zero_result_accepts_only_esrch_as_absence` success;
- macOS `process_tree::tests::signal_zero_probe_never_masks_a_live_process_group` success;
- macOS `runner::tests::runner_enforces_wall_clock_output_caps_and_kills_descendants` success;
- Windows `sentrdel-review` clippy with `-D warnings` success;
- `Bootstrap CI` success;
- `Schema Lock Qualification` success;
- `Self Security` success;
- clean independent exact-head review;
- zero unresolved review conversations.

## Canonical closeout evidence

PWQ-001-D1 is canonical only because every pre-merge and post-merge gate completed on the recorded identities below.

### Guarded merge identity

- PR: `#250`
- final PR head: `317a4ec2083ad751bce344e19838efcc6ac5c1de`
- canonical base before merge: `81ce86472754b9a9cc04630f198d0022f26193ac`
- merge method: merge commit with guarded `expected_head_sha`
- canonical merge/main SHA: `b61b0e532a68ce5b56c7c4e27c41ac43484b6ae7`

### Exact-head pre-merge evidence

All listed runs targeted final PR head `317a4ec2083ad751bce344e19838efcc6ac5c1de`:

- `Self Security` run `33521211369`: `success`;
- `Cross-platform CI` run `33521211225`: `success`;
- `Schema Lock Qualification` run `33521211307`: `success`;
- `Bootstrap CI` run `33521211218`: `success`;
- Cubic independent exact-head review: completed successfully with no issues across the five changed files;
- review conversations: zero unresolved at merge;
- GitHub mergeability: clean against unchanged canonical base.

### Canonical post-merge evidence

All listed runs targeted canonical `main` SHA `b61b0e532a68ce5b56c7c4e27c41ac43484b6ae7`:

- `Self Security` run `33523055645`: `success`;
- `Cross-platform CI` run `33523054818`: `success`, including macOS T027 lifecycle qualification and Windows review lint;
- `Bootstrap CI` run `33523054824`: `success`;
- `Schema Lock Qualification` run `33523054834`: `success`.

### Live repository-governance verification

A bounded non-gate probe, based exactly on canonical main `b61b0e532a68ce5b56c7c4e27c41ac43484b6ae7`, used only the masked repository secret `SENTRDEL_GOVERNANCE_ADMIN_TOKEN`, unset the built-in `GITHUB_TOKEN`, used checkout with `persist-credentials: false`, and ran `scripts/verify_repository_governance.py`.

- workflow run: `33523152820`;
- job: `99907174845`;
- result: `success`;
- verifier output: `repository-governance: PASS`;
- verified branch: `main`;
- verified head: `b61b0e532a68ce5b56c7c4e27c41ac43484b6ae7`;
- verified required checks: `Dependency security`, `Resolve and test schema substrate`, `Rust 1.98 bootstrap`;
- active repository rulesets reported by the verifier: `0`.

The temporary workflow was removed from its non-canonical probe branch in commit `938f1684042ee676d4183a2c7754e4adac8e95be`. It never modified canonical `main`, never persisted the credential, and never used the credential for mutation.

## Authority and non-claims

This delta proves only the tested T027 POSIX process-group lifecycle seam on macOS. It does not claim or authorize:

- hostile-code sandboxing;
- per-process network isolation;
- provider or production access;
- target repository build/script execution;
- identical process semantics across operating systems;
- Windows Job Object runtime qualification;
- `LIVE_POSTURE`, target SQL execution, or R3 `BUSINESS_LOGIC`;
- any policy, Finding, Evidence-class, or reconciler authority for `process-wrap` or `nix`.

The original `PWQ-001` authority ceilings remain binding.

## Canonicalization result

The canonicalization gate is satisfied for the exact identities recorded above. PWQ-001-D1 is part of canonical `PWQ-001` for the bounded macOS T027 process-group lifecycle seam described in this document.

Any later `process-wrap`/`nix` version change, resolved feature-closure expansion, additional direct privileged API use, or broader platform claim requires another qualification delta.
