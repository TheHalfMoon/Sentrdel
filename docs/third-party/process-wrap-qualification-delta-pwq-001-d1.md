# PWQ-001-D1 — macOS post-reap process-group absence proof

**Parent qualification:** `PWQ-001`  
**Scope:** T027 external-engine process lifecycle containment on macOS only  
**Dependency identities:** unchanged — `process-wrap = 9.1.0`, `nix = 0.31.3`  
**Status:** `CANDIDATE_PENDING_EXACT_HEAD_QUALIFICATION`

## Why this delta exists

Issue #138 exposed a macOS race in the already-qualified T027 process-group boundary. A short-lived process-group leader can exit while Sentrdel is handling an output-cap event, leaving process-group lifecycle state in which `process-wrap` 9.1.0 can report a group-kill error while the root/group teardown is still being reconciled.

The original `PWQ-001` record allowed Sentrdel's direct `nix` use only for structured `ESRCH` identity. PR #250 additionally uses safe `nix` PID/signal wrappers on macOS to prove that the exact process group is absent after the existing `process-wrap` wrapper has reaped an exited root. This is a privileged-use-boundary change and therefore receives this explicit qualification delta instead of being treated as covered implicitly by the original record.

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

## Admitted direct API surface

On `target_os = "macos"` only, first-party `sentrdel-engine` may use:

- `nix::unistd::Pid` to represent the exact process-group ID captured from the spawned child;
- `nix::sys::signal::kill` with signal `0` and a negative PID to probe that exact process group;
- `nix::errno::Errno::ESRCH` as the only signal-zero result proving that the process group no longer exists.

No signal is delivered by the signal-zero probe. No arbitrary PID or process group comes from repository data: the identifier is captured from the already-admitted child created by the T027 containment wrapper.

The delta grants no direct use of `nix` for filesystem access, networking, credentials, executable selection, process spawning, policy decisions, repository traversal, target execution, or provider access.

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

## Qualification evidence and candidate discipline

Earlier candidate heads are historical diagnostic evidence only. They do not qualify the final PR head:

- unsafe direct FFI was rejected by `#![forbid(unsafe_code)]`;
- pre-reap signal-zero probing was rejected by macOS lifecycle qualification;
- cross-platform cfg warnings were rejected by `clippy -D warnings`;
- incomplete macOS live-group qualification coverage was found by independent review;
- a later exact-head review found that accepting initial macOS group-kill `ESRCH` before reap/probe was inconsistent with this fail-closed lifecycle rule.

The corrected candidate must therefore receive a **fresh exact-current-head** qualification cycle after this document and the implementation agree. No historical CI or review result substitutes for the final gate.

Required final-head evidence includes:

- `Cross-platform CI` success on Linux, macOS, and Windows;
- macOS `process_tree::tests::signal_zero_probe_never_masks_a_live_process_group` success;
- macOS `runner::tests::runner_enforces_wall_clock_output_caps_and_kills_descendants` success;
- Windows `sentrdel-review` clippy with `-D warnings` success;
- `Bootstrap CI` success;
- `Schema Lock Qualification` success;
- `Self Security` success;
- clean independent review of the exact current head;
- zero unresolved review conversations.

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

## Canonicalization gate

This delta has no canonical authority merely because it exists on a feature branch. It becomes part of `PWQ-001` only if PR #250 reaches protected `main` after all of the following are true on the exact final head:

- every applicable required and project qualification check is successful;
- independent review is clean;
- all review conversations are resolved;
- mergeability is clean;
- merge uses guarded expected-head semantics;
- post-merge repository-governance verification passes against the resulting canonical `main`.

Any later `process-wrap`/`nix` version change, resolved feature-closure expansion, additional direct privileged API use, or broader platform claim requires another qualification delta.