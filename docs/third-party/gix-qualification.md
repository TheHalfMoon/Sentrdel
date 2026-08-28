# GIXQ-001 — gix 0.87.1 Qualification for T037

**Status:** `QUALIFIED_FOR_BOUNDED_READ_ONLY_GIT_DISCOVERY_AND_SNAPSHOTS`  
**Task:** T037  
**Qualified:** 2026-08-28

## Purpose

T037 needs local Git repository discovery plus read-only access to commit/tree/index objects without executing target-repository Git helpers, hooks, filters, textconv programs, credential helpers, submodule fetches, package/build commands, or network remotes.

Sentrdel uses `gix` only as a local object/index/ref reader. Diff classification, working-tree reads, binary classification, exact rename correlation, safety policy, and output semantics remain Sentrdel-owned.

## Exact upstream identity

- repository: `GitoxideLabs/gitoxide`
- crate: `gix =0.87.1`
- tag: `gix-v0.87.1`
- annotated tag object: `62e56ce06e437fae8b39b71a3f5ae20a6bd3cf84`
- dereferenced source commit: `3ebca8b66017ab2dd02a38f75f78f485bee1ded8`
- tag verification observed at qualification: unsigned; this is retained as a provenance limitation
- crates.io checksum: `fdefc1465d8631807deaf504dacdeff628b978de515653b47976ca7c28ab2a7a`
- license: `MIT OR Apache-2.0`
- upstream Rust minimum: 1.85
- Sentrdel compilation qualification: Rust 1.98.0

## Admitted feature surface

Direct dependency declaration:

```toml
gix = { version = "=0.87.1", default-features = false, features = ["sha1", "index", "revision"] }
```

Admitted features are exactly:

- `sha1` — SHA-1 Git object identifiers used by ordinary repositories;
- `index` — decode `.git/index` for staged and tracked working-tree snapshots;
- `revision` — resolve local revision expressions such as `HEAD` and an explicitly requested local base.

The broad `default`, `basic`, `comfort`, `extras`, and performance bundles are disabled.

The following capability features are explicitly **not admitted**:

- `command`;
- `attributes` / `excludes`;
- `blob-diff`;
- `status` / `dirwalk`;
- `worktree-mutation`;
- `credentials`;
- `submodule`;
- `blocking-network-client` / `async-network-client` and all HTTP transport features;
- `worktree-stream` / `worktree-archive`;
- `merge`, `blame`, `mailmap`, `notes`, and other unrelated extras.

T037 code MUST NOT call command, filter, transport, protocol-client, credential, submodule, status, attribute, checkout, or worktree-mutation APIs even if a plumbing crate exists in the locked transitive graph.

## Open/discovery boundary

Repository opening uses `gix::open::Options::isolated()` and never uses the environment-override opening APIs. Sentrdel performs bounded upward `.git` discovery itself and passes the discovered repository root into isolated `gix` open logic.

This prevents repository opening from using ambient Git environment configuration such as `GIT_DIR` and prevents configuration lookup from spreading outside the repository. Target-repository configuration remains untrusted data and does not authorize executable helpers.

## Diff architecture

T037 does not enable gix blob-diff/status/attribute machinery.

- **staged:** compare the local `HEAD` tree snapshot to the decoded index snapshot;
- **working tree:** compare decoded index entries to raw Sentrdel-owned filesystem reads for tracked paths only;
- **base:** compare an explicitly resolved local base tree to the local `HEAD` tree;
- **rename:** classify only exact add/delete pairs with identical object ids; no similarity engine or textconv is used;
- **binary:** classify from raw bytes with a bounded NUL-byte prefix heuristic; Git attributes/textconv are not consulted;
- **shallow/missing objects:** return an explicit local error/coverage condition; never fetch a remote to fill missing history.

T038 owns the broader bounded repository/file-view abstraction and additional symlink/confusable/oversize policy. T037 does not silently absorb that later task.

## Locked closure qualification

Qualification workflow:

- branch head: `5277caab3b2c9c0be47a8900a1db3b9f4c737323`
- workflow run: `33185941445`
- job: `98898847163`
- artifact: `t037-gix-qualification` / id `9691687880`
- artifact digest: `sha256:006440e379d4094a8bbcb99f39f174f1ba2376e1a25af27ec7691f21a9e7af38`

The workflow generated the lockfile, captured `cargo tree -p sentrdel-review -e features`, captured full Cargo metadata, and successfully compiled `sentrdel-review --all-targets --locked` on Rust 1.98.0.

The selected `sentrdel-review` closure contains 150 packages. Package presence is not feature/API authorization. In particular, gix base plumbing causes packages such as `gix-protocol`, `gix-transport`, `gix-command`, `gix-filter`, and `gix-attributes` to exist transitively even though Sentrdel does not enable the corresponding top-level client/filter/attribute capability features. The observed selected feature state includes:

- `gix`: `index`, `revision`, `sha1` only;
- `gix-protocol`: no client feature selected;
- `gix-command`: no feature selected;
- `gix-filter`: no feature selected;
- no `gix-credentials`, `gix-submodule`, `gix-status`, `gix-pathspec`, `gix-ignore`, or `gix-prompt` package in the selected closure.

A machine validator freezes these expectations so a later dependency/feature drift fails Self Security rather than silently widening T037 authority.

## Privileged compile-time closure

The new gix closure introduces locked packages with `custom-build`, `proc-macro`, or native `links` targets. They are recorded exhaustively in `docs/security/privileged-dependencies.toml` under `SSQ-001` unless a narrower qualification exists.

Newly observed privileged packages are:

| Package | Version | Surface | crates.io checksum |
|---|---:|---|---|
| `crc32fast` | 1.5.1 | build-script | `8498c871161e1742aaa9d52551b2d6ebdd4c3d45a3be423e3728f33b955be550` |
| `crossbeam-utils` | 0.8.22 | build-script | `61803da095bee82a81bb1a452ecc25d3b2f1416d1897eb86430c6159ef717c17` |
| `defmt` | 1.1.1 | build-script, native-link | `e2953bfe4f93bbd20cc71198842756f77d161884c99ebbabc41d80231ded88d1` |
| `defmt-macros` | 1.1.1 | build-script, proc-macro | `bad9c72e7ca2137e0dc3813245a0d282fd6daad32fd800af018306a9169b5fe8` |
| `generic-array` | 0.14.7 | build-script | `85649ca51fd72272d7821adaf274ad91c288277713d9c18820d8499a7ff69e9a` |
| `gix-macros` | 0.1.6 | proc-macro | `d3836b4b051393464a753c5a08fe19c7ce0d8b77574a92bd558972941d4553cb` |
| `heapless` | 0.8.0 | build-script | `0bfb9eb618601c89945a70e254898da93b13be0388091d42117462b265bb3fad` |
| `jiff-static` | 0.2.35 | proc-macro | `3a69dcb3a21cfb32ce1cd056169337ca284af0766dd766e7878819b251a49204` |
| `portable-atomic` | 1.15.0 | build-script | `05c8b63e8d9609db387f0324918f81d68fe27748f084ef092fb35954d0539a85` |
| `portable-atomic-util` | 0.2.7 | build-script | `c2a106d1259c23fac8e543272398ae0e3c0b8d33c88ed73d0cc71b0f1d902618` |
| `rustix` | 1.1.4 | build-script | `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190` |
| `rustversion` | 1.0.23 | build-script, proc-macro | `cf54715a573b99ac80df0bc206da022bcd442c974952c7b9720069370852e21f` |

`SSQ-001` means these exact locked compile/link surfaces are registered and mechanically gated; it does **not** claim a line-by-line audit of every transitive crate. T082 remains the release-grade dependency hardening gate.

## Security invariants

- target repositories are data, not authority;
- no Git subprocess is spawned by production T037 code;
- no hook is executed;
- no external diff or textconv process is executed;
- no clean/smudge filter process is executed;
- no credential helper is executed;
- no submodule is initialized or fetched;
- no remote is contacted;
- no target package/build command is executed;
- no missing object is repaired from a network remote;
- repository-local config cannot widen these invariants.

## Maintenance and removal cost

`gix` is fast-moving and has a broad internal crate graph. Any version, feature, or selected-closure change requires a new qualification delta, lockfile regeneration, privileged-surface validation, and exact-head CI.

Removal cost is moderate: T037 deliberately exposes Sentrdel-owned snapshot/change types rather than gix types, so the Git backend can be replaced without changing downstream Evidence or Finding contracts.
