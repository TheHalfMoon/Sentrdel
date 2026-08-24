# Major Architecture, Security, and Market Review — 2026-08-24

**Status:** ACCEPTED_AMENDMENTS  
**Scope:** R1 plan and Sentrdel product architecture  
**Review basis:** exact PR #1 planning head plus fresh upstream/security/product research as of 2026-08-24.

## Executive verdict

**GO — WITH PRE-IMPLEMENTATION HARDENING APPLIED.**

The core thesis survives: Rust trusted core, local-first/vendor-neutral operation, Evidence-before-Finding, honest guard fidelity, bounded external engines, and provider-aware A-to-Z security are the right strategic direction.

The review found no reason to replace the architecture, but it found several places where the original R1 plan was too trusting of dependencies or too slow to prioritize provider posture. The changes below are binding amendments to R1 and the roadmap.

## 1. Category and competitive position

Fresh 2026 product research confirms that generic "security scanning while AI codes" is already commoditizing:

- Semgrep Guardian runs inside coding-agent workflows using MCP/hooks/skills and reports millions of weekly scans with low inline latency.
- GitHub automatically validates code from third-party coding agents with CodeQL, dependency/advisory checks and secret scanning.
- OpenAI Codex Security and Anthropic Claude Code Security both perform contextual repository security analysis; Codex Security adds isolated validation/remediation.

Therefore Sentrdel MUST NOT define its moat as "real-time AI code scanning," rule count, or an IDE-specific scanner.

### Category Sentrdel should own

**The open-source security evidence and control plane for the whole software project — from agent action to production.**

Defensible product assets:

1. canonical evidence schema and proof/coverage semantics;
2. ASEL vendor-neutral agent-action ledger;
3. independent reconciliation across native rules, provider packs, external engines, runtime/test evidence and optional LLM hypotheses;
4. explicit coverage truth instead of silent clean results;
5. project security invariants and business-logic substrate;
6. provider-aware A-to-Z posture, beginning with Supabase;
7. local-first Rust distribution and inspectable evidence.

## 2. Rust toolchain and self supply chain

### Decision

Pin R1 implementation to **Rust 1.98.0** initially, not the previously proposed 1.88 floor.

### Basis

- Rust 1.98.0 was released 2026-08-20 and is current stable during this review.
- Cargo versions shipped before Rust 1.96.0 were affected by CVE-2026-5223 involving symlinks in third-party registry crate archives.
- On 2026-08-20 the Rust Security Response Team disclosed a real crates.io supply-chain incident involving malicious crates/build scripts and a compromised release of `arrayref`.

### Binding consequences

- `rust-toolchain.toml` pins `1.98.0` for R1.
- `Cargo.lock` is committed once dependencies exist.
- `cargo-audit` and `cargo-deny` are required CI gates.
- New dependencies require explicit justification.
- Dependencies with `build.rs`, procedural macros, native compilation, downloaded artifacts, or credential/network behavior receive elevated source qualification.
- `cargo-vet` MAY later be used for Sentrdel's own trusted first-party dependency governance, but MUST NOT be run against untrusted target repositories. Cargo commands can honor repository `.cargo/config.toml` and are not inherently safe on hostile repositories.

## 3. MCP gateway hardening

### Finding

The official Rust MCP SDK (`rmcp`) remains the preferred protocol/model dependency, but R1 MUST NOT blindly delegate transport safety to its defaults.

Current review found:

- rmcp 3.x is active and Apache-2.0;
- a prior Streamable HTTP DNS-rebinding issue was patched in the SDK;
- an open 2026 issue describes unbounded line buffering in the async stdio transport, creating memory-exhaustion risk;
- protocol-version constants/defaults may lag the newest supported conformance version, so implicit `LATEST`/default semantics are not sufficient for a security gateway.

### Decision

R1 MCP scope becomes **stdio gateway only**.

Sentrdel will:

- use qualified rmcp model/protocol capabilities;
- own a bounded stdio framing/reader boundary with maximum frame size and total buffered-byte caps;
- negotiate/validate protocol versions explicitly;
- reject unsupported version transitions fail-closed;
- cap tool descriptions, schemas, request arguments and result payloads before persistence/policy/reasoning;
- never interpret tool descriptions/results as policy instructions.

Remote/Streamable HTTP MCP is deferred to a dedicated later specification requiring DNS-rebinding defenses, explicit allowed hosts, redirect policy, TLS/auth policy and remote transport threat modeling.

## 4. Regorus/Rego hardening

Regorus remains the preferred in-process Rego implementation, but R1 must pin a version including current recursion/deep-input protections and must wrap it defensively.

Binding controls:

- pin qualified Regorus **>=0.11.0**;
- maximum policy source bytes;
- maximum JSON/input depth and object size;
- tested allowlist/subset of supported builtins/features;
- compile/load policy outside per-action hot path;
- bounded evaluation time/work where feasible;
- kernel invariants remain Rust-owned and cannot be replaced by Rego.

## 5. Evidence epistemic precision

The evidence model is strengthened:

- `FACT` means a directly observable bounded property only.
- Example FACT: "literal matching rule X appears at file Y line Z."
- Not FACT: "this credential is valid," "this route is exploitable," or "this user can cross tenants" unless appropriate execution/semantic evidence exists.
- Security interpretation remains INFERENCE/HYPOTHESIS unless supported by stronger producer authority.

Evidence should distinguish the direct observation/basis from the security interpretation so a consumer can audit how the conclusion was reached.

## 6. Secret persistence

Discovered secret plaintext MUST never be persisted by default.

Additionally, Sentrdel MUST NOT persist a stable unkeyed digest computed solely from the discovered secret value, because low-entropy secrets/tokens may be dictionary-attackable offline.

Persist instead:

- repository-relative location;
- rule identifier/type;
- redacted display token;
- optional sanitized surrounding-content fingerprint not derived solely from the secret;
- evidence/input content hashes that do not expose the secret value.

## 7. Git and repository safety

Read-only analysis MUST avoid hidden execution surfaces.

R1 Git implementation must not:

- execute repository hooks;
- invoke external diff/textconv/filter processes;
- fetch submodules;
- follow repository-configured credential helpers or network remotes;
- run Cargo/npm/pip or repository tooling merely to discover metadata.

Prefer minimal `gix` features and bounded direct parsing. Any fallback external `git` command needs a separate security qualification and scrubbed environment.

## 8. External engine process boundary

The engine runner's environment is deny-by-default/allowlisted.

It MUST NOT inherit the developer's complete environment into external scanners. In particular, cloud credentials, model/provider API keys, signing credentials, SSH-agent sockets and unrelated secrets are not inherited unless an explicit engine capability and user policy authorizes them.

No shell strings; bounded cwd/time/process/output; validated executable identity; strict output parsing remain required.

## 9. Integrity language

ASEL/content chains provide integrity linkage and replay verification.

A local chain alone does not independently prove that an attacker with write access did not replace/truncate the entire chain and its head. R1 therefore uses precise language:

- `chain-valid` / `integrity-linked` / `head hash`;
- not `tamper-proof`.

Later signing/remote attestation can strengthen the trusted-checkpoint story.

## 10. Supabase roadmap acceleration

Fresh Supabase documentation shows a large deterministic posture surface that does **not** require waiting for the full business-logic engine:

- RLS enabled/missing-policy states;
- grants and function EXECUTE privileges;
- SECURITY DEFINER/view/function risks;
- mutable `search_path`;
- sensitive columns exposed through the Data API;
- Storage/public bucket/listing/ownership-policy issues;
- service-role/secret-key client exposure;
- Auth/anonymous-sign-in posture and related configuration signals.

### Roadmap change

- **R2 becomes Supabase P0 Static/Posture Pack.** Offline deterministic checks first; optional explicit credentialed live posture is a later mode.
- **R3 becomes Business-Logic Substrate + Invariants.** This augments Supabase with cross-layer route/guard/tenant semantics and then generalizes.
- **R4 becomes Provider Pack Expansion** (Firebase/Auth/Stripe/deploy/cloud) while CI/IDE integration moves after the core/provider posture foundation.

This gives Sentrdel early A-to-Z differentiation without pretending to solve business logic before the substrate exists.

## 11. CI security detector expansion

R1's GitHub Actions producer must include high-signal evidence/candidates for:

- broad or write repository permissions;
- `id-token: write` / OIDC trust-sensitive changes;
- secret use in untrusted PR contexts;
- `pull_request_target` and checkout/execution of attacker-controlled code;
- untrusted expression interpolation into shell/run commands;
- mutable action references vs full commit SHA pinning;
- self-hosted runner exposure to untrusted contributions;
- workflow/artifact/cache handoff candidates where trust changes.

It remains a high-signal change detector, not a claim of complete GitHub Actions security.

## 12. Security policy in repository

R1 Phase 1 must add root `SECURITY.md` as reviewer/scanner guidance containing:

- system and scope;
- threat model/trust boundaries;
- security invariants;
- reportable findings/severity context;
- explicit exclusions/known limitations.

`SECURITY.md` is security context, never executable authority and never permission to run commands or suppress findings.

## 13. Dependency adoption decisions

The previous donor decisions remain broadly valid:

- native/adopt: tree-sitter, ast-grep-core, petgraph, qualified gix/regorus/rmcp;
- semantic precision: SCIP and optional external engines;
- study/adapt: Graphify, code-graph-rag, DeepSeek Harness, Continue;
- no Python/Memgraph/JVM runtime becomes mandatory for base Sentrdel solely for reuse convenience.

Every dependency/source still passes exact license/provenance/security qualification.

## 14. License decision

Founder authorization to proceed resolves the open core-license gate with:

**Sentrdel Core License: Apache License 2.0.**

This is compatible with the project's intended permissive infrastructure role and explicit patent grant. It does not waive per-source donor qualification.

## Final implementation gate

R1 may proceed after these amendments are reflected in the authoritative Spec Kit artifacts.

Still prohibited without later explicit specification/authorization:

- autonomous exploitation;
- production or third-party target probing;
- credential access for provider posture by default;
- remote MCP transport in R1;
- universal CPG construction;
- target build/install execution during analysis;
- copying unqualified donor source/data.
