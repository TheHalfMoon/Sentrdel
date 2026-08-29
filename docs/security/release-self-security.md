# R1 Release Self-Security

**Task:** T082  
**Scope:** Sentrdel trusted workspace only  
**Advisory snapshot reviewed:** 2026-08-29

## Release gate

The stable protected-main check remains `Dependency security` under `.github/workflows/self-security.yml`. T082 strengthens that existing gate rather than introducing a replacement status context.

The release-grade path requires:

1. exact Rust `1.98.0` toolchain policy;
2. committed and locked Cargo resolution;
3. source qualification and privileged dependency declarations;
4. package-wide malicious-crate defense-in-depth denylist validation;
5. current RustSec advisory evaluation through checksum-pinned `cargo-audit`;
6. cargo-deny advisory, ban, license, and source policy;
7. a weekly advisory-refresh execution of the same read-only trusted-workspace gate.

The scheduled path has no target repository input, no alternate working directory, read-only repository permission, and no persisted checkout credential.

## Malicious-package defense in depth

`docs/security/malicious-package-denylist.toml` is intentionally narrower than an arbitrary malware feed. A package is admitted to the package-wide denylist only when a reviewed RustSec advisory classifies that package as malicious and reports no patched versions.

The 2026-08-29 snapshot records these RustSec package-wide advisories:

- `RUSTSEC-2025-0154` — `replit_ruspty`
- `RUSTSEC-2025-0155` — `rands`
- `RUSTSEC-2026-0018` — `rpc-check`
- `RUSTSEC-2026-0019` — `tracing-check`
- `RUSTSEC-2026-0027` — `tracings`
- `RUSTSEC-2026-0028` — `tracing_checks`
- `RUSTSEC-2026-0030` — `time_calibrator`
- `RUSTSEC-2026-0036` — `time-sync`
- `RUSTSEC-2023-0114` — `tiny-server`

Each record links directly to its RustSec advisory. The denylist is defense in depth only: it is not a substitute for version-aware RustSec evaluation, and it is not claimed to be exhaustive.

## Fail-closed validation

`scripts/validate_release_dependency_policy.py` fails when:

- the toolchain pin drifts from Rust 1.98.0;
- the committed lockfile contract is malformed;
- the malicious-package denylist is malformed, duplicated, or does not point to the matching HTTPS RustSec advisory;
- a package-wide denied crate appears in current locked metadata;
- the recurring release advisory refresh path disappears; or
- the self-security workflow gains a target-redirection surface such as an alternate working directory or workflow input.

The validator has direct unit coverage in `scripts/test_validate_release_dependency_policy.py`, including a malicious-package canary.

## Non-claims

- PASS does not prove every dependency is behaviorally safe or free of undisclosed vulnerabilities.
- The committed denylist is not a complete malware database.
- The weekly refresh does not create autonomous dependency updates or modify the lockfile.
- T082 does not authorize `cargo-vet`, arbitrary target-repository Cargo execution, package installation, credential use, or release artifact signing/attestation.
- Privileged dependency qualification remains a governed evidence record; it is not replaced by advisory scanning.
