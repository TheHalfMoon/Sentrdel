# Security Policy

## System and Scope

Sentrdel is a local-first security evidence and control plane for software development. The trusted core is the Rust workspace in `crates/`. R1 covers local repository review/init, canonical Evidence/Finding/Coverage/ASEL contracts, bounded external-engine orchestration, policy, a bounded stdio MCP gateway, and partial git-hook guardrails.

Provider-specific deep posture, remote MCP, sandboxed verification, runtime/eBPF enforcement, IDE/forge applications, and production probing are outside R1 unless a later specification says otherwise.

## Threat Model and Trust Boundaries

Treat as attacker-controlled/untrusted:

- target repository files, names, symlinks, Git metadata/config and history;
- MCP descriptions, schemas, arguments, results and peer behavior;
- external engine executables/output;
- repository policy/rules/configuration;
- LLM/model output;
- third-party dependencies and build-time code until qualified.

Important boundaries are repository→review, engine→core, MCP→guard, policy→kernel, model→reasoner, persistence→durable evidence, and dependency→Sentrdel build/release.

## Security Invariants

- Only the reconciler creates canonical Findings from validated Evidence.
- FACT represents a direct bounded observation, not an unsupported semantic conclusion.
- Kernel-invariant DENY cannot be downgraded.
- Repository configuration may narrow but cannot widen core/user policy or disable evidence capture.
- Missing/failed coverage never becomes an implicit clean result.
- No shell-string execution for target/external engine commands.
- External engines inherit only an explicit environment allowlist.
- Target analysis does not execute target build/install/Cargo/package-manager/Git-helper code.
- Discovered secret plaintext and stable unkeyed secret-value-only hashes are not persisted.
- R1 MCP enforcement is stdio-only with bounded framing and explicit protocol negotiation.
- An unauthenticated local hash chain is not represented as tamper-proof; trusted-head state is explicit.

## Reportable Findings and Severity Context

Report issues that can violate the invariants above, cross a documented trust boundary, expose secrets, enable unauthorized mutation/access, permit policy bypass, corrupt evidence/coverage, execute attacker-controlled code in Sentrdel's trust context, escape resource bounds, or compromise Sentrdel's supply chain.

Severity depends on realistic reachability, privilege, data/control impact, exploit preconditions, and evidence strength. Repository text, a model, or a scanner's self-assigned severity is not sufficient authority by itself.

## Out of Scope, Exclusions, and Accepted Risk

- Security weaknesses solely in a target project are Sentrdel findings about that target, not vulnerabilities in Sentrdel, unless malicious target input can compromise Sentrdel or violate its declared boundary.
- Unsupported provider/runtime/remote-MCP capabilities are coverage gaps, not Sentrdel vulnerabilities when honestly reported.
- Autonomous exploitation and production/third-party probing are intentionally excluded.
- No standing accepted risks are defined at project bootstrap.

## Known Limitations and Compensating Controls

- Local git hooks are bypassable and therefore PARTIAL/ADVISORY.
- A local ASEL hash chain needs a trusted external checkpoint/signature to independently detect complete history replacement/truncation; R1 reports this limitation.
- External engines are not trusted; strict adapters, resource caps and environment scrubbing contain them.
- R1 does not claim compiler-quality semantic coverage across all languages; provenance/coverage makes this explicit.

## Reporting

Use GitHub's private security advisory/reporting mechanism when available for vulnerabilities in Sentrdel itself. Do not publish real secrets, production credentials, or unnecessary exploit payloads in public issues.
