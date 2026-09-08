# Source Candidate Assessment — 2026-09-08

**Status:** RESEARCH_CANDIDATE_ASSESSMENT  
**Sentrdel planning base:** `main@bf50d14ef3747b028069d148f23c1696e9e67a42`  
**Related roadmap supplement:** `specs/000-sentrdel-roadmap/source-driven-security-expansion-2026-09-08.md`  
**Authority:** Research/provenance record only. This is **not** a source-qualification ledger entry and does not authorize copying, vendoring, linking, dependency adoption, dataset import, runtime execution, network access, credentials, target scanning, or dynamic verification. Any future reuse still requires the exact qualification required by the Constitution, `AGENTS.md`, and `docs/third-party/source-qualification-ledger.md`.

## Assessment method

Each source was evaluated against Sentrdel's current category and trust model using:

- exact upstream default-branch commit;
- repository license observation;
- capability fit with the SSG / Evidence / Coverage / invariant-regression strategy;
- build/runtime/dependency/credential/network authority;
- benchmark and provenance value;
- maintenance/freshness observation;
- whether reuse is more defensible than rebuilding;
- whether the source should be code, an external engine, a benchmark reference, a taxonomy reference, or knowledge only.

Repository-level licensing is not treated as proof that every embedded dataset, third-party sample, model, image, PoC, or generated artifact has identical reuse rights.

## Summary matrix

| ID | Source | Exact research pin | Default branch | License observation | Freshness observation | Research decision |
|---|---|---|---|---|---|---|
| SRC-2026-09-AIG | `Tencent/AI-Infra-Guard` | `e4e622af3ad2b8228ce82dd62b01415dd8ce2b9c` | `main` | Apache-2.0 repository license observed | exact head dated 2026-09-04; active 2026 release line | `HIGH_PRIORITY_TAXONOMY_AND_CONFORMANCE_REFERENCE` |
| SRC-2026-09-MAGIKA | `google/magika` | `26b6a9ba7e92f2b0a3745970a9190ec0dde9bf83` | `main` | Apache-2.0 repository/package license observed | exact head dated 2026-09-07; active | `HIGH_PRIORITY_OPTIONAL_ARTIFACT_CLASSIFIER_CANDIDATE` |
| SRC-2026-09-ASE | `Tencent/AICGSecEval` | `94428ebf45141bf4ecd365a51d596dcd51caa690` | `master` | Apache-2.0 repository license observed; bundled acknowledgements/dependency licenses require preservation/review | exact head dated 2026-05-25; active 2026 benchmark line | `HIGH_PRIORITY_BENCHMARK_METHODOLOGY_REFERENCE` |
| SRC-2026-09-SECGUIDE | `Tencent/secguide` | `bfda087142e3bb3f5840cbc6af82c1982d1d14e4` | `main` | repository LICENSE is CC-BY-SA-4.0; README wording is internally inconsistent and must not override LICENSE | exact head dated 2021-12-17 | `KNOWLEDGE_SOURCE_ONLY` |
| SRC-2026-09-TSCANCODE | `Tencent/TscanCode` | `3e3b6b66a7e39283d99add581fb9d54ee80c48f5` | `master` | GPL-3.0 repository license observed; bundled Cppcheck/Tinyxml notices also present | exact head dated 2023-12-25; public feature release line primarily 2022 | `LOW_PRIORITY_EXTERNAL_ENGINE_REFERENCE` |

## SRC-2026-09-AIG — Tencent/AI-Infra-Guard

### Exact research pin

```text
repository: Tencent/AI-Infra-Guard
exact_ref: e4e622af3ad2b8228ce82dd62b01415dd8ce2b9c
default_branch: main
head_date_observed: 2026-09-04
repository_license_observed: Apache-2.0
assessment_mode: RESEARCH_ONLY
```

### Capabilities observed at the pin

The repository presents a broad AI-security/red-team platform including:

- Agent Scan;
- MCP Server and Agent Skills scanning;
- AI-infrastructure vulnerability scanning;
- jailbreak evaluation;
- Claw/OpenClaw scanning;
- model/API relay checking;
- vulnerability/fingerprint/rule libraries;
- standalone skill/MCP/agent scanning CLIs;
- benchmarked Skill scanning;
- source and remote-target modes.

The current release documentation records high-value threat/evasion areas including:

- skill instruction hijacking;
- memory poisoning;
- remote payload download/execution;
- embedded malicious code;
- privilege escalation / unauthorized access;
- persistence;
- tool hijacking/spoofing;
- insecure dependencies;
- insecure coding practices;
- tool poisoning;
- credential/data exfiltration;
- command injection;
- indirect prompt injection;
- SSRF via agent;
- RCE via tool;
- web exfiltration;
- `.pyc`/bytecode bypass and charset-smuggling defenses.

The repository also contains SARIF/output formatting and rule/taxonomy material that may be useful for future importer/conformance research.

### Why it fits Sentrdel

Its strongest value is not as a runtime dependency. It provides a concrete modern threat vocabulary for the **Agent/MCP/Skill** domain, adversarial routing/encoding cases, and possible external-producer fixtures.

Sentrdel can differentiate by correlating these artifact/capability observations through ASEL + SSG + invariant/coverage contracts instead of cloning a standalone agent scanner.

### Authority and dependency concerns

The full platform includes combinations of:

- Python and Go runtimes;
- Docker deployment;
- local HTTP services;
- remote URL scanning;
- model/LLM configuration and API keys;
- dynamic red-team behavior;
- live AI-infrastructure fingerprinting;
- plugin/rule libraries.

The upstream documentation also warns that the full server currently lacks authentication and should not be publicly exposed.

These surfaces are incompatible with silent admission into the base Sentrdel trust boundary.

### Planning decision

```text
decision: HIGH_PRIORITY_TAXONOMY_AND_CONFORMANCE_REFERENCE
source_copy_authorized_by_this_record: NO
runtime_dependency_authorized: NO
network_mode_authorized: NO
credential_mode_authorized: NO
dynamic_red_team_authorized: NO
preferred_future_boundary:
  1. independently authored Sentrdel threat/evidence contracts informed by the taxonomy;
  2. exact-file qualification only where selective source reuse is genuinely superior;
  3. optional external-evidence producer after S6 importer contracts exist;
  4. dynamic attack ideas only under future R6 isolation/authorization.
```

## SRC-2026-09-MAGIKA — google/magika

### Exact research pin

```text
repository: google/magika
exact_ref: 26b6a9ba7e92f2b0a3745970a9190ec0dde9bf83
default_branch: main
head_date_observed: 2026-09-07
repository_license_observed: Apache-2.0
assessment_mode: RESEARCH_ONLY
```

### Capabilities observed at the pin

Magika is a content-based file-type classifier. Its documentation reports:

- 200+ content types;
- a large training/evaluation corpus;
- fast CPU inference after model load;
- Rust CLI/library availability plus other bindings;
- per-content-type trust thresholds;
- explicit generic/unknown outcomes;
- use as a routing signal for downstream security/content scanners.

The exact Rust library manifest observed at this pin declares an ONNX Runtime dependency through `ort = =2.0.0-rc.12` with defaults disabled for the library configuration, plus ndarray/tokio/serde/thiserror. Its internal test feature enables `ort/download-binaries` and `ort/tls-native`.

### Why it fits Sentrdel

Sentrdel currently needs a stronger contract for deciding which analyzers should inspect an untrusted artifact. Magika is a strong candidate **additional routing signal**, especially for extension/content disagreement and unknown content.

### Epistemic boundary

Magika output is probabilistic classification. It must therefore remain **INFERENCE**, not a FACT about the repository merely because the model is accurate on an upstream benchmark.

A safe Sentrdel design must combine:

- path/extension observation;
- deterministic bounded byte/content observations;
- optional classifier prediction;
- explicit disagreement;
- conservative analyzer selection;
- coverage diagnostics.

No classifier prediction may silently suppress an otherwise applicable analyzer.

### Authority and dependency concerns

Potential in-process use would expand the dependency/security surface through:

- ONNX Runtime/native implementation;
- model artifacts and their provenance/versioning;
- memory/latency impact;
- possible platform-specific packaging behavior;
- artifact-download behavior in upstream test/configuration paths.

A smaller external-process boundary may be safer, but it would still need exact binary/version/output/cwd/env/resource qualification.

### Planning decision

```text
decision: HIGH_PRIORITY_OPTIONAL_ARTIFACT_CLASSIFIER_CANDIDATE
source_copy_authorized_by_this_record: NO
native_dependency_authorized: NO
model_artifact_authorized: NO
prediction_authority: INFERENCE_ONLY
preferred_future_boundary:
  compare no-classifier deterministic routing vs optional external-process Magika vs optional in-process Rust integration;
  adopt only if benchmark evidence shows materially better safe routing without unacceptable trusted-base growth.
```

## SRC-2026-09-ASE — Tencent/AICGSecEval

### Exact research pin

```text
repository: Tencent/AICGSecEval
exact_ref: 94428ebf45141bf4ecd365a51d596dcd51caa690
default_branch: master
head_date_observed: 2026-05-25
repository_license_observed: Apache-2.0
assessment_mode: RESEARCH_ONLY
```

### Capabilities observed at the pin

AICGSecEval describes a repository-level AI-generated code security benchmark with:

- tasks derived from real repository/CVE contexts;
- repository-level context extraction;
- support for LLM and agentic programming evaluation;
- OWASP Top 10 / CWE Top 25-oriented coverage;
- 29 CWE categories across multiple languages;
- static and dynamic hybrid evaluation;
- test-case/PoC-based dynamic assessment;
- checkpoint/recovery for long evaluations;
- dataset contribution formats carrying fields such as CWE/CVE/source/severity/image/line metadata.

The documented execution environment includes Python, Docker, large local disk/memory recommendations, optional GitHub tokens, and model/agent credentials or endpoints depending on the evaluated system.

### Why it fits Sentrdel

It is a high-value **methodology reference** for a future SentrdelBench profile that evaluates repository-level AI/agent-generated changes. Sentrdel should go beyond generic CWE counts by judging:

- trusted-base vs candidate invariant state;
- coverage regression;
- evidence provenance;
- explanation correctness;
- static-vs-verified proof separation;
- generator/evaluator independence;
- protected holdouts.

### Data and execution concerns

Repository-level Apache-2.0 is not enough to assume reuse rights for every embedded third-party project sample, CVE-derived file, PoC, Docker image, or generated output.

The dynamic evaluator also has authority surfaces that ordinary Sentrdel analysis deliberately forbids: container execution, target code execution, provider/model credentials, remote GitHub access, and PoCs.

### Planning decision

```text
decision: HIGH_PRIORITY_BENCHMARK_METHODOLOGY_REFERENCE
source_copy_authorized_by_this_record: NO
dataset_copy_authorized: NO
docker_image_authorized: NO
poc_execution_authorized: NO
provider_credentials_authorized: NO
preferred_future_boundary:
  reuse benchmark methodology and schema ideas first;
  create independently controlled Sentrdel regression pairs;
  import external benchmark artifacts only after artifact-level rights/provenance qualification;
  keep dynamic verification in a separate future R6 tier.
```

## SRC-2026-09-SECGUIDE — Tencent/secguide

### Exact research pin

```text
repository: Tencent/secguide
exact_ref: bfda087142e3bb3f5840cbc6af82c1982d1d14e4
default_branch: main
head_date_observed: 2021-12-17
repository_license_observed: CC-BY-SA-4.0
assessment_mode: RESEARCH_ONLY
```

### Capabilities observed at the pin

The repository is a developer-oriented secure coding guide covering C/C++, JavaScript/Node, Go, Java, and Python. It explicitly positions the material as useful for secure coding guidance, scanner-rule design, security-component development, and remediation.

### License ambiguity

The repository `LICENSE` identifies **CC-BY-SA-4.0**. The README display text says `CC BY 4.0` while linking to a BY-SA URL. This inconsistency must not be resolved by assumption. For planning, the repository LICENSE is treated as the controlling observation unless a future legal/source qualification proves otherwise.

### Maintenance concern

The exact default-branch head is from 2021. Secure-coding guidance can remain conceptually useful, but framework/library APIs and recommended practices can age. Any candidate derived from it needs current primary-reference validation and affected-version scope.

### Planning decision

```text
decision: KNOWLEDGE_SOURCE_ONLY
source_copy_authorized_by_this_record: NO
adapted_text_authorized: NO
trusted_rule_promotion_authorized: NO
preferred_future_boundary:
  provenance-linked research input for independently authored candidate rules/remediation;
  current primary references + SentrdelBench qualification required before promotion;
  legal/license review required before distributing adapted material.
```

## SRC-2026-09-TSCANCODE — Tencent/TscanCode

### Exact research pin

```text
repository: Tencent/TscanCode
exact_ref: 3e3b6b66a7e39283d99add581fb9d54ee80c48f5
default_branch: master
head_date_observed: 2023-12-25
repository_license_observed: GPL-3.0
assessment_mode: RESEARCH_ONLY
```

### Capabilities observed at the pin

TscanCode is a native static-analysis project focused publicly on C/C++ with historical C#/Lua claims. The README demonstrates XML findings with file/line/rule/severity/message fields and advertises performance/accuracy claims. The public README also notes that the public trunk is C++ while C#/Lua code was not equivalently available at the time described.

The license file records GPL-3.0 and bundled third-party notices including Cppcheck and Tinyxml components.

### Why it has limited but useful value

The mature external-evidence strategy means Sentrdel does not need to port this scanner. Its value is mainly:

- a legacy/tool-specific XML producer shape for importer conformance;
- defect examples for research comparison;
- an optional external-engine boundary only if user demand later justifies the maintenance and qualification cost.

### License and maintenance boundary

GPL implementation must not be linked or copied into Sentrdel's permissive trusted core. The older public feature line and limited current language availability reduce priority relative to standards-first imports and actively maintained engines.

### Planning decision

```text
decision: LOW_PRIORITY_EXTERNAL_ENGINE_REFERENCE
source_copy_authorized_by_this_record: NO
in_process_linkage_authorized: NO
required_engine_authorized: NO
preferred_future_boundary:
  generic bounded XML importer conformance fixture;
  optional external process only after exact qualification if future demand proves value.
```

## Cross-source conclusions

### Highest-value source by future Sentrdel area

| Sentrdel area | Best source signal | Reason |
|---|---|---|
| Agent/MCP/Skill security taxonomy and adversarial fixtures | AI-Infra-Guard | most direct fit to modern tool/skill/instruction/agent risk surfaces |
| Artifact identity / analyzer routing | Magika | mature content-type classifier with explicit unknown/confidence model and Rust availability |
| Agent-generated code benchmark methodology | AICGSecEval | repository-level coding-agent evaluation and static/dynamic separation |
| Secure coding knowledge seed | secguide | broad developer-oriented guidance, but license/freshness constrain reuse mode |
| Legacy tool-specific external evidence/import shape | TscanCode | XML static-analysis output, but GPL/maintenance make it unsuitable for core adoption |

### What none of the sources should own

None of these sources should own or override:

- Sentrdel Evidence epistemic classes;
- Sentrdel Coverage truth;
- SSG identities/provenance;
- invariant semantics;
- reconciler-only Finding creation;
- monotonic guard policy;
- verification semantics;
- protected holdout labels;
- release gates.

Those remain Sentrdel-owned trust and judgment surfaces.

## Future qualification trigger

A separate exact qualification is required before any future change does one or more of the following:

- copies or ports upstream implementation source;
- copies benchmark data or documentation content;
- links a library or model runtime;
- vendors a model, rule pack, dataset, binary, container, or generated artifact;
- invokes an external engine as part of supported Sentrdel behavior;
- consumes a network service or provider credential;
- executes dynamic benchmark/PoC/red-team behavior;
- distributes adapted CC-BY-SA material;
- adds GPL-covered implementation to a distributed component;
- changes an already qualified source ref/version/features/artifacts.

At that point the ordinary source-qualification ledger must bind exact files/artifacts, checksums where applicable, permission/license basis, notices, modification history, build/runtime authority, dependency closure, network/credential behavior, maintenance status, security review, and tests/CI evidence.
