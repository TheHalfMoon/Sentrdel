# Contract — External Engines and Security Packs

**Status:** BINDING_FOR_R1_IMPLEMENTATION

## 1. External Engine Boundary

External engines are untrusted evidence producers. They do not participate in the trusted Rust core process except through bounded invocation and validated output.

Conceptual Rust boundary:

```text
trait Engine {
    fn manifest(&self) -> &EngineManifest;
    async fn run(&self, request: EngineRequest, limits: EngineLimits)
        -> Result<EngineRunResult, EngineRunError>;
}
```

The implementation MAY differ syntactically; semantics are binding.

### EngineRequest

Contains only normalized paths/scopes/input references needed by the engine. Repository-controlled data MUST NOT choose arbitrary executable paths or inject shell syntax.

### EngineLimits

Must support:

- wall-clock timeout;
- stdout byte cap;
- stderr byte cap;
- bounded environment inheritance;
- cwd/workspace boundary;
- network requirement declaration;
- future CPU/memory/process constraints where platform APIs permit.

### Invocation rules

- No shell string evaluation.
- Executable + each argument are separate argv elements.
- Engine executable origin/version is captured.
- Repository hooks/install scripts are not implicitly executed to prepare an engine.
- Output is parsed as untrusted bytes.
- Absolute result paths are normalized/rejected if they escape the repository scope.
- Malformed output never becomes Evidence.

### Engine result

Every run yields:

- zero or more validated Evidence items;
- CoverageRecord(s);
- EngineRun metadata;
- diagnostics.

A timeout/crash/missing executable/malformed output MUST emit non-covered coverage state.

## 2. Supported output dialects

R1 canonical adapters MAY support:

- Sentrdel-native JSON evidence dialect;
- SARIF subset/full mapping as qualified;
- engine-specific JSON only through a dedicated adapter with contract fixtures.

There is no generic "accept any JSON and ask the LLM what it means" pathway.

## 3. Security Pack Boundary

A Security Pack is a provider/framework-specific evidence module. Packs allow A-to-Z depth without giving provider code authority over findings or kernel policy.

Conceptual boundary:

```text
trait SecurityPack {
    fn manifest(&self) -> &SecurityPackManifest;
    fn detect(&self, project: &ProjectView) -> DetectionResult;
    async fn collect_evidence(&self, scope: AnalysisScope)
        -> PackEvidenceResult;
}
```

A pack MAY be native Rust or orchestrate qualified external engines through `sentrdel-engine`; it MUST NOT spawn processes directly.

## 4. Pack authority

A pack may:

- detect its provider/framework;
- emit Evidence;
- emit CoverageRecords;
- contribute graph nodes/edges with provenance;
- recommend required evidence capabilities.

A pack may NOT:

- create/update canonical Findings directly;
- mark the project globally secure;
- override/remove kernel invariants;
- weaken user/system policy;
- set runtime VERIFIED without a future authorized verification producer;
- persist secret plaintext.

## 5. Supabase Pack reserved capability map

R1 only detects Supabase and records pack coverage state. R3 will specify the implementation, but the pack contract MUST be capable of representing at least these future dimensions:

- Postgres schema exposure;
- Row Level Security enabled/disabled and policy semantics;
- table/view/function grants;
- Auth/JWT/claims usage;
- service-role/secret-key boundary and client exposure;
- Storage buckets and policies;
- migrations/triggers/views/functions/security-definer/search-path concerns;
- Edge Functions;
- Realtime authorization where applicable;
- configuration/secrets relevant to Supabase deployment;
- code-to-database/resource relationships;
- tenant/user ownership invariants.

`detected_provider = supabase` does not imply any of these dimensions are covered.

## 6. Manifest provenance

Every EngineManifest and SecurityPackManifest contains or references:

- stable id;
- version;
- source provenance;
- compatible Sentrdel schema versions;
- declared capabilities;
- declared network/runtime requirements;
- license/provenance record for non-Sentrdel-owned source/data;
- integrity digest for installed external artifacts where feasible.

## 7. Failure isolation

One engine or pack failure MUST NOT corrupt other Evidence or Findings. The orchestrator continues independent producers when safe and records per-capability failure/coverage state.

A producer cannot write directly into another producer's namespace or mutate previously accepted immutable Evidence.

## 8. Deterministic test fixtures

Every adapter/pack must include fixtures covering:

- valid minimal output;
- multiple findings/evidence;
- empty but covered output;
- malformed output;
- oversized output;
- absolute/out-of-root paths;
- duplicate IDs/fingerprints;
- unsupported schema/version;
- engine non-zero/timeout/missing cases;
- secret-like content in output to prove redaction.

Provider packs additionally need positive/negative detection fixtures to prove detection is not a security verdict.
