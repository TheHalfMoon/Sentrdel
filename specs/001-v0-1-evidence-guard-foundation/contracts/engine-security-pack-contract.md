# Contract — External Engines and Security Packs

**Version:** draft-v1.1  
**Status:** BINDING_FOR_R1_IMPLEMENTATION

## 1. External Engine Boundary

External engines are untrusted evidence producers. They do not participate in the trusted Rust core except through bounded invocation and validated output.

Conceptual Rust boundary:

```text
trait Engine {
    fn manifest(&self) -> &EngineManifest;
    async fn run(&self, request: EngineRequest, limits: EngineLimits)
        -> Result<EngineRunResult, EngineRunError>;
}
```

Syntax may differ; semantics are binding.

### EngineRequest

Contains normalized scopes/input references only. Repository-controlled data MUST NOT choose arbitrary executables, inject shell syntax or expand process environment authority.

### EngineLimits

Must support:

- wall-clock timeout;
- stdout/stderr byte caps;
- cwd/workspace boundary;
- **deny-by-default child environment with explicit allowed variable names**;
- network requirement declaration and command-level policy;
- future CPU/memory/process limits where platform APIs permit.

### Invocation rules

- No shell string evaluation; executable/arguments are separate argv values.
- Executable origin/version/digest are captured where feasible.
- Engine paths come from trusted user/system installation/manifest resolution, not target-repository arbitrary paths.
- Full developer environment is NOT inherited. Cloud credentials, model/provider keys, signing keys, SSH agent sockets and unrelated secrets are excluded by default.
- Target hooks/build/install scripts/Cargo/package-manager code are not implicitly executed to prepare analysis.
- Output is untrusted bounded bytes; malformed output never becomes Evidence.
- Result paths are repository-relative or normalized/rejected if outside scope.
- Engine failure emits explicit coverage state.

### Engine result

Every run yields zero or more validated Evidence items, CoverageRecords, EngineRun metadata and diagnostics. Timeout/crash/missing/malformed/output-cap/policy block is visible as non-covered coverage.

## 2. Supported output dialects

R1 adapters MAY support Sentrdel-native JSON, qualified SARIF mapping, and dedicated engine-specific JSON adapters with fixtures.

There is no generic "accept arbitrary JSON and ask an LLM what it means" path.

## 3. Security Pack Boundary

A Security Pack is a provider/framework-specific Evidence/Coverage module. It allows A-to-Z depth without giving provider code authority over Findings or kernel policy.

```text
trait SecurityPack {
    fn manifest(&self) -> &SecurityPackManifest;
    fn detect(&self, project: &ProjectView) -> DetectionResult;
    async fn collect_evidence(&self, scope: AnalysisScope)
        -> PackEvidenceResult;
}
```

A pack MAY be native Rust or orchestrate qualified external engines only through `sentrdel-engine`; it MUST NOT spawn processes directly.

## 4. Pack authority

A pack may detect its provider/framework, emit Evidence/Coverage, contribute provenance-qualified graph relationships, and declare missing capabilities.

A pack may NOT create/update canonical Findings, mark a project globally secure, weaken policy/kernel invariants, set VERIFIED without future verification authority, or persist secret plaintext/value-only hashes.

## 5. Pack coverage modes

Provider detection is not security coverage. Manifests/results distinguish:

- `DETECTION` — provider/framework presence only;
- `STATIC_POSTURE` — repository/migration/config/source analysis without provider credentials;
- `LIVE_POSTURE` — explicit credentialed provider/API posture, only in later specs and opt-in;
- `BUSINESS_LOGIC` — cross-layer application/provider trust and invariant reasoning;
- `RUNTIME` — observed runtime/provider behavior when a later authorized surface exists.

A missing mode is a visible coverage gap, never a PASS.

## 6. Supabase P0 reserved capability map

R1 detects Supabase and validates the pack contract. **R2** specifies the first full pack, beginning with offline/static posture. The contract represents at least:

- Postgres/Data API schema exposure;
- RLS enabled/missing-policy/policy evidence;
- table/view/function grants and function EXECUTE exposure;
- SECURITY DEFINER/view/function and mutable `search_path` concerns;
- Auth/JWT/claims/config signals;
- service-role/secret-key boundary and client/browser exposure;
- Storage buckets/policies/public-listing/ownership signals;
- migrations/triggers/views/functions;
- Edge Functions and Realtime authorization where statically observable;
- code-to-database/resource relationships;
- tenant/user ownership invariants in later BUSINESS_LOGIC mode.

`detected_provider = supabase` does not imply any of these dimensions are covered.

## 7. Manifest provenance

Every EngineManifest/SecurityPackManifest contains or references stable ID, version, source provenance, compatible schema versions, capabilities, network/runtime requirements, license/source-qualification record and artifact integrity digest where feasible.

## 8. Failure isolation

One engine/pack failure cannot corrupt another producer's Evidence or mutate accepted immutable Evidence. Independent producers continue when safe and coverage records the failed capability.

## 9. Deterministic fixtures

Every adapter/pack includes fixtures for valid minimal output, multiple evidence, empty-but-covered, malformed/oversized output, out-of-root paths, duplicate IDs, unsupported schema/version, non-zero/timeout/missing cases, environment secret canaries and secret-like output redaction.

Provider packs additionally need positive/negative detection fixtures and per-coverage-mode fixtures proving detection is not a security verdict.
