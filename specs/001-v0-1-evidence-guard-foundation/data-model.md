# Data Model — Sentrdel v0.1 Evidence + Guard Foundation

**Status:** DESIGN_COMPLETE  
**Authority:** `spec.md`, constitution, and this model. Field-level Rust/JSON names may evolve during implementation only if contracts and semantics remain compatible or are explicitly version-bumped.

## Design Rules

1. Evidence is immutable once accepted into the canonical store.
2. Findings are reconciled projections over Evidence; producers never create Findings directly.
3. Coverage is first-class and cannot be inferred from absence of findings.
4. LLM producers cannot construct FACT/OBSERVATION/VERIFIED evidence through the public reasoner API.
5. Secret plaintext is never part of the persistent canonical model by default.
6. All persisted/cross-process objects have explicit schema versions.
7. Stable identities use content hashes or deterministic semantic keys; random UUIDs may identify sessions/runs but not replace provenance hashes.

## 1. Evidence

```text
Evidence {
  schema_version
  evidence_id              # BLAKE3 of canonical stable serialization
  producer
  producer_version
  producer_kind
  input_digests[]
  claim
  category
  epistemic_class
  confidence_band?
  subjects[]
  locations[]
  attributes
  reproducer?
  captured_at
}
```

### `ProducerKind`

- `NATIVE_RULE`
- `COMPILER_INDEX`
- `EXTERNAL_ENGINE`
- `RUNTIME_TEST`
- `LLM_REASONER`
- `HUMAN`
- `SYSTEM`

### `EpistemicClass`

- `FACT` — directly observable and machine-checkable from bounded input.
- `INFERENCE` — deterministic or model-derived interpretation; producer kind preserves which.
- `HYPOTHESIS` — unconfirmed candidate, commonly from LLM/heuristic reasoning.
- `OBSERVATION` — runtime/test measurement.
- `VERIFIED` — independent bounded execution reproduced the claim. Reserved for future Verify producer authority.
- `CONTRADICTION` — evidence that disputes another claim/evidence item.

R1 has no producer authorized to emit `VERIFIED` from execution because verification is not implemented. Fixture tests MAY create synthetic VERIFIED records only inside schema tests.

### `ConfidenceBand`

- `LOW`
- `MEDIUM`
- `HIGH`

No fake probability percentages are part of the core schema in R1.

### Location

```text
Location {
  repo_relative_path
  start_line?
  start_column?
  end_line?
  end_column?
  symbol?
  content_digest?
}
```

Absolute host paths MUST NOT be persisted as canonical source locations.

## 2. Finding

```text
Finding {
  schema_version
  finding_id
  fingerprint
  title
  impact_statement
  category
  severity
  epistemic_state
  workflow_state
  evidence_ids[]
  contradiction_ids[]
  primary_location?
  affected_subjects[]
  first_seen_commit?
  last_seen_commit?
  remediation?
  accepted_risk?
  updated_at
}
```

### Severity

Initial action-oriented severity:

- `BLOCK` — fix before merge under active policy.
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

CLI novice rendering MAY use `Fix before merging`, `Fix soon`, `Worth a look`; the machine schema remains stable.

### Epistemic state

- `DETECTED`
- `CORROBORATED`
- `CONTESTED`
- `PROVEN`
- `UNPROVEN`
- `UNVERIFIABLE`

R1 normally produces DETECTED/CORROBORATED/CONTESTED/UNPROVEN. PROVEN is reserved for future qualified verification evidence or deterministic proof classes explicitly authorized by a later spec.

### Workflow state

- `NEW`
- `TRIAGED_FIX_NOW`
- `TRIAGED_DEFER`
- `ACCEPTED`
- `SUPPRESSED`
- `FIX_PROPOSED`
- `FIX_VERIFIED`
- `FIX_REGRESSED`
- `CLOSED`

R1 MUST NOT automatically set `ACCEPTED`, `SUPPRESSED`, or `FIX_VERIFIED` from LLM output.

### AcceptedRisk

```text
AcceptedRisk {
  owner
  reason
  created_at
  expires_at
  signature_ref?           # future cryptographic signature
  evidence_basis[]
}
```

Expiry is mandatory.

## 3. CoverageRecord

```text
CoverageRecord {
  schema_version
  coverage_id
  capability
  scope
  producer?
  state
  reason_code?
  details?
  input_digests[]
  observed_at
}
```

### CoverageState

- `COVERED`
- `PARTIAL`
- `UNSUPPORTED`
- `UNAVAILABLE`
- `FAILED`
- `TIMED_OUT`
- `SKIPPED_BY_POLICY`

There is deliberately no `CLEAN` coverage state. Cleanliness is a finding/query conclusion over covered dimensions, not a producer availability state.

## 4. ASEL Event

Agent Security Event Log is append-only and hash chained.

```text
AgentSecurityEvent {
  schema_version
  session_id
  sequence
  timestamp
  actor
  kind
  intent?
  target?
  params_digest?
  result_digest?
  policy_decision?
  provenance
  previous_event_hash?
  event_hash
}
```

### Actor

```text
Actor {
  actor_type      # USER | AGENT | TOOL | SYSTEM
  id
  vendor?
  version?
}
```

### R1 event kinds

Implemented/required:

- `mcp.discovery`
- `mcp.invocation`
- `git.operation`
- `approval`
- `denial`
- `tool.result`
- `guard.error`

Reserved in schema for later:

- `prompt.input`
- `model.request`
- `file.read`
- `file.write`
- `file.edit`
- `shell.command`
- `subprocess.spawn`
- `network.access`
- `package.install`
- `dependency.change`
- `secret.access`
- `env.access`
- `ci.change`
- `iac.change`

Unknown future event kinds MUST be forward-compatible through a namespaced extension mechanism; core-known security-critical kinds remain enums/validated.

## 5. PolicyDecision

```text
PolicyDecision {
  decision_id
  verdict
  enforcement_fidelity
  reason_codes[]
  rule_ids[]
  kernel_invariant_ids[]
  policy_version_digests[]
  action_digest
  decided_at
}
```

### Verdict

- `ALLOW`
- `ASK`
- `DENY`
- `UNDECIDABLE`

### EnforcementFidelity

- `ENFORCED`
- `PARTIAL`
- `ADVISORY`

`DENY` from any kernel invariant is absorbing for the exact `action_digest` scope.

## 6. ProjectProfile

```text
ProjectProfile {
  schema_version
  repository_id
  repository_root_digest
  languages[]
  package_ecosystems[]
  ci_systems[]
  mcp_configurations[]
  detected_providers[]
  detected_frameworks[]
  security_packs[]
  created_at
  refreshed_at
}
```

### DetectedProvider

```text
DetectedProvider {
  provider_id             # e.g. "supabase"
  evidence_ids[]
  detection_confidence
  pack_status             # AVAILABLE | NOT_INSTALLED | NOT_IMPLEMENTED | PARTIAL
}
```

Detection is not a security verdict.

## 7. SecurityPackManifest

```text
SecurityPackManifest {
  schema_version
  pack_id
  version
  provider_or_framework
  source_provenance
  detection_capabilities[]
  evidence_capabilities[]
  required_engines[]
  required_features[]
  coverage_dimensions[]
}
```

A pack may emit Evidence and CoverageRecords only. It cannot create Findings or policy exceptions.

## 8. EngineManifest

```text
EngineManifest {
  schema_version
  engine_id
  adapter_version
  executable_source
  executable_digest?
  expected_version_constraint?
  input_dialects[]
  output_dialects[]
  capabilities[]
  timeout_ms
  max_stdout_bytes
  max_stderr_bytes
  network_requirement
}
```

Repository files MUST NOT redefine the executable path to an arbitrary binary under the repository.

## 9. EngineRun

```text
EngineRun {
  run_id
  engine_manifest_digest
  input_digests[]
  started_at
  finished_at
  exit_status?
  termination_reason
  stdout_digest?
  stderr_digest?
  produced_evidence_ids[]
  coverage_ids[]
}
```

Termination reasons include completed, non-zero, timeout, output-cap, spawn-failed, malformed-output, policy-blocked.

## 10. Security Graph

### Node

```text
GraphNode {
  node_id
  node_kind
  semantic_key
  attributes
  provenance_ids[]
}
```

Initial kinds:

- PROJECT
- FILE
- SYMBOL
- REFERENCE
- RESOURCE
- DEPENDENCY
- WORKFLOW
- PROVIDER
- MCP_SERVER
- MCP_TOOL
- AGENT_ACTION
- EVIDENCE
- FINDING
- INVARIANT

### Edge

```text
GraphEdge {
  edge_id
  source
  target
  relation
  confidence_source
  provenance_ids[]
  attributes
}
```

Initial relations:

- `REFS`
- `CALLS`
- `DEPENDS_ON`
- `READS_FROM`
- `WRITES_TO`
- `FLOWS_TO`
- `AFFECTED_BY`
- `SUPPORTS`
- `CONTRADICTS`
- `DETECTED_AS`
- `INVOKES`
- `CROSSES_TRUST_BOUNDARY`

`CALLS`/`FLOWS_TO` MUST NOT imply compiler certainty unless their producer provenance actually supplies it.

## 11. SourceQualificationRecord

```text
SourceQualificationRecord {
  source_id
  repository
  exact_ref
  files_or_artifacts[]
  license_expression
  notices[]
  integration_mode      # NATIVE_DEP | COPIED_SOURCE | COPIED_DATA | EXTERNAL_PROCESS | STUDY_ONLY
  security_notes
  maintenance_notes
  modifications
  qualified_by
  qualified_at
}
```

No `COPIED_SOURCE`/`COPIED_DATA` adoption is permitted without this record and compatible project license policy.

## Relationships

```text
ProjectProfile 1 --- * CoverageRecord
ProjectProfile 1 --- * SecurityPackManifest (detected/available)
EngineManifest 1 --- * EngineRun
EngineRun 1 --- * Evidence
Evidence * --- * Finding
Finding 1 --- * Workflow history
ASEL Session 1 --- * AgentSecurityEvent
AgentSecurityEvent * --- 0..1 PolicyDecision
Evidence/Findings/Events --- Graph nodes/edges by stable ids
```

## Invariants

- Evidence ID must match canonical content hash.
- Event sequence strictly increases inside a session.
- Event `previous_event_hash` must match prior event hash except sequence 0/1 root.
- Finding evidence IDs must exist.
- `VERIFIED` evidence must come from a producer authority permitted by the active schema/policy version; no such runtime producer exists in R1.
- LLM reasoner API cannot produce disallowed epistemic classes.
- Repository policy cannot remove kernel invariant IDs.
- A CoverageRecord failure/unavailable state cannot be converted into `COVERED` without a successful producer run for the same capability/input scope.
- Provider detection never implies secure posture.
