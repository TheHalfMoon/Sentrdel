# Data Model — Sentrdel v0.1 Evidence + Guard Foundation

**Status:** DESIGN_COMPLETE_AFTER_MAJOR_REVIEW  
**Authority:** `spec.md`, constitution, major review, and this model. Field-level Rust/JSON names may evolve during implementation only if semantics remain compatible or are explicitly version-bumped.

## Design Rules

1. Evidence is immutable once accepted into the canonical store.
2. Findings are reconciled projections over Evidence; producers never create Findings directly.
3. Coverage is first-class and cannot be inferred from absence of findings.
4. LLM producers cannot construct FACT/OBSERVATION/VERIFIED evidence through the public reasoner API.
5. FACT describes a directly observable bounded property, not a semantic security conclusion merely because a detector is deterministic.
6. Discovered secret plaintext and stable unkeyed digests derived solely from secret values are excluded from the persistent canonical model by default.
7. All persisted/cross-process objects have explicit schema versions.
8. Stable identities use canonical content hashes or deterministic semantic keys; UUIDs may identify sessions/runs but do not replace provenance hashes.
9. Hash-linked history is verifiable relative to a trusted head/checkpoint; unauthenticated local chains are not described as tamper-proof.

## 1. Evidence

```text
Evidence {
  schema_version
  evidence_id              # BLAKE3 of canonical stable serialization
  producer
  producer_version
  producer_kind
  input_digests[]
  observation              # direct bounded basis: what was actually parsed/matched/observed
  security_interpretation? # producer's security meaning; may be inference/hypothesis
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

A producer MUST NOT hide an interpretation inside `observation`. For example:

- valid FACT observation: `workflow job has permissions.contents = write`;
- valid inference: `this widens repository-write capability`;
- invalid FACT: `attacker can compromise repository` unless the producer has the semantic/runtime authority to support that statement.

### `ProducerKind`

- `NATIVE_RULE`
- `COMPILER_INDEX`
- `EXTERNAL_ENGINE`
- `RUNTIME_TEST`
- `LLM_REASONER`
- `HUMAN`
- `SYSTEM`

### `EpistemicClass`

- `FACT` — directly observable and machine-checkable bounded property.
- `INFERENCE` — interpretation derived from facts; producer kind/provenance tells whether deterministic or model-derived.
- `HYPOTHESIS` — unconfirmed candidate, commonly heuristic/LLM.
- `OBSERVATION` — runtime/test measurement.
- `VERIFIED` — independent bounded execution reproduced the security claim; reserved for future Verify authority.
- `CONTRADICTION` — evidence disputing another claim/evidence item.

R1 has no runtime producer authorized to emit VERIFIED. Schema fixtures MAY construct synthetic VERIFIED values solely for invariant tests.

### `ConfidenceBand`

`LOW | MEDIUM | HIGH`

No fake probability percentages are part of R1 core schema.

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

### Secret evidence

For a discovered secret candidate, persistent attributes MAY include:

```text
secret_rule_id
secret_kind
redacted_display
sanitized_context_fingerprint?
```

They MUST NOT include plaintext value or an unkeyed digest derived solely from that value.

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

- `BLOCK`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

CLI novice rendering may use `Fix before merging`, `Fix soon`, `Worth a look`.

### Epistemic state

- `DETECTED`
- `CORROBORATED`
- `CONTESTED`
- `PROVEN`
- `UNPROVEN`
- `UNVERIFIABLE`

R1 normally produces DETECTED/CORROBORATED/CONTESTED/UNPROVEN. PROVEN is reserved for qualified proof classes defined by a later spec.

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

R1 MUST NOT automatically set ACCEPTED, SUPPRESSED or FIX_VERIFIED from LLM output.

### AcceptedRisk

```text
AcceptedRisk {
  owner
  reason
  created_at
  expires_at
  signature_ref?
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

There is deliberately no CLEAN coverage state. Cleanliness is a conclusion over covered dimensions, not producer availability.

Provider coverage dimensions distinguish at least detection, offline/static posture, optional live posture and cross-layer/business-logic coverage.

## 4. ASEL Event

ASEL is append-only in normal operation and hash-linked.

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

Reserved later:

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

Unknown future event kinds use a namespaced extension mechanism; core security-critical kinds remain validated.

### Session integrity state

```text
ASELSessionIntegrity {
  session_id
  event_count
  computed_head_hash
  expected_head_hash?      # trusted checkpoint when supplied
  chain_valid
  trusted_checkpoint_valid?
  first_invalid_sequence?
}
```

`chain_valid=true` means the available chain is internally consistent. It does not independently prove non-truncation/replacement unless `expected_head_hash` or a later trusted signature/attestation is available.

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

`ALLOW | ASK | DENY | UNDECIDABLE`

### EnforcementFidelity

`ENFORCED | PARTIAL | ADVISORY`

DENY from any kernel invariant is absorbing for the exact action scope.

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
  provider_id
  evidence_ids[]
  detection_confidence
  pack_status             # AVAILABLE | NOT_INSTALLED | NOT_IMPLEMENTED | PARTIAL
  coverage_dimensions[]
}
```

Detection is never a security verdict.

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
  live_access_requirement?  # NONE | OPTIONAL_EXPLICIT | REQUIRED; R1 packs use NONE
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
  allowed_environment_names[]
  network_requirement
}
```

Repository files MUST NOT redefine an arbitrary executable. Environment inheritance is deny-by-default; explicitly allowed variable names still pass redaction/policy boundaries.

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

Initial kinds: PROJECT, FILE, SYMBOL, REFERENCE, RESOURCE, DEPENDENCY, WORKFLOW, PROVIDER, MCP_SERVER, MCP_TOOL, AGENT_ACTION, EVIDENCE, FINDING, INVARIANT.

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

Initial relations: REFS, CALLS, DEPENDS_ON, READS_FROM, WRITES_TO, FLOWS_TO, AFFECTED_BY, SUPPORTS, CONTRADICTS, DETECTED_AS, INVOKES, CROSSES_TRUST_BOUNDARY.

CALLS/FLOWS_TO MUST NOT imply compiler certainty unless provenance supplies it.

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
  executes_at_build?
  procedural_macro?
  native_code?
  downloads_artifacts?
  security_notes
  maintenance_notes
  modifications
  qualified_by
  qualified_at
}
```

No COPIED_SOURCE/COPIED_DATA adoption is permitted without this record and compatible Apache-2.0 project policy. Privileged dependency properties require explicit review even for ordinary NATIVE_DEP adoption.

## Relationships

```text
ProjectProfile 1 --- * CoverageRecord
ProjectProfile 1 --- * SecurityPackManifest
EngineManifest 1 --- * EngineRun
EngineRun 1 --- * Evidence
Evidence * --- * Finding
ASEL Session 1 --- * AgentSecurityEvent
AgentSecurityEvent * --- 0..1 PolicyDecision
Evidence/Findings/Events --- Graph nodes/edges by stable ids
```

## Invariants

- Evidence ID matches canonical serialization hash.
- Evidence FACT observation is direct/bounded and cannot be emitted by LLM reasoner authority.
- Event sequence strictly increases in a session.
- Event previous hash matches prior event except root.
- A chain is only independently compared against history when a trusted expected head/checkpoint exists.
- Finding evidence IDs exist.
- VERIFIED Evidence comes only from producer authority permitted by active schema/policy; no runtime Verify producer exists in R1.
- Repository policy cannot remove kernel invariant IDs.
- Coverage failure/unavailable cannot become COVERED without successful producer evidence for the same scope.
- Provider detection never implies secure posture.
- Persistent secret evidence contains neither plaintext value nor stable unkeyed value-only digest.
