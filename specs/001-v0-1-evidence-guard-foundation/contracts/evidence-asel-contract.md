# Contract — Canonical Evidence, Findings, Coverage, and ASEL

**Version:** draft-v1  
**Status:** BINDING_FOR_R1_IMPLEMENTATION

## 1. Canonical serialization

All cross-crate/persisted/exported canonical objects MUST have:

- explicit `schema_version`;
- deterministic JSON serialization rules documented and tested;
- generated JSON Schema checked into `/schemas`;
- rejection of structurally invalid objects before persistence;
- stable content hashing after redaction and canonicalization.

Unknown fields MAY be rejected for security-critical R1 envelopes where forward compatibility is not needed; extension points MUST be explicitly namespaced rather than silently accepting arbitrary authority-bearing fields.

## 2. Evidence producer authority

A producer submits candidate Evidence to `sentrdel-schema` validation. It does not submit a Finding.

Allowed producer-to-epistemic mapping in R1:

| Producer | Allowed classes |
|---|---|
| Native deterministic rule | FACT, INFERENCE, CONTRADICTION |
| Compiler/index/semantic external producer | FACT, INFERENCE, CONTRADICTION |
| External scanner engine | FACT or INFERENCE according to adapter mapping; never VERIFIED merely because scanner severity says so |
| LLM reasoner | INFERENCE, HYPOTHESIS only |
| Human | HUMAN workflow decision/evidence note; cannot fabricate runtime VERIFIED |
| Future verification executor | OBSERVATION, VERIFIED, CONTRADICTION — **not implemented in R1** |

Deserialization/API design MUST prevent an LLM adapter from requesting a more authoritative class.

## 3. Reconciliation

The reconciler is the sole component that maps Evidence sets into Findings.

Required behavior:

- equivalent evidence is fingerprint-correlated;
- every contributing evidence ID is retained;
- independent corroboration may advance epistemic state;
- contradiction marks finding `CONTESTED` until deterministic rules resolve it or future verification produces stronger evidence;
- producer severity is advisory input only and does not bypass Sentrdel severity policy;
- absence of evidence is not positive evidence of safety.

## 4. Coverage

Every producer invocation MUST end with one or more CoverageRecords that make the relevant capability state explicit.

Failures/timeouts/unavailable producers are machine-visible. CLI output MUST surface analysis incompleteness according to command policy.

The following is forbidden:

```text
engine missing -> no findings -> PASS
```

Required model:

```text
engine missing -> CoverageRecord(UNAVAILABLE) -> analysis incomplete/partial
```

## 5. ASEL chain

For each `session_id`:

1. sequence is monotonically increasing;
2. each event includes the prior canonical event hash, except the root;
3. event hash covers the canonical redacted event envelope including previous hash;
4. tool result/prompt/secret payload plaintext is not required for chain integrity; digests are sufficient;
5. any invalid chain is an explicit integrity failure and MUST NOT be silently repaired.

### Minimum event envelope

```json
{
  "schema_version": "1",
  "session_id": "...",
  "sequence": 42,
  "timestamp": "...",
  "actor": {"actor_type": "AGENT", "id": "..."},
  "kind": "mcp.invocation",
  "target": {"server": "...", "tool": "..."},
  "params_digest": "blake3:...",
  "policy_decision": "...",
  "provenance": {"source": "sentrdel-guard"},
  "previous_event_hash": "blake3:...",
  "event_hash": "blake3:..."
}
```

The JSON above is illustrative; generated schema is canonical.

## 6. Guard decision monotonicity

For one normalized action digest:

```text
ALLOW < ASK < DENY
```

`UNDECIDABLE` is not permission. At an enforcement seam it behaves fail-closed according to configured user/core policy, with ASK as the default interactive resolution path.

Kernel-invariant DENY is absorbing. No repo policy, plugin, external engine, tool result, MCP description, or LLM can lower it.

Property tests MUST generate arbitrary policy orderings and prove that adding restrictions cannot lower the final verdict.

## 7. Enforcement fidelity

Every guard event/state exposed to users or machines includes one of:

- `ENFORCED` — Sentrdel controls the execution path for the action.
- `PARTIAL` — Sentrdel controls some but not all equivalent paths.
- `ADVISORY` — Sentrdel can observe/advise but cannot guarantee prevention.

No marketing/UI layer may map PARTIAL/ADVISORY to ENFORCED.

## 8. Secret handling

When secret-like content is detected:

- matching plaintext may exist transiently in bounded memory for detection;
- persistent Evidence stores location, category, rule id, digest/redacted token metadata only;
- logs/tracing MUST NOT emit plaintext;
- engine stdout containing secret-like material is redacted before durable storage;
- tests include canary secrets and assert they never appear in SQLite, JSON exports, logs, or snapshots.

## 9. Tamper behavior

ASEL/evidence hash mismatch, impossible state transition, unknown authority-bearing producer, or invalid schema version MUST fail explicitly. The system MUST NOT coerce corrupted security history into a valid-looking state.
