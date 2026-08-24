# Contract — Canonical Evidence, Findings, Coverage, and ASEL

**Version:** draft-v1.1  
**Status:** BINDING_FOR_R1_IMPLEMENTATION

## 1. Canonical serialization

All cross-crate/persisted/exported canonical objects MUST have:

- explicit `schema_version`;
- deterministic JSON serialization rules documented/tested;
- generated JSON Schema checked into `/schemas`;
- rejection of structurally invalid objects before persistence;
- stable content hashing after redaction/canonicalization.

Unknown fields MAY be rejected for security-critical R1 envelopes; extension points are explicitly namespaced rather than silently accepting arbitrary authority-bearing fields.

## 2. Evidence producer authority

A producer submits candidate Evidence to schema validation. It never submits a Finding.

Evidence separates a direct `observation`/basis from optional `security_interpretation`.

### FACT rule

`FACT` means a directly observable bounded property. Deterministic detection alone does not make a semantic security conclusion a FACT.

Examples:

- FACT: `package-lock.json contains pkg@1.2.3`.
- FACT: `workflow permissions.contents is write`.
- FACT: `literal matches secret rule SNT-SECRET-001 at file:line`.
- INFERENCE: `the workflow change widens repository-write capability`.
- NOT FACT without stronger evidence: `credential is valid`, `route is exploitable`, `cross-tenant access is possible`.

Allowed producer-to-epistemic mapping in R1:

| Producer | Allowed classes |
|---|---|
| Native deterministic rule | FACT for direct observations; INFERENCE/CONTRADICTION for interpretations |
| Compiler/index/semantic producer | FACT/INFERENCE/CONTRADICTION according to adapter authority |
| External scanner | FACT only for directly mapped observations; otherwise INFERENCE; never VERIFIED because scanner severity says so |
| LLM reasoner | INFERENCE, HYPOTHESIS only |
| Human | workflow decision/evidence note; cannot fabricate runtime VERIFIED |
| Future verification executor | OBSERVATION, VERIFIED, CONTRADICTION — **not implemented in R1** |

API design MUST prevent an LLM adapter from requesting a more authoritative class.

## 3. Reconciliation

Only the reconciler maps Evidence sets into Findings.

Required behavior:

- fingerprint equivalent evidence;
- retain every contributing evidence ID;
- independent corroboration may advance epistemic state;
- contradiction marks `CONTESTED` until resolved by qualified evidence;
- producer severity is advisory and cannot bypass Sentrdel severity policy;
- absence of evidence is not positive evidence of safety.

## 4. Coverage

Every producer invocation ends with explicit CoverageRecords.

Forbidden:

```text
engine missing -> no findings -> PASS
```

Required:

```text
engine missing -> CoverageRecord(UNAVAILABLE) -> analysis partial/incomplete
```

Provider security coverage distinguishes provider detection, offline/static posture, optional live posture and cross-layer/business-logic coverage.

## 5. ASEL chain and trusted-head semantics

For each `session_id`:

1. sequence monotonically increases;
2. each non-root event includes prior canonical event hash;
3. event hash covers canonical redacted envelope including previous hash;
4. raw secret/prompt/tool payload is not required for integrity; bounded redacted metadata/digests are sufficient;
5. invalid available chain is an explicit integrity failure and is never silently repaired.

### Important truthfulness rule

A self-contained local hash chain proves **internal consistency of the available chain**. It does not independently prove that an attacker with write access did not replace/truncate both the log and its stored head.

Therefore R1 exposes:

- computed head hash;
- event count;
- `chain_valid`;
- optional expected/trusted head comparison when a caller supplies a checkpoint.

UI/docs MUST NOT call a local unauthenticated chain `tamper-proof`. Later signatures/remote attestation may add stronger provenance.

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

Generated JSON Schema is canonical.

## 6. Guard decision monotonicity

For one normalized action scope:

```text
ALLOW < ASK < DENY
```

`UNDECIDABLE` is not permission. At an enforcement seam it fails closed according to configured core/user policy, with ASK as default interactive resolution where available.

Kernel-invariant DENY is absorbing. No repo policy, plugin, external engine, tool result, MCP description or LLM lowers it.

Property tests generate policy orderings and prove adding restrictions cannot lower final verdict.

## 7. Enforcement fidelity

Every guard state exposed to users/machines includes:

- `ENFORCED` — Sentrdel controls that execution path.
- `PARTIAL` — Sentrdel controls some but not all equivalent paths.
- `ADVISORY` — Sentrdel can observe/advise but not guarantee prevention.

No UI/marketing layer maps PARTIAL/ADVISORY to ENFORCED.

## 8. Secret handling

When secret-like content is detected:

- plaintext may exist transiently in bounded memory for detection;
- plaintext MUST NOT enter persistent Evidence, SQLite, exports, snapshots or tracing;
- persistent Evidence may store repository-relative location, secret category, rule ID, redacted display token and a sanitized surrounding-content fingerprint;
- Sentrdel MUST NOT store a stable unkeyed hash/digest computed solely from the secret value;
- engine output is redacted before durable persistence;
- canary tests assert plaintext and known value-only digests never appear in persistent artifacts.

## 9. Corruption and authority failures

Hash mismatch, impossible state transition, unknown authority-bearing producer, invalid schema version or invalid trusted-head comparison fails explicitly. Sentrdel MUST NOT coerce corrupted security history into a valid-looking state.
