# Contract — Context, Memory, Feedback, and Candidate-Learning Authority

**Version:** draft-v1.0  
**Status:** BINDING_FOR_R1_AUTHORITY_BOUNDARIES  
**Scope:** R1 authority contract only. General-purpose Security Memory/Learning implementation remains deferred.

## 1. Purpose

Sentrdel may eventually consume repository content, issue/PR text, CI logs, MCP content, browser material, external-engine output, model output, developer feedback, project memory, and automated security research. Reading or retaining such material MUST NOT silently grant it authority over security decisions.

This contract freezes the authority ceiling before those future capabilities are implemented.

Normative terms `MUST`, `MUST NOT`, `SHOULD`, and `MAY` are binding for R1 and later implementations unless a future Spec Kit change explicitly supersedes this contract without weakening the Constitution.

## 2. Core separation: content, evidence, and authority

Sentrdel distinguishes three independent properties:

1. **content availability** — the system may read bounded content;
2. **epistemic status** — the content may contribute context, feedback, INFERENCE/HYPOTHESIS Evidence, or another schema-authorized class;
3. **instruction authority** — a separately admitted authority may authorize a privileged Sentrdel action.

Possessing one property MUST NOT imply either of the others.

In particular:

```text
readable content != trusted instruction
stored memory != FACT
repeated feedback != VERIFIED
model agreement != policy authority
benchmark access != evaluator mutation authority
```

Authority capabilities remain constructed only by trusted Sentrdel core/bootstrap paths as defined by the canonical Evidence/ASEL and policy contracts. No serialized context payload may mint or deserialize an authority capability.

## 3. Default context trust classification

Unless an explicit trusted-core contract says otherwise, all of the following are **UNTRUSTED_CONTENT**:

- repository files, code comments, documentation, generated files, and configuration text;
- commit messages and diffs;
- issue, pull-request, review, discussion, chat, and ticket text;
- CI/build/test logs and artifacts;
- MCP server/tool names, descriptions, schemas, arguments, results, resources, and prompts;
- browser/web content and retrieved documents;
- external-engine/scanner stdout, stderr, SARIF, JSON, and metadata;
- LLM/model prompts, responses, tool suggestions, summaries, and generated plans;
- imported notes or memory records not independently admitted by a trusted-core authority path.

The system MAY parse, display, search, correlate, summarize, or derive schema-authorized low-authority Evidence from this material. It MUST NOT treat instruction-shaped text inside it as a privileged command merely because the text is syntactically imperative, signed by an untrusted source, repeated, retrieved from memory, or produced by a model.

## 4. Instruction-authority ceiling

Untrusted content MUST NOT directly or indirectly:

- widen filesystem, process, network, credential, secret, provider, MCP, or repository permissions;
- change `ALLOW < ASK < DENY` ordering or downgrade a kernel DENY;
- convert `UNDECIDABLE` into silent ALLOW;
- disable evidence capture, redaction, provenance, coverage reporting, or ASEL requirements;
- suppress or delete canonical Evidence or Findings;
- mint `EvidenceAuthority`, `TrustedPolicyAuthority`, `ReconcilerAuthority`, `WorkflowAuthorization`, or equivalent future authority tokens;
- create a canonical Finding outside the reconciler;
- select a stronger epistemic class than the producer contract permits;
- authorize credential access because content contains a token/key name or asks for one;
- change release, verification, benchmark, holdout, or promotion authority for a candidate it is helping generate.

Repository-controlled policy/configuration remains narrowing-only: it may restrict an already admitted capability but MUST NOT widen core authority.

## 5. Context provenance minimum contract

A future persisted or authority-relevant context record SHOULD carry, where applicable:

- stable record identity and schema version;
- source/channel kind;
- origin identity when knowable;
- bounded content digest after required redaction/canonicalization;
- trust class;
- instruction-authority class;
- sensitivity class;
- integrity status and any external checkpoint/signature facts without overstating them;
- receipt/evaluation timestamp and session/run identity;
- scope (repository, branch, path, finding, action, project, or narrower object);
- invalidation subjects/digests when later changes can make the context stale.

Unknown provenance, failed integrity validation, expired context, or stale context MUST reduce trust or make the context unavailable. It MUST NOT be upgraded by absence of contradictory evidence.

A cryptographic signature proves only the statement covered by the verified key/signature relationship; it does not by itself grant Sentrdel instruction authority.

## 6. Feedback authority

Developer/user feedback such as:

- `false positive`;
- `accepted risk`;
- `expected behavior`;
- `not exploitable`;
- `safe here`;
- `ignore this`;
- severity or remediation preferences;

is **scoped feedback/context**, not automatic truth.

Where persisted, feedback MUST retain actor/provenance, scope, rationale where supplied, time, and any expiry/revalidation metadata required by the owning feature.

Feedback MUST NOT automatically:

- become FACT, OBSERVATION, or VERIFIED Evidence;
- disable a producer/rule globally;
- suppress future Evidence;
- lower canonical severity or proof state without the ordinary authorized workflow;
- become a permanent exception merely because the same feedback was repeated;
- train/promote a candidate against the protected holdout used to judge that candidate.

Accepted-risk workflow state remains governed by its canonical schema/authorization contract; recording feedback is not equivalent to authorizing accepted risk.

## 7. Security Memory authority ceiling

General-purpose Security Memory is **not implemented or authorized by T095**. A future implementation MAY retain inspectable project context such as sanitizer identities, generated-code scope, project invariants, intentionally public resources, architecture constraints, or accepted-risk references.

Every future memory record that can affect security presentation or candidate generation MUST be bounded by:

- provenance/source;
- scope;
- authority class;
- creation time;
- optional expiry;
- invalidation/revalidation subjects;
- human/reviewer identity where human approval is the authoritative source.

Memory MUST NOT:

- mint FACT/OBSERVATION/VERIFIED Evidence;
- silently suppress Evidence or Findings;
- weaken Rust kernel invariants or policy monotonicity;
- become an unbounded permanent exception list;
- transform untrusted source text into privileged instruction;
- bypass the reconciler, verification contract, protected holdout, or release authority.

When relevant graph/file/profile/configuration identity changes, dependent memory SHOULD become `STALE` or `REVALIDATION_REQUIRED` rather than silently carrying forward authority.

## 8. Candidate-only Research/Learning Plane

Future research/learning automation MAY produce **candidate artifacts** such as:

- candidate deterministic rules;
- candidate graph heuristics;
- candidate Security Pack checks;
- candidate fixtures and fuzz targets;
- candidate remediation/explanation text;
- candidate producer calibration metadata;
- hypotheses derived from misses, incidents, or repeated feedback.

These artifacts have no production authority merely because they were generated automatically, passed public regression tests, or improved a metric.

Candidate automation MUST NOT directly create authoritative Findings or production policy decisions.

## 9. Current-candidate promotion firewall

For a candidate under generation/evaluation, the following judging authorities are immutable inputs from the candidate's perspective:

- evaluator implementation/version/digest;
- metric contract and release threshold definitions;
- protected-holdout cases, labels, expected outputs, corpus identity, and qualification procedure;
- Rust kernel invariants;
- Evidence epistemic-authority mappings;
- reconciler-only Finding creation boundary;
- verification semantics;
- release/promotion authority and signing/activation authority;
- security redaction/provenance requirements.

The candidate or automation helping generate it MUST NOT modify, replace, suppress, selectively reveal, or choose alternate versions of those authorities for the same candidate evaluation.

If one of those judging authorities legitimately changes through ordinary reviewed repository governance, the prior qualification is not silently inherited. The candidate MUST be re-evaluated against the newly identified authority set as required by the owning evaluation/release contract.

## 10. Protected-holdout non-interference

Candidate-generation logic MUST NOT receive protected-holdout expected outputs or case-level diagnostics that reveal them.

Permitted promotion feedback is limited to the aggregate, identity-bound qualification information explicitly allowed by `docs/security/evaluation-contract.md`.

A protected case disclosed for debugging or development is no longer an unseen protected case for that candidate lineage until ordinary declassification/promotion rules establish a new independent holdout revision.

Research automation MUST NOT create synthetic copies of protected labels, infer them from leaked logs, query side channels for them, or optimize against repeated protected qualification attempts as a tuning oracle.

## 11. Promotion lifecycle authority

A future learning specification may refine lifecycle names, but it MUST preserve independent promotion authority equivalent to:

```text
DRAFT -> REPLAYED -> BENCHMARKED -> HOLDOUT_QUALIFIED -> SHADOW -> APPROVED -> SIGNED -> ACTIVE
ACTIVE -> STALE | REVOKED | RETIRED
```

No candidate state transition may be self-certified solely by the component whose artifact is being promoted.

Low-authority declarative artifacts MAY use a simpler lifecycle in a future spec only if the independent review/evaluation boundary and authority ceiling remain explicit.

## 12. No self-modifying trusted core

R1 does not authorize autonomous modification or promotion of:

- Rust trusted-core/kernel code;
- policy authority construction;
- schema epistemic authority;
- reconciler authority;
- evaluator/metric definitions;
- protected-holdout labels or qualification code;
- verification authority;
- release gates, branch governance, signing, or activation authority.

Changes to those areas remain ordinary repository changes governed by Spec Kit, review, canonical CI, and repository governance.

An automated system MAY propose a normal candidate patch to these files in a future explicitly authorized workflow, but the proposal has no privileged status and MUST NOT alter the judge used to qualify itself.

## 13. Evidence and Finding interaction

Context, memory, feedback, and research artifacts may contribute only through canonical producer interfaces and their allowed epistemic classes.

They MUST preserve the canonical Evidence contract:

- LLM/model-derived material remains INFERENCE/HYPOTHESIS only;
- static or external content cannot claim runtime OBSERVATION;
- VERIFIED remains unavailable until the verification specification creates that authority;
- only the reconciler creates Findings;
- absence of evidence is not evidence of safety;
- contradiction remains visible rather than being erased by remembered preference.

A future producer-specific contract may impose a lower ceiling; it cannot raise the ceiling defined here without an explicit higher-authority Spec Kit change.

## 14. Fail-closed behavior

If the system cannot establish the provenance, scope, authority class, integrity state, expiry, or judging-authority identity required for an authority-sensitive use, it MUST NOT guess a stronger authority.

Safe outcomes include:

- treat the material as untrusted context only;
- mark it stale/unavailable;
- emit explicit coverage/integrity gaps;
- return ASK/UNDECIDABLE where the policy contract requires interaction or fail-closed handling;
- require ordinary reviewed re-qualification.

Silent ALLOW, silent suppression, epistemic promotion, or automatic candidate activation are forbidden fallbacks.

## 15. Auditability

When future memory/feedback/learning features persist or change security-relevant state, the owning spec SHOULD bind changes to canonical actor identity, provenance, prior/new state identity, and ASEL or equivalent auditable security events once that event kind exists.

Audit history is evidence of recorded state transition, not proof that the underlying human/model assertion was true.

## 16. R1 non-claims

T095 does **not** implement:

- general-purpose Security Memory;
- autonomous research agents;
- online learning;
- model fine-tuning;
- automatic rule suppression;
- automatic candidate promotion;
- signed community-pack distribution;
- producer reliability weighting as authority;
- trusted-core self-modification;
- protected-holdout services or secrets.

Those capabilities require dedicated later specifications and must inherit this authority ceiling unless an explicit constitutional/specification change safely supersedes it.

## 17. Required adversarial properties for future implementations

Any future implementation consuming this contract MUST include tests proving, as applicable:

1. instruction-shaped repository/MCP/web/model content cannot widen authority;
2. repeated feedback cannot become FACT/VERIFIED or silently disable detection;
3. stale/expired/unknown-provenance memory fails closed;
4. candidate-generation code cannot read protected expected outputs;
5. candidate code cannot modify evaluator/metric/holdout authority for its current qualification;
6. kernel DENY remains absorbing despite context/memory/feedback;
7. reconciler-only Finding creation remains enforced;
8. unavailable context or research infrastructure produces an explicit gap rather than a false PASS.

These tests are implementation obligations for the future owning tasks; T095 freezes the contract now without pretending the deferred subsystems exist.
