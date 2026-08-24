# Clarification Closeout — Sentrdel v0.1 Evidence + Guard Foundation

**Date:** 2026-08-24  
**Status:** CLARIFICATION_COMPLETE  
**Spec:** `specs/001-v0-1-evidence-guard-foundation/spec.md`

## Founder decisions incorporated

1. **Primary language:** Rust. This is binding for the trusted core.
2. **Product goal:** Sentrdel must become an essential security tool developers use while coding, not merely a PR scanner.
3. **Scope direction:** long-term A-to-Z project security, including source, data, identity, infrastructure, CI/CD, deployment, runtime, AI agents and MCP.
4. **Provider-aware security:** Supabase and similar platforms require first-class provider-specific analysis; Supabase is the first P0 provider pack on the roadmap.
5. **Planning process:** repository planning and implementation must use Spec Kit artifacts.
6. **Open-source posture:** the product core is open source and local-first.

## Independent adversarial-review decisions incorporated

The external architecture review produced a `GO WITH MAJOR CHANGES` verdict. The following critiques are accepted into R1:

- GUARD cannot honestly promise vendor-neutral pre-execution interception across agents that expose no hook; v0.1 focuses on controllable environment/protocol seams and labels enforcement fidelity.
- Sentrdel will build a thin evidence/property graph, not a universal CPG.
- The evidence schema and finding lifecycle are first-class product assets.
- VERIFY is deferred from v0.1 and will be bounded, opt-in test execution rather than autonomous exploitation.
- The initial Rust workspace is intentionally bounded rather than split into many premature crates.
- Business-logic security is preserved as a major differentiator but moves to R2 after the evidence substrate exists.

## Clarifications resolved by design

### C1 — What does "Guard" mean if an agent exposes no hook?

**Resolution:** Guard means enforced policy only where Sentrdel controls a seam (for example MCP gateway or CI gate). Other visibility surfaces are explicitly `PARTIAL` or `ADVISORY`. No universal-interception claim is allowed.

### C2 — Does Sentrdel build its own full code property graph?

**Resolution:** No. R1 builds a provenance-aware evidence/property graph and imports higher-confidence semantic edges from qualified producers such as SCIP/external engines. AST/CFG/type-system completeness is out of scope.

### C3 — Does the long-term A-to-Z goal require all providers in v0.1?

**Resolution:** No. R1 must detect provider/framework signals and define a stable Security Pack evidence contract. Full provider-specific analysis begins in R3 with Supabase as P0.

### C4 — Can an LLM decide that a finding is safe?

**Resolution:** No. LLM output is structurally restricted to inference/hypothesis. It cannot set FACT/VERIFIED, suppress deterministic evidence, downgrade kernel policy, or independently lower a high-confidence deterministic claim.

### C5 — What happens when an engine is unavailable or fails?

**Resolution:** The affected capability becomes a visible coverage gap. Sentrdel must not translate missing analysis into a clean verdict.

### C6 — Is verification included in v0.1?

**Resolution:** No. The canonical schema may reserve verification states, but execution/sandbox verification is R5. This prevents the first release from carrying an immature isolation liability.

### C7 — Which project license is frozen?

**Resolution:** The project is open source, but the exact core license is not yet founder-frozen. Before any donor source is copied or a release is published, the implementation tasks require an explicit license decision and third-party policy. Until then, concepts may be studied and external tools may only be referenced in planning.

## Unresolved blockers

**None for planning.**

The exact core license is a pre-implementation/reuse governance gate, not a blocker to producing the architecture and task package.

## Scope lock

R1 MUST NOT silently expand to include:

- full Supabase or Firebase security-pack implementation;
- production/live exploitation;
- runtime/eBPF enforcement;
- full verification sandbox;
- IDE extensions or GitHub App;
- universal CPG construction;
- automatic fix application;
- broad rule-count competition.

Any such expansion requires its own roadmap slice/spec or an explicit amendment to R1.
