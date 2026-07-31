# Chimera Architecture

## The Reasoning Loop

Chimera is not a scanner. It is a reasoning engine. Everything flows through this loop:

`\n1. OBSERVE\n      |\n      v\n2. MODEL (Build parser cascades, system models)\n      |\n      v\n3. HYPOTHESIZE (Generate falsifiable claims)\n      |\n      v\n4. INTERROGATE (Skeptic challenges each hypothesis)\n      |\n      v\n5. TEST (Gather evidence via execution adapters)\n      |\n      v\n6. UPDATE (Revise confidence based on observations)\n      |\n      v\n7. DECIDE (Confirm, reject, or iterate)\n      |\n      v\n8. REMEMBER (Store in structured memory)\n      |\n      +---> Back to 1 (with what we learned)\n`

This separates Chimera from every scanner on the market. Scanners skip steps 2, 3, 4, and 6. They observe, then report. Chimera observes, models, claims, challenges, tests, revises, decides, and remembers.

## The Central Object: Hypothesis

Everything revolves around Hypothesis:

| Field | Purpose |
|-------|---------|
| claim | The falsifiable statement |
| equired_conditions | What must be true for the claim to hold |
| evidence | Observations that support the claim |
| missing_information | What we still need to know |
| alsifiers | What would prove this claim false |
| confidence | Current belief strength |
| status | proposed â†’ testing â†’ confirmed / rejected |

A finding is not a finding until it is a Hypothesis that has survived interrogation and testing.

## The Four Planes

### Causal Plane
- CausalEngine: Analyzes parser cascades for grammar differentials
- ParserLayer: Represents one layer in the cascade
- GrammarDifferential: Proof that a trust boundary is violated
- **Output**: Hypothesis objects with required conditions and falsifiers

### Epistemic Plane
- EpistemicMonitor: Interrogates hypotheses before they become beliefs
- Questions every hypothesis: \"What would prove you wrong?\"
- Tracks known biases and calibration history
- **Output**: Surviving hypotheses promoted to 	esting status

### Memory Plane
Two systems, distinct purposes:

**Structured Memory (SQLite) â€” Source of Truth**
- hypotheses: All hypotheses with full provenance
- indings: Confirmed hypotheses with proof
- decisions: Why we took each action
- ailures: What went wrong and why

**Semantic Memory (Vector DB) â€” Retrieval Aid**
- Similar code patterns
- Similar vulnerability classes
- Previous reasoning chains
- **Never** the source of truth. Always derived from structured memory.

### Execution Plane
Capabilities, not products:

| Capability | Purpose | Current Adapters |
|------------|---------|------------------|
| **Observation** | Map target surface | Nuclei |
| **Controlled Testing** | Send crafted inputs, observe responses | Caido |
| **Environment Interaction** | Act like a user or system | Browser, Terminal |
| **Runtime Verification** | Confirm exploitability without damage | Custom instrumentation |

Adapters are replaceable. The capability is stable.

## Solo Developer Rules
- One make test runs everything in < 10 seconds
- Pydantic models enforce contracts across modules
- Every module has a Base* ABC for extension
- Hypothesis is the center of gravity â€” everything produces, consumes, or validates it
