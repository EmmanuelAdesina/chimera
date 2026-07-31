# Chimera

**Causal Security Reasoning Engine**

Finds violated security assumptions by modeling parser cascades, grammar differentials, and intent-vs-implementation contradictions.

## The Reasoning Loop

1. **Observe** â€” Gather raw target data
2. **Model** â€” Build parser cascades and system models
3. **Hypothesize** â€” Generate falsifiable claims
4. **Interrogate** â€” Skeptic challenges each hypothesis
5. **Test** â€” Gather evidence via execution adapters
6. **Update** â€” Revise confidence based on observations
7. **Decide** â€” Confirm, reject, or iterate
8. **Remember** â€” Store everything in structured memory

## Quick Start

`powershell\n.\\scripts\\setup.ps1\nmake test\npython -m chimera analyze\n`

## Structure

| Path | Purpose |
|------|---------|
| chimera/core/ | Causal engine, epistemic monitor, memory, orchestrator |
| chimera/models/ | Pydantic models: Hypothesis, Evidence, Grammar |
| chimera/parsers/ | Parser cascade builders |
| chimera/execution/ | Capability-based execution adapters |
| chimera/plugins/ | Drop-in extensions |
| 	ests/ | Unit + integration tests |

## The Core Insight

> The developer thinks there is one language. The machine is actually processing several languages in sequence.

Chimera models each boundary, computes grammar differentials, and proves where trust assumptions break.

## License\nMIT
