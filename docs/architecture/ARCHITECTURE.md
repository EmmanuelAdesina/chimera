# Causal Security Reasoning Engine

## Architecture

\\\
                    Epistemic Plane
                         |
                         |
    Crypto Plane <---- Causal Plane ----> Infra Plane
    (Math proofs)       |              (IAM, K8s, Terraform)
                        |
                   Parser Cascades
                   (Transport → App → DB → Defense)
                        |
                        |
                   Execution Plane
                   (Static analysis, Nuclei, Caido)
\\\

## The Core Insight

> The developer thinks there is one language. The machine is actually processing several languages in sequence.

Chimera models each language boundary, computes grammar differentials, and proves where trust assumptions break.

## Grammar Differential

A grammar differential exists when a character or token is **data** in layer *n* but **meta** in layer *n+1*, and no sanitizer translates between the grammars.

Example:
- JSON: \"O'Brien\" → safe string
- Python json.loads(): O'Brien → bare quote preserved
- SQL f-string: 'O'Brien' → quote terminates literal, injection begins

## Modules

| Module | Purpose |
|--------|---------|
| chimera/core/causal_engine.py | Grammar differential analyzer |
| chimera/core/epistemic_engine.py | Confidence calibration, self-interrogation |
| chimera/parsers/ | Parser cascade builders (JSON, SQL, Python AST, IAM) |
| chimera/tools/nuclei_bridge.py | One-day baseline + template analysis |
| chimera/tools/caido_bridge.py | Request execution + response observation |
| chimera/analysis/intent_model.py | Developer Intent Model (DIM) extraction |
| chimera/analysis/implementation.py | Actual Implementation Model (AIM) extraction |

## 30-Day Target

Build the grammar differential analyzer for one cascade:
- **Input**: Python web app using json.loads() + f-string SQL construction
- **Output**: Proof that the JSON → Python → SQL boundary contains a grammar differential at the quote character
- **Evidence**: Causal narrative + exact code location + exploit path

## Running

`ash
# Install
pip install -e .

# Run causal analysis on a target
python -m chimera analyze --target ./tests/targets/vuln_app.py --cascade json-python-sql
