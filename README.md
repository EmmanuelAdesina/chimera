# Chimera
# Causal Security Reasoning Engine

## What
Chimera does not scan for known bugs. It reasons about **security assumption violations** by modeling how data transforms across parser cascades — from transport layer to database execution — and finding where developer intent diverges from implementation reality.

## Three Planes
- **Causal Plane**: Grammar differential analysis across parser boundaries
- **Epistemic Plane**: Confidence calibration and self-interrogation
- **Execution Plane**: Tool integration (Nuclei, Caido) for validation

## Current Status
Pre-alpha. Building the grammar differential analyzer for JSON → Python → SQL cascades.

## License
MIT
