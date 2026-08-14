"""
Chimera — Closed-Loop Reasoning Engine for Business Logic Vulnerability Discovery.

A dynamic semantic graph-based system that generates adversarial hypotheses from
contradictions between Expected Semantics (IntentModel) and Observed Semantics
(ImplementationModel), then validates through targeted, low-noise experiments.

Architectural Pillars:
    1. Causal Differential Engine is the Core (LLM is plugin)
    2. Debunker is the Gatekeeper (hostile adversary, 90% false-positive kill rate)
    3. Memory is the Moat (vector embeddings, cross-target pattern retrieval)
    4. Evidence is the Currency (AST nodes, HTTP traces, verifiable chain of custody)

Target Vulnerability Classes:
    - IDOR (Insecure Direct Object Reference)
    - Privilege Escalation (Horizontal / Vertical)
    - Workflow Bypasses
    - Race Conditions
    - State Machine Violations
"""

__version__ = "2.0.0"
__author__ = "Project Chimera"
