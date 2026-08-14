"""Chimera Causal Differential Engine — Converts semantic differentials into hypotheses.

The Causal Differential Engine sits between the WorkflowStateMachineAnalyzer
(which produces raw differentials) and the Debunker (which kills false positives).

Its job:
1. Take differentials from the WorkflowStateMachineAnalyzer
2. Classify each differential into a vulnerability class
3. Build a causal chain (root cause -> mechanism -> impact)
4. Generate a Hypothesis with proper confidence, evidence, and falsifiers
5. Check memory for similar patterns (novelty detection)

The LLM is NOT the core here. The differential computation in the
WorkflowStateMachineAnalyzer is the primary intelligence. This engine
is the translation layer from raw differentials to testable hypotheses.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from chimera.core.semantic_graph import SemanticGraph
    from chimera.core.intent_model import IntentModel
    from chimera.core.implementation_model import ImplementationModel
    from chimera.core.workflow_state_analyzer import (
        WorkflowStateMachineAnalyzer, StateMachineDifferential,
    )
    from chimera.core.memory import StructuredMemory, SemanticMemory
    from chimera.models.hypothesis import Hypothesis


class CausalDifferentialEngine:
    """
    Converts semantic differentials into testable vulnerability hypotheses.

    The Causal Differential Engine is the bridge between the structural analysis
    (WorkflowStateMachineAnalyzer) and the adversarial review (Debunker). It:

    1. Receives StateMachineDifferential objects from the analyzer
    2. Maps each differential to a VulnerabilityClass
    3. Constructs a causal chain explaining the vulnerability
    4. Generates a Hypothesis with calibrated confidence
    5. Checks memory for similar patterns (novelty detection)
    6. Returns hypotheses ready for debunking
    """

    # Mapping from differential types and context to vulnerability classes
    _DIFFERENTIAL_VULN_MAP = {
        "missing_guard": {
            "privilege_escalation_vertical": 0.9,
            "privilege_escalation_horizontal": 0.85,
            "idor": 0.85,
            "state_machine_violation": 0.8,
        },
        "extra_transition": {
            "workflow_bypass": 0.8,
            "state_machine_violation": 0.75,
        },
        "bypass_path": {
            "workflow_bypass": 0.85,
            "race_condition": 0.5,
        },
        "missing_state": {
            "state_machine_violation": 0.4,
        },
    }

    def __init__(
        self,
        memory: Optional[object] = None,
    ) -> None:
        self.memory = memory
        self._hypothesis_count = 0

    def analyze(
        self,
        differentials: List[StateMachineDifferential],
        graph: SemanticGraph,
        intent_model: IntentModel,
        impl_model: ImplementationModel,
        target_version: str = "",
    ) -> List[Hypothesis]:
        """
        Main entry point: convert differentials into hypotheses.

        Args:
            differentials: Raw differentials from WorkflowStateMachineAnalyzer.
            graph: The semantic graph of the target system.
            intent_model: The intent model (expected semantics).
            impl_model: The implementation model (observed semantics).
            target_version: Version/commit hash of the target.

        Returns:
            List of Hypothesis objects ready for debunking.
        """
        from chimera.models.hypothesis import (
            Hypothesis, VulnerabilityClass,
        )

        hypotheses: List[Hypothesis] = []

        for diff in differentials:
            # Step 1: Classify the vulnerability
            vuln_class = self._classify_vulnerability(diff)
            if not vuln_class:
                continue

            # Step 2: Build causal chain
            causal_chain = self._build_causal_chain(diff, graph)

            # Step 3: Check memory for similar patterns
            is_novel = True
            memory_hits = []
            if self.memory:
                is_novel, memory_hits = self._check_novelty(diff, vuln_class)

            # Step 4: Calculate confidence
            confidence = self._calculate_confidence(
                diff, vuln_class, is_novel, memory_hits
            )

            # Step 5: Generate the hypothesis
            hypothesis = Hypothesis(
                claim=self._formulate_claim(diff, vuln_class, causal_chain),
                confidence=confidence,
                file_path=diff.file_path,
                target_version=target_version,
                vulnerability_class=vuln_class,
                differential_score=diff.severity,
                causal_chain=causal_chain,
                is_novel=is_novel,
                intent_model_ref=diff.expected,
                implementation_model_ref=diff.observed,
                attack_surface=diff.entity_ids,
            )

            # Step 6: Add prerequisite conditions
            hypothesis.prerequisite_conditions = self._infer_prerequisites(
                diff, vuln_class, graph
            )

            # Step 7: Set severity based on vulnerability class and differential
            hypothesis.severity = self._assess_severity(diff, vuln_class)

            hypotheses.append(hypothesis)
            self._hypothesis_count += 1

        return hypotheses

    def _classify_vulnerability(
        self, diff: StateMachineDifferential
    ) -> Optional[VulnerabilityClass]:
        """Map a differential to a specific vulnerability class."""
        from chimera.models.hypothesis import VulnerabilityClass

        # First check if the differential context explicitly states a class
        ctx_class = diff.context.get("vulnerability_class", "")
        if ctx_class:
            try:
                return VulnerabilityClass(ctx_class)
            except ValueError:
                pass

        # Fall back to mapping by differential type
        type_map = self._DIFFERENTIAL_VULN_MAP.get(diff.differential_type, {})
        if type_map:
            best_class = max(type_map, key=type_map.get)
            try:
                return VulnerabilityClass(best_class)
            except ValueError:
                pass

        return None

    def _build_causal_chain(
        self, diff: StateMachineDifferential, graph: SemanticGraph
    ) -> List[str]:
        """Build a causal chain explaining the vulnerability."""
        chain = []

        # Root cause: the missing check/guard
        chain.append(
            f"Root cause: {diff.differential_type} in '{diff.state_machine_name}'"
        )

        # Mechanism: what the code does wrong
        chain.append(f"Mechanism: {diff.observed}")

        # Impact: what an attacker can do
        vuln_class = diff.context.get("vulnerability_class", "")
        impact_map = {
            "idor": "Impact: Attacker can access/modify resources belonging to other users",
            "privilege_escalation_horizontal": (
                "Impact: User can perform actions on resources of other users "
                "at the same privilege level"
            ),
            "privilege_escalation_vertical": (
                "Impact: User can perform actions reserved for higher-privileged roles"
            ),
            "workflow_bypass": (
                "Impact: Attacker can skip required workflow steps, "
                "reaching unauthorized states"
            ),
            "state_machine_violation": (
                "Impact: System enters an invalid state, potentially causing "
                "data corruption or business logic violations"
            ),
            "race_condition": (
                "Impact: Concurrent requests can exploit timing to bypass checks"
            ),
        }
        chain.append(impact_map.get(vuln_class, "Impact: Security-relevant deviation from expected behavior"))

        return chain

    def _check_novelty(
        self, diff: StateMachineDifferential, vuln_class: VulnerabilityClass
    ) -> tuple:
        """Check memory for similar patterns. Returns (is_novel, memory_hits)."""
        if not self.memory or not hasattr(self.memory, 'semantic'):
            return True, []

        try:
            query = f"{diff.differential_type} {vuln_class.value} {diff.expected[:100]}"
            results = self.memory.semantic.search(query, n_results=3, filter_dict={
                "vulnerability_class": vuln_class.value,
            })
            if results and len(results) >= 1:
                # Check similarity score
                top_score = results[0].get("score", 0) if isinstance(results[0], dict) else 0
                if top_score > 0.85:
                    return False, results
            return True, []
        except Exception:
            return True, []

    def _calculate_confidence(
        self,
        diff: StateMachineDifferential,
        vuln_class: VulnerabilityClass,
        is_novel: bool,
        memory_hits: list,
    ) -> float:
        """Calculate initial confidence for a hypothesis."""
        # Base confidence from differential severity
        base = diff.severity

        # Boost from vulnerability class severity
        class_boost = {
            "idor": 0.1,
            "privilege_escalation_vertical": 0.15,
            "privilege_escalation_horizontal": 0.1,
            "workflow_bypass": 0.05,
            "state_machine_violation": 0.05,
            "race_condition": 0.0,
        }
        base += class_boost.get(vuln_class.value, 0.0)

        # Novelty boost (new patterns are slightly more uncertain)
        if is_novel:
            base *= 0.95
        else:
            # Previously seen patterns get a small confidence boost
            base *= 1.05

        # Clamp to [0.1, 0.9] — hypotheses should never start too certain
        return max(0.1, min(0.9, base))

    def _formulate_claim(
        self,
        diff: StateMachineDifferential,
        vuln_class: VulnerabilityClass,
        causal_chain: List[str],
    ) -> str:
        """Formulate a clear, specific claim for the hypothesis."""
        claim = (
            f"[{diff.differential_type.upper()}] In {diff.file_path or 'unknown file'}: "
            f"{diff.expected} HOWEVER {diff.observed} "
            f"This creates a {vuln_class.value} vulnerability. "
            f"Causal chain: {' -> '.join(causal_chain)}"
        )
        return claim

    def _infer_prerequisites(
        self,
        diff: StateMachineDifferential,
        vuln_class: VulnerabilityClass,
        graph: SemanticGraph,
    ) -> List[str]:
        """Infer conditions that must hold for the vulnerability to be exploitable."""
        prereqs = ["An attacker must be able to reach the vulnerable endpoint"]

        if vuln_class.value in {"idor", "privilege_escalation_horizontal"}:
            prereqs.append(
                "The attacker must know or be able to guess valid resource IDs"
            )
            prereqs.append(
                "No server-side enforcement of ownership at the data access layer"
            )
        elif vuln_class.value == "privilege_escalation_vertical":
            prereqs.append(
                "The attacker must have a valid session at a lower privilege level"
            )
        elif vuln_class.value == "workflow_bypass":
            prereqs.append(
                "The workflow state must be modifiable via the vulnerable transition"
            )
        elif vuln_class.value == "state_machine_violation":
            prereqs.append(
                "The system must not have compensating controls outside the analyzed code"
            )

        return prereqs

    def _assess_severity(
        self, diff: StateMachineDifferential, vuln_class: VulnerabilityClass
    ) -> Severity:
        """Assess severity based on vulnerability class and differential."""
        from chimera.models.hypothesis import Severity

        severity_map = {
            "privilege_escalation_vertical": Severity.CRITICAL,
            "idor": Severity.HIGH,
            "privilege_escalation_horizontal": Severity.HIGH,
            "workflow_bypass": Severity.MEDIUM,
            "state_machine_violation": Severity.MEDIUM,
            "race_condition": Severity.HIGH,
        }
        return severity_map.get(vuln_class.value, Severity.MEDIUM)
