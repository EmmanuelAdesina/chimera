"""Chimera Hypothesis Model — Adversarial claims about business logic vulnerabilities.

Every hypothesis represents a specific, testable claim about a potential
vulnerability in the target system. Hypotheses are born from contradictions
between Expected Semantics (IntentModel) and Observed Semantics
(ImplementationModel), then survive the Debunker's 9-vector assault.

The Hypothesis lifecycle:
    GENERATED → UNDER_REVIEW → [DEBUNKED | EXPERIMENT_SCHEDULED →
    EXPERIMENT_RUNNING → CONFIRMED | REJECTED]

Critical: Every field referenced by the Debunker MUST exist here.
No phantom fields. No missing attributes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import uuid

if TYPE_CHECKING:
    from chimera.models.evidence import Evidence


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class VulnerabilityClass(Enum):
    """Target vulnerability classes Chimera discovers."""
    IDOR = "idor"
    PRIVILEGE_ESCALATION_HORIZONTAL = "privilege_escalation_horizontal"
    PRIVILEGE_ESCALATION_VERTICAL = "privilege_escalation_vertical"
    WORKFLOW_BYPASS = "workflow_bypass"
    RACE_CONDITION = "race_condition"
    STATE_MACHINE_VIOLATION = "state_machine_violation"


class HypothesisStatus(Enum):
    """Lifecycle states of a hypothesis."""
    GENERATED = "generated"
    UNDER_REVIEW = "under_review"
    DEBUNKED = "debunked"
    EXPERIMENT_SCHEDULED = "experiment_scheduled"
    EXPERIMENT_RUNNING = "experiment_running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class Severity(Enum):
    """Impact severity if the hypothesis is true."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Hypothesis
# ---------------------------------------------------------------------------


@dataclass
class Hypothesis:
    """
    A testable adversarial claim about a potential vulnerability.

    This is the central artifact in Chimera's reasoning loop. Every hypothesis
    MUST have all fields populated — no phantom references, no defaults that
    the Debunker or Orchestrator will trip over.

    Attributes:
        id: Unique identifier for this hypothesis.
        claim: The core assertion (e.g., "User A can access User B's order
            because the endpoint lacks ownership validation in the
            ImplementationModel, contradicting the IntentModel's requirement").
        confidence: Current confidence score [0.0, 1.0]. Calibrated by
            EpistemicEngine, adjusted by evidence and debunking.
        evidence: List of Evidence artifacts supporting this hypothesis.
        falsifiers: List of specific observations that would falsify this
            hypothesis. Populated during generation and expanded by Debunker.
        metadata: Arbitrary key-value metadata (vuln class, affected endpoints,
            etc.).
        file_path: Primary source file where the vulnerability exists.
        target_version: Version/commit hash of the target being analyzed.
        vulnerability_id: Short human-readable identifier (e.g., "CHM-A1B2C3D4").
        status: Current lifecycle status.
        vulnerability_class: Which vulnerability class this falls under.
        causal_chain: Ordered list of causal steps from root cause to impact.
        counter_hypotheses: Alternative explanations the Debunker generates.
        severity: Impact severity if confirmed.
        created_at: Timestamp when this hypothesis was first generated.
        updated_at: Timestamp of the last modification.
        debunker_notes: Notes from the Debunker's 9-vector assault.
        experiment_results: Results from validation experiments.
        intent_model_ref: Reference to the IntentModel expectation that was violated.
        implementation_model_ref: Reference to the ImplementationModel observation
            that contradicts the intent.
        differential_score: Magnitude of the semantic differential that spawned
            this hypothesis (0.0-1.0).
        is_novel: Whether this pattern was found in memory (False) or is
            genuinely new (True).
        attack_surface: Which endpoints/state machines are affected.
        prerequisite_conditions: Conditions that must hold for this vuln to
            be exploitable.
    """
    id: str = field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:10].upper()}")
    claim: str = ""
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    falsifiers: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    file_path: str = ""
    target_version: str = ""
    vulnerability_id: str = field(
        default_factory=lambda: f"CHM-{uuid.uuid4().hex[:8].upper()}"
    )
    status: HypothesisStatus = HypothesisStatus.GENERATED
    vulnerability_class: Optional[VulnerabilityClass] = None
    causal_chain: List[str] = field(default_factory=list)
    counter_hypotheses: List[Hypothesis] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    debunker_notes: Dict[str, Any] = field(default_factory=dict)
    experiment_results: List[Dict[str, Any]] = field(default_factory=list)
    intent_model_ref: str = ""
    implementation_model_ref: str = ""
    differential_score: float = 0.0
    is_novel: bool = True
    attack_surface: List[str] = field(default_factory=list)
    prerequisite_conditions: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def transition_to(self, new_status: HypothesisStatus) -> None:
        """
        Move this hypothesis to a new status with validation.

        Valid transitions:
            GENERATED → UNDER_REVIEW
            UNDER_REVIEW → DEBUNKED | EXPERIMENT_SCHEDULED
            EXPERIMENT_SCHEDULED → EXPERIMENT_RUNNING
            EXPERIMENT_RUNNING → CONFIRMED | REJECTED
        """
        valid_transitions = {
            HypothesisStatus.GENERATED: {HypothesisStatus.UNDER_REVIEW},
            HypothesisStatus.UNDER_REVIEW: {
                HypothesisStatus.DEBUNKED,
                HypothesisStatus.EXPERIMENT_SCHEDULED,
            },
            HypothesisStatus.EXPERIMENT_SCHEDULED: {HypothesisStatus.EXPERIMENT_RUNNING},
            HypothesisStatus.EXPERIMENT_RUNNING: {
                HypothesisStatus.CONFIRMED,
                HypothesisStatus.REJECTED,
            },
        }
        allowed = valid_transitions.get(self.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition: {self.status.value} → {new_status.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self.status = new_status
        self.updated_at = datetime.utcnow()

    # ------------------------------------------------------------------
    # Evidence management
    # ------------------------------------------------------------------

    def add_evidence(self, evidence: Evidence) -> None:
        """Attach a piece of supporting evidence."""
        self.evidence.append(evidence)
        self.updated_at = datetime.utcnow()

    def add_falsifier(self, falsifier: str) -> None:
        """Add a specific observation that would falsify this hypothesis."""
        if falsifier not in self.falsifiers:
            self.falsifiers.append(falsifier)
            self.updated_at = datetime.utcnow()

    def add_causal_step(self, step: str) -> None:
        """Append a step to the causal chain (ordered: root cause → impact)."""
        self.causal_chain.append(step)
        self.updated_at = datetime.utcnow()

    def add_counter_hypothesis(self, counter: Hypothesis) -> None:
        """Add an alternative explanation generated by the Debunker."""
        self.counter_hypotheses.append(counter)
        self.updated_at = datetime.utcnow()

    def add_experiment_result(self, result: Dict[str, Any]) -> None:
        """Record the outcome of a validation experiment."""
        self.experiment_results.append(result)
        self.updated_at = datetime.utcnow()

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize hypothesis to dictionary."""
        return {
            "id": self.id,
            "claim": self.claim,
            "confidence": self.confidence,
            "evidence_count": len(self.evidence),
            "falsifiers": self.falsifiers,
            "metadata": self.metadata,
            "file_path": self.file_path,
            "target_version": self.target_version,
            "vulnerability_id": self.vulnerability_id,
            "status": self.status.value,
            "vulnerability_class": (
                self.vulnerability_class.value if self.vulnerability_class else None
            ),
            "causal_chain": self.causal_chain,
            "counter_hypotheses_count": len(self.counter_hypotheses),
            "severity": self.severity.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "debunker_notes": self.debunker_notes,
            "experiment_results_count": len(self.experiment_results),
            "intent_model_ref": self.intent_model_ref,
            "implementation_model_ref": self.implementation_model_ref,
            "differential_score": self.differential_score,
            "is_novel": self.is_novel,
            "attack_surface": self.attack_surface,
            "prerequisite_conditions": self.prerequisite_conditions,
        }

    def summary(self) -> str:
        """One-line human-readable summary."""
        vuln_class = (
            self.vulnerability_class.value if self.vulnerability_class else "unknown"
        )
        return (
            f"[{self.vulnerability_id}] [{vuln_class}] "
            f"conf={self.confidence:.2f} status={self.status.value} — {self.claim[:120]}"
        )

    @staticmethod
    def from_differential(
        intent_expectation: str,
        implementation_observation: str,
        file_path: str,
        vuln_class: VulnerabilityClass,
        differential_score: float,
        causal_chain: Optional[List[str]] = None,
    ) -> Hypothesis:
        """
        Factory: create a hypothesis directly from a semantic differential.

        This is the primary way hypotheses are born — when the Causal
        Differential Engine detects a contradiction between what the
        developer intended and what the code actually does.
        """
        claim = (
            f"Intent expects '{intent_expectation}' but Implementation observes "
            f"'{implementation_observation}' in {file_path}. "
            f"This contradiction suggests a {vuln_class.value} vulnerability."
        )
        h = Hypothesis(
            claim=claim,
            confidence=min(0.3 + differential_score * 0.4, 0.9),
            file_path=file_path,
            vulnerability_class=vuln_class,
            differential_score=differential_score,
            intent_model_ref=intent_expectation,
            implementation_model_ref=implementation_observation,
            causal_chain=causal_chain or [],
            is_novel=True,
        )
        h.add_falsifier(
            f"Ownership/authorization check exists but was missed during AST analysis"
        )
        h.add_falsifier(
            f"Runtime middleware enforces the constraint not visible in source code"
        )
        h.add_falsifier(
            f"The differential is a false positive due to indirect authorization via a decorator or mixin"
        )
        return h
