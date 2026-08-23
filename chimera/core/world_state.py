"""
Chimera World State — Mutable analysis state tracked across the reasoning loop.

WorldState is the single source of truth for the current analysis session.
It tracks:
    - Which files have been parsed
    - The current semantic graph
    - All generated hypotheses and their statuses
    - Analysis configuration and target metadata
    - Phase tracking for the orchestrator

Every component reads from and writes to WorldState. It is NOT thread-safe
by design — the Orchestrator runs the loop single-threaded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set

if TYPE_CHECKING:
    from chimera.core.semantic_graph import SemanticGraph
    from chimera.models.hypothesis import Hypothesis


class AnalysisPhase(Enum):
    """Phases of the Chimera analysis loop."""
    INITIALIZATION = "initialization"
    PARSING = "parsing"
    GRAPH_CONSTRUCTION = "graph_construction"
    INTENT_EXTRACTION = "intent_extraction"
    IMPLEMENTATION_EXTRACTION = "implementation_extraction"
    DIFFERENTIAL_ANALYSIS = "differential_analysis"
    HYPOTHESIS_GENERATION = "hypothesis_generation"
    DEBUNKING = "debunking"
    EXPERIMENTATION = "experimentation"
    EPISTEMIC_CALIBRATION = "epistemic_calibration"
    REPORTING = "reporting"
    COMPLETE = "complete"


@dataclass
class AnalysisConfig:
    """Configuration for the current analysis run."""
    target_path: str = ""
    target_version: str = ""
    target_language: str = "python"
    max_hypotheses: int = 50
    debunker_passes: int = 2
    confidence_threshold: float = 0.6
    experiment_budget: int = 20
    enable_dynamic_analysis: bool = False
    base_url: str = "http://localhost:8000"
    auth_token: str = ""
    verbose: bool = False
    output_path: str = "./chimera_results"


@dataclass
class WorldState:
    """
    Central mutable state for a single Chimera analysis session.

    This is the shared blackboard that all components read from and write to.
    The Orchestrator manages transitions between phases and ensures
    components operate on consistent state.
    """
    # Configuration
    config: AnalysisConfig = field(default_factory=AnalysisConfig)

    # Phase tracking
    current_phase: AnalysisPhase = AnalysisPhase.INITIALIZATION
    phase_history: List[Dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    # Parsed files
    parsed_files: Set[str] = field(default_factory=set)
    parse_errors: Dict[str, str] = field(default_factory=dict)

    # Semantic graph (set by orchestrator after parsing)
    semantic_graph: Optional[SemanticGraph] = None

    # Hypotheses
    hypotheses: List[Hypothesis] = field(default_factory=list)
    hypotheses_by_id: Dict[str, Hypothesis] = field(default_factory=dict)
    debunked_count: int = 0
    confirmed_count: int = 0
    rejected_count: int = 0

    # Analysis metrics
    total_differentials_found: int = 0
    total_experiments_run: int = 0
    memory_hits: int = 0

    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Results
    confirmed_vulnerabilities: List[Hypothesis] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Phase management
    # ------------------------------------------------------------------

    def set_phase(self, new_phase: AnalysisPhase, note: str = "") -> None:
        """Transition to a new analysis phase, recording history."""
        old_phase = self.current_phase
        self.phase_history.append({
            "from": old_phase.value,
            "to": new_phase.value,
            "timestamp": datetime.utcnow().isoformat(),
            "note": note,
        })
        self.current_phase = new_phase
        if new_phase == AnalysisPhase.COMPLETE and self.completed_at is None:
            self.completed_at = datetime.utcnow()

    # ------------------------------------------------------------------
    # File tracking
    # ------------------------------------------------------------------

    def mark_parsed(self, file_path: str) -> None:
        """Mark a file as successfully parsed."""
        self.parsed_files.add(file_path)

    def record_parse_error(self, file_path: str, error: str) -> None:
        """Record a parse error for a file."""
        self.parse_errors[file_path] = error
        self.errors.append(f"Parse error in {file_path}: {error}")

    # ------------------------------------------------------------------
    # Hypothesis management
    # ------------------------------------------------------------------

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        """Register a new hypothesis."""
        self.hypotheses.append(hypothesis)
        self.hypotheses_by_id[hypothesis.id] = hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Retrieve a hypothesis by ID."""
        return self.hypotheses_by_id.get(hypothesis_id)

    def get_active_hypotheses(self) -> List[Hypothesis]:
        """Get hypotheses that are still alive (not debunked or rejected)."""
        from chimera.models.hypothesis import HypothesisStatus
        active_statuses = {
            HypothesisStatus.GENERATED,
            HypothesisStatus.UNDER_REVIEW,
            HypothesisStatus.EXPERIMENT_SCHEDULED,
            HypothesisStatus.EXPERIMENT_RUNNING,
        }
        return [h for h in self.hypotheses if h.status in active_statuses]

    def get_hypotheses_by_status(
        self, status: "HypothesisStatus"
    ) -> List[Hypothesis]:
        """Get all hypotheses with a specific status."""
        return [h for h in self.hypotheses if h.status == status]

    def record_debunked(self, hypothesis: Hypothesis) -> None:
        """Record a debunked hypothesis (idempotent)."""
        if getattr(hypothesis, "_debunked_recorded", False):
            return
        hypothesis._debunked_recorded = True  # type: ignore[attr-defined]
        self.debunked_count += 1

    def record_confirmed(self, hypothesis: Hypothesis) -> None:
        """Record a confirmed vulnerability (idempotent)."""
        if getattr(hypothesis, "_confirmed_recorded", False):
            return
        hypothesis._confirmed_recorded = True  # type: ignore[attr-defined]
        self.confirmed_count += 1
        self.confirmed_vulnerabilities.append(hypothesis)

    def record_rejected(self, hypothesis: Hypothesis) -> None:
        """Record a rejected hypothesis — experiment disproved it (idempotent)."""
        if getattr(hypothesis, "_rejected_recorded", False):
            return
        hypothesis._rejected_recorded = True  # type: ignore[attr-defined]
        self.rejected_count += 1

    # ------------------------------------------------------------------
    # Metrics and reporting
    # ------------------------------------------------------------------

    def record_differential(self) -> None:
        """Increment the differential counter."""
        self.total_differentials_found += 1

    def record_experiment(self) -> None:
        """Increment the experiment counter."""
        self.total_experiments_run += 1

    def add_error(self, error: str) -> None:
        """Record a non-fatal error."""
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Record a warning."""
        self.warnings.append(warning)

    def summary(self, include_details: bool = True) -> Dict[str, Any]:
        """Produce a summary of the analysis state.

        Counts live under explicit ``*_count``-style keys; full detail lists
        (``errors``, ``warnings``, ``hypotheses``) are included when
        ``include_details`` is true. Both consumers — dashboards that want
        numbers and callers that want the artifacts — are first-class.
        """
        base: Dict[str, Any] = {
            "phase": self.current_phase.value,
            "target": self.config.target_path,
            "target_version": self.config.target_version,
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            # Counts
            "files_parsed": len(self.parsed_files),
            "parse_errors": len(self.parse_errors),
            "total_hypotheses": len(self.hypotheses),
            "active_hypotheses": len(self.get_active_hypotheses()),
            "debunked": self.debunked_count,
            "confirmed": self.confirmed_count,
            "rejected": self.rejected_count,
            "differentials_found": self.total_differentials_found,
            "experiments_run": self.total_experiments_run,
            "memory_hits": self.memory_hits,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            # Details
            "errors": list(self.errors) if include_details else [],
            "warnings": list(self.warnings) if include_details else [],
            "parse_error_details": dict(self.parse_errors) if include_details else {},
            "hypotheses": (
                [h.to_dict() for h in self.hypotheses] if include_details else []
            ),
            "confirmed_vulnerabilities": (
                [h.to_dict() for h in self.confirmed_vulnerabilities]
                if include_details else []
            ),
            "graph_stats": (
                self.semantic_graph.stats() if self.semantic_graph else None
            ),
        }
        return base
