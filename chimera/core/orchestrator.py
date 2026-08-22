"""Chimera Orchestrator — The main analysis loop.

The Orchestrator is the single entry point for Chimera. It coordinates
all modules in the correct order and manages the WorldState through
the analysis phases.

Analysis Loop:
    1. PARSING — Parse target files, build SemanticGraph
    2. INTENT_EXTRACTION — Extract expected semantics (IntentModel)
    3. IMPLEMENTATION_EXTRACTION — Extract observed semantics (ImplementationModel)
    4. DIFFERENTIAL_ANALYSIS — WorkflowStateMachineAnalyzer computes differentials
    5. HYPOTHESIS_GENERATION — CausalDifferentialEngine creates hypotheses
    6. DEBUNKING — Debunker runs 9 attack vectors on each hypothesis
    7. EPISTEMIC_CALIBRATION — EpistemicEngine calibrates confidence
    8. EXPERIMENTATION — ExecutionPlanner designs experiments
    9. REPORTING — Collect results

CRITICAL: The orchestrator must run without crashing.
Every phase has error handling and graceful degradation.
"""

from __future__ import annotations
import os
import sys
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from chimera.core.world_state import WorldState, AnalysisPhase, AnalysisConfig
from chimera.core.semantic_graph import SemanticGraph
from chimera.core.intent_model import IntentModel
from chimera.core.implementation_model import ImplementationModel
from chimera.core.workflow_state_analyzer import WorkflowStateMachineAnalyzer
from chimera.core.causal_differential_engine import CausalDifferentialEngine
from chimera.core.debunker import Debunker
from chimera.core.epistemic_engine import EpistemicEngine
from chimera.core.execution_planner import ExecutionPlanner
from chimera.core.memory import StructuredMemory, SemanticMemory
from chimera.models.hypothesis import Hypothesis, HypothesisStatus

logger = logging.getLogger(__name__)


class ChimeraOrchestrator:
    """
    Main orchestrator for Chimera analysis.

    Coordinates all modules through the analysis loop.
    Must run without crashing — every phase has error handling.
    """

    def __init__(self, config: Optional[AnalysisConfig] = None) -> None:
        # Optional extensions are initialized safely and idempotently so core
        # analysis remains usable when Tree-sitter is not installed.
        from chimera.core.asi_runtime_patch import initialize_asi_extensions
        initialize_asi_extensions()
        self.state = WorldState(config=config or AnalysisConfig())
        self.graph = SemanticGraph()
        self.intent_model = IntentModel()
        self.impl_model = ImplementationModel()
        self.analyzer = WorkflowStateMachineAnalyzer()
        self.differential_engine: Optional[CausalDifferentialEngine] = None
        self.debunker = Debunker()
        self.epistemic = EpistemicEngine()
        self.planner = ExecutionPlanner()
        self.structured_memory = StructuredMemory()
        self.semantic_memory = SemanticMemory()

    def analyze(self) -> Dict[str, Any]:
        """Run the full Chimera analysis loop. Returns summary."""
        try:
            self._run_loop()
        except Exception as e:
            logger.error(f"Orchestrator error: {e}", exc_info=True)
            self.state.add_error(str(e))
        self.state.set_phase(AnalysisPhase.COMPLETE)
        return self.state.summary()

    def _run_loop(self) -> None:
        """Execute all analysis phases sequentially."""
        self._phase_parsing()
        self._phase_intent_extraction()
        self._phase_implementation_extraction()
        self._phase_differential_analysis()
        self._phase_hypothesis_generation()
        self._phase_debunking()
        self._phase_epistemic_calibration()
        self._phase_experimentation()
        self._phase_reporting()

    def _phase_parsing(self) -> None:
        """Phase 1: Parse target files and build the SemanticGraph."""
        self.state.set_phase(AnalysisPhase.PARSING)
        target = self.state.config.target_path
        if not target or not os.path.exists(target):
            self.state.add_warning(f"Target path not found: {target}")
            return

        self.semantic_memory.initialize()
        self.state.semantic_graph = self.graph

        # Discover files
        target_path = Path(target)
        if target_path.is_file():
            files = [str(target_path)]
        elif target_path.is_dir():
            files = self._discover_files(target_path)
        else:
            files = []

        for fpath in files:
            try:
                self._parse_file(fpath)
                self.state.mark_parsed(fpath)
            except Exception as e:
                self.state.record_parse_error(fpath, str(e))

    def _discover_files(self, directory: Path) -> List[str]:
        """Discover parseable files in a directory."""
        extensions = {"py", "sql"}
        files = []
        for root, _, filenames in os.walk(directory):
            for fname in filenames:
                if any(fname.endswith(f".{ext}") for ext in extensions):
                    files.append(str(Path(root) / fname))
        return files[:200]  # Cap at 200 files

    def _parse_file(self, file_path: str) -> None:
        """Parse a single file using the appropriate parser."""
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
        if not source.strip():
            return

        if file_path.endswith(".py"):
            from chimera.parsers.languages.python_parser import PythonParser
            parser = PythonParser()
            evidence = parser.parse(file_path, source, self.graph)
            for ev in evidence:
                self.state.semantic_graph  # ensure graph is set
        elif file_path.endswith(".sql"):
            from chimera.parsers.languages.sql_parser import SQLParser
            parser = SQLParser()
            evidence = parser.parse(file_path, source, self.graph)

    def _phase_intent_extraction(self) -> None:
        """Phase 2: Extract expected semantics."""
        self.state.set_phase(AnalysisPhase.INTENT_EXTRACTION)
        try:
            expectations = self.intent_model.extract(self.graph)
            logger.info(f"Extracted {len(expectations)} intent expectations")
        except Exception as e:
            self.state.add_error(f"Intent extraction failed: {e}")

    def _phase_implementation_extraction(self) -> None:
        """Phase 3: Extract observed semantics."""
        self.state.set_phase(AnalysisPhase.IMPLEMENTATION_EXTRACTION)
        try:
            observations = self.impl_model.extract(self.graph)
            logger.info(f"Extracted {len(observations)} implementation observations")
        except Exception as e:
            self.state.add_error(f"Implementation extraction failed: {e}")

    def _phase_differential_analysis(self) -> None:
        """Phase 4: Compute semantic differentials."""
        self.state.set_phase(AnalysisPhase.DIFFERENTIAL_ANALYSIS)
        try:
            self.analyzer.extract_state_machines(self.graph)
            self._differentials = self.analyzer.compute_differentials(
                self.intent_model, self.impl_model, self.graph
            )
            self.state.total_differentials_found = len(self._differentials)
            logger.info(f"Found {len(self._differentials)} differentials")
        except Exception as e:
            self.state.add_error(f"Differential analysis failed: {e}")
            self._differentials = []

    def _phase_hypothesis_generation(self) -> None:
        """Phase 5: Generate hypotheses from differentials."""
        self.state.set_phase(AnalysisPhase.HYPOTHESIS_GENERATION)
        differentials = getattr(self, '_differentials', [])
        if not differentials:
            logger.info("No differentials — skipping hypothesis generation")
            return
        try:
            self.differential_engine = CausalDifferentialEngine(
                memory=self
            )
            hypotheses = self.differential_engine.analyze(
                differentials, self.graph, self.intent_model, self.impl_model,
                target_version=self.state.config.target_version,
            )
            for h in hypotheses:
                h.target_version = self.state.config.target_version
                self.state.add_hypothesis(h)
            logger.info(f"Generated {len(hypotheses)} hypotheses")
        except Exception as e:
            self.state.add_error(f"Hypothesis generation failed: {e}")

    def _phase_debunking(self) -> None:
        """Phase 6: Run Debunker on each hypothesis."""
        self.state.set_phase(AnalysisPhase.DEBUNKING)
        active = self.state.get_active_hypotheses()
        if not active:
            logger.info("No active hypotheses to debunk")
            return
        for h in active:
            try:
                h.transition_to(HypothesisStatus.UNDER_REVIEW)
                report = self.debunker.debunk(h, graph=self.graph, memory=self)
                if not report.survived_all:
                    self.state.record_debunked(h)
                elif report.recommendation == "proceed":
                    h.transition_to(HypothesisStatus.EXPERIMENT_SCHEDULED)
                else:
                    h.confidence *= report.overall_score
            except Exception as e:
                self.state.add_error(f"Debunking {h.id} failed: {e}")
        logger.info(f"Debunking complete: {self.state.debunked_count} killed")

    def _phase_epistemic_calibration(self) -> None:
        """Phase 7: Calibrate confidence scores."""
        self.state.set_phase(AnalysisPhase.EPISTEMIC_CALIBRATION)
        active = self.state.get_active_hypotheses()
        for h in active:
            try:
                calibrated = self.epistemic.calibrate(h)
                h.confidence = calibrated
                counters = self.epistemic.generate_counter_hypotheses(h)
                h.counter_hypotheses.extend(counters)
            except Exception as e:
                self.state.add_error(f"Calibration of {h.id} failed: {e}")

    def _phase_experimentation(self) -> None:
        """Phase 8: Plan experiments for surviving hypotheses."""
        self.state.set_phase(AnalysisPhase.EXPERIMENTATION)
        if not self.state.config.enable_dynamic_analysis:
            logger.info("Dynamic analysis disabled — skipping experimentation")
            return
        active = self.state.get_active_hypotheses()
        if not active:
            return
        try:
            plans = self.planner.prioritize(
                active, budget=self.state.config.experiment_budget
            )
            logger.info(f"Generated {len(plans)} experiment plans")
            for plan in plans:
                self.state.record_experiment()
        except Exception as e:
            self.state.add_error(f"Experimentation planning failed: {e}")

    def _phase_reporting(self) -> None:
        """Phase 9: Collect confirmed vulnerabilities."""
        self.state.set_phase(AnalysisPhase.REPORTING)
        active = self.state.get_active_hypotheses()
        for h in active:
            if h.confidence >= self.state.config.confidence_threshold:
                h.transition_to(HypothesisStatus.CONFIRMED)
                self.state.record_confirmed(h)
                self.semantic_memory.store_hypothesis(h)
        logger.info(
            f"Analysis complete: {self.state.confirmed_count} confirmed, "
            f"{self.state.debunked_count} debunked"
        )
