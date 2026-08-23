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
       (every hypothesis carries static evidence + falsifiers from birth)
    6. DEBUNKING — Debunker runs 9 attack vectors on each hypothesis
    7. EPISTEMIC_CALIBRATION — EpistemicEngine calibrates confidence
       (evidence + differential + adversarial-survival signals)
    8. EXPERIMENTATION — ExecutionPlanner designs experiments AND the
       StaticVerifier executes inter-procedural falsification probes,
       closing the loop for static runs. Dynamic swarm dispatch happens
       only when explicitly enabled.
    9. RECALIBRATION — Post-experiment belief update
    10. REPORTING — Collect results

CRITICAL: The orchestrator must run without crashing.
Every phase has error handling and graceful degradation.
"""

from __future__ import annotations
import os
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
from chimera.core.static_verifier import StaticVerifier
from chimera.core.memory import ChimeraMemory
from chimera.models.hypothesis import Hypothesis, HypothesisStatus
from chimera.parsers.errors import ParseError

logger = logging.getLogger(__name__)

# Map file extensions to parser identifiers for discovery / dispatch.
_GRAPHQL_EXTENSIONS = {".graphql", ".gql"}
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs"}
_SQL_EXTENSIONS = {".sql"}
_PYTHON_EXTENSIONS = {".py", ".pyi"}


class ChimeraOrchestrator:
    """
    Main orchestrator for Chimera analysis.

    Coordinates all modules through the analysis loop.
    Must run without crashing — every phase has error handling.
    """

    def __init__(
        self,
        config: Optional[AnalysisConfig] = None,
        memory: Optional[ChimeraMemory] = None,
    ) -> None:
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
        self.planner = ExecutionPlanner(base_url=self.state.config.base_url)
        self.verifier = StaticVerifier()
        # Unified memory facade — the moat. The causal engine and debunker
        # speak to this object, not to the orchestrator.
        self.memory = memory or ChimeraMemory()
        self._graphql_schemas: Dict[str, str] = {}
        self._python_sources: Dict[str, str] = {}
        self._js_findings: List[Any] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        """Run the full Chimera analysis loop. Returns summary."""
        try:
            self._run_loop()
        except Exception as e:
            logger.error(f"Orchestrator error: {e}", exc_info=True)
            self.state.add_error(f"Orchestrator-level failure: {type(e).__name__}: {e}")
        self.state.set_phase(AnalysisPhase.COMPLETE)
        summary = self.state.summary()
        # Flagged tier: findings that survived the loop but did not reach the
        # confirmation threshold — visible to analysts, honest about certainty.
        threshold = self.state.config.confidence_threshold
        summary["flagged_findings"] = [
            {
                "id": h.id,
                "vulnerability_id": h.vulnerability_id,
                "vulnerability_class": (
                    h.vulnerability_class.value if h.vulnerability_class else None
                ),
                "confidence": round(h.confidence, 4),
                "severity": h.severity.value,
                "status": h.status.value,
                "file_path": h.file_path,
                "summary": h.summary(),
            }
            for h in self.state.get_active_hypotheses()
            if 0.0 < h.confidence < threshold
        ]
        return summary

    def run(self, target_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Backward-compatible alias: set the target path and run ``analyze()``.

        ``ChimeraOrchestrator(cfg).run("path")`` and
        ``ChimeraOrchestrator(AnalysisConfig(target_path="path")).analyze()``
        are equivalent.
        """
        if target_path:
            self.state.config.target_path = target_path
        return self.analyze()

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

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
        self._phase_recalibration()
        self._phase_reporting()

    def _phase_parsing(self) -> None:
        """Phase 1: Parse target files and build the SemanticGraph."""
        self.state.set_phase(AnalysisPhase.PARSING)
        target = self.state.config.target_path
        if not target or not os.path.exists(target):
            self.state.add_warning(f"Target path not found: {target}")
            return

        self.memory.initialize()
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
            except ParseError as e:
                self.state.record_parse_error(fpath, str(e))
            except Exception as e:
                self.state.record_parse_error(fpath, f"{type(e).__name__}: {e}")

    def _discover_files(self, directory: Path) -> List[str]:
        """Discover parseable files in a directory (full parser cascade)."""
        extensions = (
            _PYTHON_EXTENSIONS | _SQL_EXTENSIONS
            | _GRAPHQL_EXTENSIONS | _JS_EXTENSIONS
        )
        files = []
        for root, _, filenames in os.walk(directory):
            for fname in sorted(filenames):
                if Path(fname).suffix.lower() in extensions:
                    files.append(str(Path(root) / fname))
        return files[:500]  # Safety cap

    def _parse_file(self, file_path: str) -> None:
        """Parse a single file using the appropriate parser."""
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            source = f.read()
        if not source.strip():
            return

        suffix = Path(file_path).suffix.lower()

        if suffix in _PYTHON_EXTENSIONS:
            from chimera.parsers.languages.python_parser import PythonParser
            parser = PythonParser()
            parser.parse(file_path, source, self.graph)
            self._python_sources[file_path] = source
        elif suffix in _SQL_EXTENSIONS:
            from chimera.parsers.languages.sql_parser import SQLParser
            parser = SQLParser()
            parser.parse(file_path, source, self.graph)
        elif suffix in _GRAPHQL_EXTENSIONS:
            # Schema is parsed against Python resolvers in hypothesis phase.
            self._graphql_schemas[file_path] = source
        elif suffix in _JS_EXTENSIONS:
            self._parse_javascript(file_path, source)

    def _parse_javascript(self, file_path: str, source: str) -> None:
        """Run the async-state JS analyzer; findings become hypotheses later."""
        from chimera.parsers.javascript_parser import AsyncJavaScriptAnalyzer

        analyzer = AsyncJavaScriptAnalyzer()
        try:
            findings = analyzer.analyze_source(source, file_path)
            for finding in findings:
                self._js_findings.append(finding)
        except Exception as e:
            self.state.add_warning(f"JS analysis skipped for {file_path}: {e}")

    def _phase_intent_extraction(self) -> None:
        """Phase 2: Extract expected semantics."""
        self.state.set_phase(AnalysisPhase.INTENT_EXTRACTION)
        try:
            expectations = self.intent_model.extract(self.graph)
            logger.info(f"Extracted {len(expectations)} intent expectations")
        except Exception as e:
            self.state.add_error(f"Intent extraction failed: {type(e).__name__}: {e}")

    def _phase_implementation_extraction(self) -> None:
        """Phase 3: Extract observed semantics."""
        self.state.set_phase(AnalysisPhase.IMPLEMENTATION_EXTRACTION)
        try:
            observations = self.impl_model.extract(self.graph)
            logger.info(f"Extracted {len(observations)} implementation observations")
        except Exception as e:
            self.state.add_error(f"Implementation extraction failed: {type(e).__name__}: {e}")

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
            self.state.add_error(f"Differential analysis failed: {type(e).__name__}: {e}")
            self._differentials = []

    def _phase_hypothesis_generation(self) -> None:
        """Phase 5: Generate hypotheses from differentials + parser cascades."""
        self.state.set_phase(AnalysisPhase.HYPOTHESIS_GENERATION)
        differentials = getattr(self, "_differentials", [])
        try:
            self.differential_engine = CausalDifferentialEngine(memory=self.memory)
            hypotheses = self.differential_engine.analyze(
                differentials, self.graph, self.intent_model, self.impl_model,
                target_version=self.state.config.target_version,
            )
            # GraphQL intent-vs-implementation cascade
            hypotheses.extend(self._generate_graphql_hypotheses())
            # JS async-state cascade
            hypotheses.extend(self._generate_js_hypotheses())

            # Honor the configured hypothesis cap (highest-confidence first)
            hypotheses.sort(key=lambda h: h.confidence, reverse=True)
            hypotheses = hypotheses[: self.state.config.max_hypotheses]

            for h in hypotheses:
                h.target_version = self.state.config.target_version
                # Counter-hypotheses are born WITH the hypothesis — the
                # Debunker's confirmation-bias vector expects them to exist
                # before hostile review, not after.
                try:
                    h.counter_hypotheses.extend(
                        self.epistemic.generate_counter_hypotheses(h)
                    )
                except Exception as e:
                    self.state.add_warning(
                        f"Counter-hypothesis generation failed for {h.id}: {e}"
                    )
                self.state.add_hypothesis(h)
            # Memory-moat metric: non-novel hypotheses were seen before.
            self.state.memory_hits = sum(1 for h in hypotheses if not h.is_novel)
            logger.info(f"Generated {len(hypotheses)} hypotheses")
        except Exception as e:
            self.state.add_error(f"Hypothesis generation failed: {type(e).__name__}: {e}")

    def _generate_graphql_hypotheses(self) -> List[Hypothesis]:
        """
        Run the GraphQL intent-vs-implementation cascade when the target
        contains both a schema (.graphql/.gql) and Python resolvers.
        """
        if not self._graphql_schemas or not self._python_sources:
            return []
        from chimera.parsers.graphql_parser import GraphQLCausalParser
        from chimera.models.hypothesis import VulnerabilityClass

        parser = GraphQLCausalParser()
        hypotheses: List[Hypothesis] = []
        for schema_path, schema_src in self._graphql_schemas.items():
            for py_path, py_src in self._python_sources.items():
                try:
                    contradictions = parser.analyze_python_resolvers(schema_src, py_src)
                except Exception as e:
                    self.state.add_warning(
                        f"GraphQL analysis failed ({schema_path} x {py_path}): {e}"
                    )
                    continue
                for ev in contradictions:
                    h = Hypothesis(
                        claim=(
                            f"[INTENT_CONTRADICTION] {ev.description} "
                            f"This creates a privilege_escalation_vertical vulnerability."
                        ),
                        confidence=ev.confidence,
                        file_path=py_path,
                        vulnerability_class=VulnerabilityClass.PRIVILEGE_ESCALATION_VERTICAL,
                        differential_score=0.8,
                        causal_chain=[
                            f"Root cause: declared GraphQL security directive absent from resolver ({ev.metadata.get('field', '?')})",
                            f"Mechanism: {ev.description}",
                            "Impact: Attacker can invoke the field without the declared authorization",
                        ],
                    )
                    h.add_evidence(ev)
                    h.add_falsifier(
                        "The resolver is wrapped by schema-level middleware that "
                        "enforces the directive at runtime"
                    )
                    h.add_falsifier(
                        "The directive is enforced by a gateway/proxy outside the analyzed code"
                    )
                    h.severity = h.severity.CRITICAL
                    hypotheses.append(h)
        return hypotheses

    def _generate_js_hypotheses(self) -> List[Hypothesis]:
        """Convert JS async-state findings into race-condition hypotheses."""
        if not self._js_findings:
            return []
        from chimera.models.hypothesis import VulnerabilityClass

        hypotheses: List[Hypothesis] = []
        for finding in self._js_findings:
            kind = getattr(finding, "kind", "async_state")
            desc = getattr(finding, "description", "")
            file_path = getattr(finding, "metadata", {}).get("file", "")
            h = Hypothesis(
                claim=(
                    f"[{kind}] {desc} This creates a race_condition vulnerability "
                    f"across an async boundary."
                ),
                confidence=float(getattr(finding, "confidence", 0.5)),
                file_path=file_path,
                vulnerability_class=VulnerabilityClass.RACE_CONDITION,
                differential_score=0.6,
                causal_chain=[
                    f"Root cause: {kind} at {file_path}",
                    f"Mechanism: {desc}",
                    "Impact: Concurrent requests can interleave around the await boundary",
                ],
            )
            h.add_falsifier(
                "The mutation is idempotent or serialized by an external lock/queue"
            )
            hypotheses.append(h)
        return hypotheses

    def _phase_debunking(self) -> None:
        """Phase 6: Run Debunker on each hypothesis."""
        self.state.set_phase(AnalysisPhase.DEBUNKING)
        active = self.state.get_active_hypotheses()
        if not active:
            logger.info("No active hypotheses to debunk")
            return
        for h in active:
            try:
                if h.status == HypothesisStatus.GENERATED:
                    h.transition_to(HypothesisStatus.UNDER_REVIEW)
                report = self.debunker.debunk(h, graph=self.graph, memory=self.memory)
                if not report.survived_all:
                    self.state.record_debunked(h)
                elif report.recommendation == "proceed":
                    if h.status == HypothesisStatus.UNDER_REVIEW:
                        h.transition_to(HypothesisStatus.EXPERIMENT_SCHEDULED)
                else:
                    # "refine" — discount confidence by the review score
                    h.confidence = max(0.05, h.confidence * report.overall_score)
            except Exception as e:
                # Guard against debunker internal failures skewing counts
                self.state.add_error(f"Debunking {h.id} failed: {type(e).__name__}: {e}")
        logger.info(f"Debunking complete: {self.state.debunked_count} killed")

    def _phase_epistemic_calibration(self) -> None:
        """Phase 7: Calibrate confidence scores."""
        self.state.set_phase(AnalysisPhase.EPISTEMIC_CALIBRATION)
        for h in self.state.get_active_hypotheses():
            self._calibrate(h, generate_counters=True)

    def _calibrate(self, h: Hypothesis, generate_counters: bool = False) -> None:
        """Calibrate one hypothesis (used both pre- and post-experimentation)."""
        try:
            h.confidence = self.epistemic.calibrate(h)
            # Counter-hypotheses are generated up front (phase 5) so the
            # Debunker can see them; only backfill here if somehow absent.
            if generate_counters and not h.counter_hypotheses:
                counters = self.epistemic.generate_counter_hypotheses(h)
                h.counter_hypotheses.extend(counters)
        except Exception as e:
            self.state.add_error(f"Calibration of {h.id} failed: {type(e).__name__}: {e}")

    def _phase_experimentation(self) -> None:
        """Phase 8: Close the loop — plan experiments and run static probes."""
        self.state.set_phase(AnalysisPhase.EXPERIMENTATION)
        active = self.state.get_active_hypotheses()
        if not active:
            return

        # 8a: Plan dynamic experiments (advisory when dynamic analysis is off)
        try:
            plans = self.planner.prioritize(
                active, budget=self.state.config.experiment_budget
            )
            self._experiment_plans = plans
            logger.info(f"Generated {len(plans)} experiment plans")
        except Exception as e:
            self.state.add_error(f"Experiment planning failed: {type(e).__name__}: {e}")
            plans = []
            self._experiment_plans = []

        if not self.state.config.enable_dynamic_analysis:
            logger.info(
                "Dynamic analysis disabled — experiment plans are advisory. "
                "Running static verification probes instead."
            )
        else:
            self.state.add_warning(
                "Dynamic analysis requested: plan execution against a live "
                "target requires a swarm dispatch harness (see "
                "chimera.execution.swarm_bootstrap). Plans were generated "
                "but not executed by the orchestrator."
            )

        # 8b: Static verification probes — this is what closes the loop for
        # static runs. Every surviving hypothesis gets re-interrogated
        # against the full graph (caller sweeps, container protection,
        # sink reachability).
        planned_ids = {p.get("hypothesis_id") for p in plans}
        for h in active:
            if planned_ids and h.id not in planned_ids:
                continue  # outside experiment budget
            try:
                outcome = self.verifier.verify(
                    h, self.graph, self.intent_model, self.impl_model
                )
            except Exception as e:
                self.state.add_error(f"Verification of {h.id} failed: {type(e).__name__}: {e}")
                continue

            for ev in outcome.evidence:
                h.add_evidence(ev)
            h.add_experiment_result(outcome.to_dict())
            self.state.record_experiment()

            if outcome.verdict == "weakened":
                h.confidence = max(0.05, h.confidence + outcome.confidence_delta)
                if h.confidence < 0.2:
                    # Static evidence is strongly against this claim — reject it.
                    try:
                        self._force_reject(h, outcome.rationale)
                    except Exception as e:
                        self.state.add_warning(f"Could not reject {h.id}: {e}")
            elif outcome.verdict == "strengthened":
                h.confidence = min(0.95, h.confidence + outcome.confidence_delta)

    def _force_reject(self, h: Hypothesis, rationale: str) -> None:
        """Move a hypothesis to REJECTED regardless of current active status."""
        h.metadata["rejection_rationale"] = rationale
        # Walk the status machine to a legal terminal state.
        walk = {
            HypothesisStatus.UNDER_REVIEW: HypothesisStatus.EXPERIMENT_SCHEDULED,
            HypothesisStatus.EXPERIMENT_SCHEDULED: HypothesisStatus.EXPERIMENT_RUNNING,
            HypothesisStatus.EXPERIMENT_RUNNING: HypothesisStatus.REJECTED,
        }
        while h.status in walk:
            h.transition_to(walk[h.status])
        if h.status != HypothesisStatus.REJECTED:
            # GENERATED or otherwise — park it as rejected directly.
            h.status = HypothesisStatus.REJECTED
        self.state.record_rejected(h)

    def _phase_recalibration(self) -> None:
        """Phase 9: Post-experiment belief update.

        Verification attached fresh EXPERIMENT_RESULT evidence — re-run
        calibration so belief reflects all collected evidence.
        """
        active = self.state.get_active_hypotheses()
        if not active:
            return
        for h in active:
            if h.experiment_results:  # only re-calibrate when new data arrived
                self._calibrate(h)

    def _phase_reporting(self) -> None:
        """Phase 10: Collect confirmed vulnerabilities."""
        self.state.set_phase(AnalysisPhase.REPORTING)
        active = self.state.get_active_hypotheses()
        for h in active:
            if h.confidence >= self.state.config.confidence_threshold:
                try:
                    self._force_confirm(h)
                    self.state.record_confirmed(h)
                    self.memory.store_hypothesis(h)
                except Exception as e:
                    self.state.add_warning(f"Could not confirm {h.id}: {e}")
        logger.info(
            f"Analysis complete: {self.state.confirmed_count} confirmed, "
            f"{self.state.debunked_count} debunked"
        )

    def _force_confirm(self, h: Hypothesis) -> None:
        """Move a hypothesis to CONFIRMED regardless of current active status."""
        walk = {
            HypothesisStatus.UNDER_REVIEW: HypothesisStatus.EXPERIMENT_SCHEDULED,
            HypothesisStatus.EXPERIMENT_SCHEDULED: HypothesisStatus.EXPERIMENT_RUNNING,
            HypothesisStatus.EXPERIMENT_RUNNING: HypothesisStatus.CONFIRMED,
        }
        while h.status in walk:
            h.transition_to(walk[h.status])
        if h.status != HypothesisStatus.CONFIRMED:
            h.status = HypothesisStatus.CONFIRMED
