"""Unit tests for the CausalDifferentialEngine (v2 API)."""

from __future__ import annotations

import pytest

from chimera.core.causal_differential_engine import CausalDifferentialEngine
from chimera.core.implementation_model import ImplementationModel
from chimera.core.intent_model import IntentModel
from chimera.core.memory import ChimeraMemory
from chimera.core.semantic_graph import SemanticGraph
from chimera.core.workflow_state_analyzer import StateMachineDifferential
from chimera.models.hypothesis import Hypothesis, VulnerabilityClass


def _make_diff(**overrides) -> StateMachineDifferential:
    base = dict(
        state_machine_name="entity_ownership",
        differential_type="missing_guard",
        expected="Ownership check expected on resource access",
        observed="No ownership verification found",
        severity=0.85,
        entity_ids=[],
        context={"vulnerability_class": "idor"},
        file_path="app.py",
    )
    base.update(overrides)
    return StateMachineDifferential(**base)


class TestClassification:
    def test_explicit_context_class_wins(self, graph):
        engine = CausalDifferentialEngine()
        hyps = engine.analyze(
            [_make_diff()], graph, IntentModel(), ImplementationModel()
        )
        assert len(hyps) == 1
        assert hyps[0].vulnerability_class == VulnerabilityClass.IDOR

    def test_unknown_type_falls_back_to_map(self, graph):
        engine = CausalDifferentialEngine()
        diff = _make_diff(context={}, differential_type="extra_transition")
        hyps = engine.analyze([diff], graph, IntentModel(), ImplementationModel())
        assert len(hyps) == 1
        assert hyps[0].vulnerability_class == VulnerabilityClass.WORKFLOW_BYPASS

    def test_unknown_everything_yields_no_hypothesis(self, graph):
        engine = CausalDifferentialEngine()
        diff = _make_diff(context={}, differential_type="totally_unknown_type")
        hyps = engine.analyze([diff], graph, IntentModel(), ImplementationModel())
        assert hyps == []


class TestHypothesisQuality:
    def test_causal_chain_is_complete(self, graph):
        engine = CausalDifferentialEngine()
        h = engine.analyze([_make_diff()], graph, IntentModel(), ImplementationModel())[0]
        assert len(h.causal_chain) >= 3
        assert h.causal_chain[0].startswith("Root cause:")
        assert h.causal_chain[-1].startswith("Impact:")

    def test_static_evidence_attached(self, graph):
        """Hypotheses must be born carrying evidence (chain-of-custody)."""
        engine = CausalDifferentialEngine()
        h = engine.analyze([_make_diff()], graph, IntentModel(), ImplementationModel())[0]
        assert len(h.evidence) >= 1
        assert all(ev.chain_of_custody.verify() for ev in h.evidence)

    def test_falsifiers_seeded(self, graph):
        """A hypothesis without falsifiers is unfalsifiable — engine must seed them."""
        engine = CausalDifferentialEngine()
        h = engine.analyze([_make_diff()], graph, IntentModel(), ImplementationModel())[0]
        assert len(h.falsifiers) >= 3

    def test_confidence_in_sane_range(self, graph):
        engine = CausalDifferentialEngine()
        for sev in (0.1, 0.5, 0.95):
            h = engine.analyze(
                [_make_diff(severity=sev)], graph, IntentModel(), ImplementationModel()
            )[0]
            assert 0.1 <= h.confidence <= 0.9

    def test_memory_facade_accepted(self, graph):
        mem = ChimeraMemory()
        engine = CausalDifferentialEngine(memory=mem)
        hyps = engine.analyze([_make_diff()], graph, IntentModel(), ImplementationModel())
        assert len(hyps) == 1


class TestDifferentialToHypothesisFlow:
    def test_full_pipeline_from_source(self, vulnerable_source):
        """End-to-end: parse -> intent -> impl -> differentials -> hypotheses."""
        from chimera.core.workflow_state_analyzer import WorkflowStateMachineAnalyzer
        from chimera.parsers.languages.python_parser import PythonParser

        graph = SemanticGraph()
        PythonParser().parse("app.py", vulnerable_source, graph)
        intent = IntentModel()
        intent.extract(graph)
        impl = ImplementationModel()
        impl.extract(graph)
        analyzer = WorkflowStateMachineAnalyzer()
        analyzer.extract_state_machines(graph)
        diffs = analyzer.compute_differentials(intent, impl, graph)
        assert diffs, "vulnerable source must produce differentials"

        engine = CausalDifferentialEngine(memory=ChimeraMemory())
        hyps = engine.analyze(diffs, graph, intent, impl, target_version="t1")
        classes = {h.vulnerability_class for h in hyps}
        assert VulnerabilityClass.IDOR in classes
