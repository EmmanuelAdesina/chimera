"""The 10-point critical evaluation battery, as a permanent regression gate.

Mirrors the independent critical evaluation harness. Every item was a FAIL
before the v2.1 remediation; all must stay green.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from chimera.core.orchestrator import ChimeraOrchestrator
from chimera.core.world_state import AnalysisConfig


def test_1_orchestrator_result_structure(vuln_orders_path):
    r = ChimeraOrchestrator(AnalysisConfig(target_path=vuln_orders_path)).analyze()
    assert isinstance(r["errors"], list)
    assert isinstance(r["hypotheses"], list)
    assert isinstance(r["confirmed_vulnerabilities"], list)
    assert isinstance(r["flagged_findings"], list)
    assert r["phase"] == "complete"


def test_2_python_parser_contract(graph):
    from chimera.parsers.languages.python_parser import PythonParser
    from chimera.parsers.errors import ParseError

    p = PythonParser()
    assert p.name == "python_ast"
    assert p.parse("t.py", "def f(a):\n    return a\n", graph)
    with pytest.raises(TypeError):
        p.parse("b.py", "x = 1\n", {"not": "a graph"})
    with pytest.raises(ParseError):
        p.parse("b.py", "def (:\n", None)


def test_3_sql_parser_none_graph():
    from chimera.parsers.languages.sql_parser import SQLParser

    p = SQLParser()
    assert p.parse("s.sql", "CREATE TABLE t (id INTEGER PRIMARY KEY);", None)
    assert p.graph.nodes
    assert p.parse("s.sql", None, None) == []


def test_4_memory_system_api():
    from chimera.core.memory import ChimeraMemory
    from chimera.models.hypothesis import Hypothesis

    mem = ChimeraMemory()
    mem.initialize()
    h = Hypothesis(claim="roundtrip", confidence=0.8)
    mem.store_hypothesis(h)
    assert mem.get_hypothesis(h.id)["claim"] == "roundtrip"
    assert mem.structured is not None and mem.semantic is not None
    assert isinstance(mem.recall_similar("roundtrip"), list)
    assert "structured" in mem.stats() and "semantic" in mem.stats()


def test_5_debunker_validation():
    from chimera.core.debunker import Debunker
    from chimera.models.hypothesis import Hypothesis, HypothesisStatus

    weak = Hypothesis(claim="no falsifiers tautology", confidence=0.5)
    report = Debunker().debunk(weak)
    assert not report.survived_all
    assert report.recommendation == "kill"
    assert weak.status == HypothesisStatus.DEBUNKED
    assert report.to_dict()["attack_results"]


def test_6_causal_engine_quality(graph):
    from chimera.core.causal_differential_engine import CausalDifferentialEngine
    from chimera.core.implementation_model import ImplementationModel
    from chimera.core.intent_model import IntentModel
    from chimera.core.workflow_state_analyzer import StateMachineDifferential

    diff = StateMachineDifferential(
        state_machine_name="e", differential_type="missing_guard",
        expected="ownership check", observed="none", severity=0.85,
        entity_ids=[], context={"vulnerability_class": "idor"}, file_path="a.py",
    )
    h = CausalDifferentialEngine().analyze(
        [diff], graph, IntentModel(), ImplementationModel()
    )[0]
    assert h.vulnerability_class.value == "idor"
    assert len(h.causal_chain) >= 3
    assert h.falsifiers
    assert len(h.evidence) >= 1


def test_7_swarm_dispatch():
    from chimera.execution.swarm_coordinator import SwarmCoordinator, SwarmTask

    async def run():
        coord = SwarmCoordinator()

        async def job(payload):
            return {"n": payload["n"]}

        coord.register_agent_capability("x", job)
        results = await coord.dispatch_swarm(
            [SwarmTask(capability="x", payload={"n": i}) for i in range(10)]
        )
        await coord.stop()
        return results

    results = asyncio.run(run())
    assert all(r.status.value == "success" for r in results)


def test_8_swarm_stress_500():
    from chimera.execution.swarm_coordinator import SwarmCoordinator, SwarmTask

    async def run():
        coord = SwarmCoordinator(max_concurrency=256)

        async def job(payload):
            await asyncio.sleep(0.0002)
            return 1

        coord.register_agent_capability("x", job)
        start = time.perf_counter()
        results = await coord.dispatch_swarm(
            [SwarmTask(capability="x", payload={}) for _ in range(500)]
        )
        elapsed = time.perf_counter() - start
        await coord.stop()
        return results, elapsed

    results, elapsed = asyncio.run(run())
    assert len(results) == 500
    assert all(r.status.value == "success" for r in results)
    assert elapsed < 5.0  # serial would be >> 100x this; generous CI bound


def test_9_edge_cases(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n")
    r = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
    assert r["phase"] == "complete"
    assert r["parse_errors"] == 1

    r2 = ChimeraOrchestrator(AnalysisConfig(target_path="/does/not/exist")).analyze()
    assert r2["phase"] == "complete"
    assert r2["warning_count"] >= 1


def test_10_complex_target_analysis(vuln_orders_path, safe_orders_path, vuln_app_path):
    vuln = ChimeraOrchestrator(AnalysisConfig(target_path=vuln_orders_path)).analyze()
    safe = ChimeraOrchestrator(AnalysisConfig(target_path=safe_orders_path)).analyze()
    legacy = ChimeraOrchestrator(AnalysisConfig(target_path=vuln_app_path)).analyze()

    assert vuln["total_hypotheses"] >= 8
    assert vuln["confirmed"] >= 5
    assert safe["confirmed"] == 0
    assert legacy["confirmed"] >= 1
