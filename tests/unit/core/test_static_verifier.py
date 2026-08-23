"""Unit tests for the StaticVerifier — the loop-closing probe engine."""

from __future__ import annotations

from chimera.core.semantic_graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SemanticGraph,
)
from chimera.core.static_verifier import StaticVerifier
from chimera.models.hypothesis import Hypothesis, VulnerabilityClass


def _hyp(entity_ids):
    return Hypothesis(
        claim="test",
        vulnerability_class=VulnerabilityClass.IDOR,
        attack_surface=entity_ids,
        differential_score=0.8,
    )


class TestStaticVerifier:
    def test_missing_entity_weakens(self):
        verifier = StaticVerifier()
        outcome = verifier.verify(_hyp(["nope"]), SemanticGraph())
        assert outcome.verdict == "weakened"
        assert outcome.confidence_delta < 0
        assert outcome.evidence  # chain-of-custody evidence attached

    def test_guarded_callers_weaken(self):
        """All callers enforce guards -> hypothesis weakened."""
        graph = SemanticGraph()
        callee = GraphNode(node_type=NodeType.FUNCTION, name="helper", file_path="a.py")
        caller = GraphNode(
            node_type=NodeType.FUNCTION,
            name="handler",
            file_path="a.py",
            properties={"auth_checks": [{"kind": "auth_attribute"}]},
            semantic_tags={"auth_checked"},
        )
        cid = graph.add_node(callee)
        hid = graph.add_node(caller)
        graph.add_edge(GraphEdge(source_id=hid, target_id=cid, edge_type=EdgeType.CALLS))

        outcome = StaticVerifier().verify(_hyp([cid]), graph)
        assert outcome.confidence_delta < 0
        assert any("caller_guard_sweep" in p and "guarded=True" in p for p in outcome.probes)

    def test_unguarded_caller_strengthens_or_neutral(self):
        graph = SemanticGraph()
        callee = GraphNode(
            node_type=NodeType.FUNCTION, name="helper", file_path="a.py",
            properties={"comparisons": [{"left": "a", "ops": ["=="], "comparators": ["b"]}]},
        )
        caller = GraphNode(node_type=NodeType.FUNCTION, name="handler", file_path="a.py")
        cid = graph.add_node(callee)
        hid = graph.add_node(caller)
        graph.add_edge(GraphEdge(source_id=hid, target_id=cid, edge_type=EdgeType.CALLS))

        outcome = StaticVerifier().verify(_hyp([cid]), graph)
        # no guard evidence -> not weakened
        assert outcome.confidence_delta >= 0.0 - 1e-9

    def test_no_attack_surface_is_neutral(self):
        outcome = StaticVerifier().verify(_hyp([]), SemanticGraph())
        assert outcome.verdict == "neutral"
        assert outcome.confidence_delta == 0.0

    def test_evidence_has_valid_chain(self):
        graph = SemanticGraph()
        node = GraphNode(node_type=NodeType.FUNCTION, name="f", file_path="a.py")
        nid = graph.add_node(node)
        outcome = StaticVerifier().verify(_hyp([nid]), graph)
        assert outcome.evidence
        assert all(ev.chain_of_custody.verify() for ev in outcome.evidence)
