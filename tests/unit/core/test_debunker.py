"""Unit tests for the Debunker — the hostile gatekeeper."""

from __future__ import annotations

from chimera.core.debunker import Debunker
from chimera.core.semantic_graph import SemanticGraph
from chimera.models.hypothesis import Hypothesis, HypothesisStatus, VulnerabilityClass


def _strong_hypothesis() -> Hypothesis:
    h = Hypothesis(
        claim=(
            "[MISSING_GUARD] In app.py: Intent expects authorization HOWEVER "
            "No authorization check found on 'delete_order'. "
            "This creates a privilege_escalation_vertical vulnerability. "
            "Causal chain: Root cause: missing_guard -> Mechanism: no auth "
            "check -> Impact: attacker can delete any order"
        ),
        confidence=0.7,
        file_path="app.py",
        vulnerability_class=VulnerabilityClass.PRIVILEGE_ESCALATION_VERTICAL,
        differential_score=0.8,
        causal_chain=[
            "Root cause: missing_guard in delete_order",
            "Mechanism: no authorization verification found on delete_order",
            "Impact: attacker can trigger missing_guard to delete orders",
        ],
        intent_model_ref="auth expected",
        implementation_model_ref="no authorization guard found on delete_order",
        attack_surface=["entity-1"],
    )
    h.add_falsifier("middleware enforces auth at runtime")
    h.add_falsifier("base class applies the check")
    h.prerequisite_conditions = ["attacker reaches endpoint", "no server-side enforcement"]
    h.counter_hypotheses.append(Hypothesis(claim="protected by gateway"))
    return h


def _weak_hypothesis() -> Hypothesis:
    # No falsifiers, no causal chain, no evidence, tautological phrasing.
    return Hypothesis(
        claim="the endpoint does not check auth so it does not check auth",
        confidence=0.5,
    )


class TestAttackVectors:
    def test_nine_vectors_run(self, graph):
        d = Debunker()
        report = d.debunk(_strong_hypothesis(), graph=graph)
        names = {r.attack_name for r in report.attack_results}
        expected = {
            "tautology_check", "assumption_audit", "counter_example_search",
            "causal_chain_break", "scope_creep", "confirmation_bias",
            "temporal_validity", "semantic_drift", "attack_surface_mismatch",
        }
        assert names == expected

    def test_strong_hypothesis_survives(self, graph):
        d = Debunker()
        report = d.debunk(_strong_hypothesis(), graph=graph)
        assert report.survived_all
        assert report.recommendation in {"proceed", "refine"}
        assert report.overall_score > 0.0

    def test_weak_hypothesis_killed(self, graph):
        d = Debunker()
        h = _weak_hypothesis()
        report = d.debunk(h, graph=graph)
        assert not report.survived_all
        assert report.recommendation == "kill"
        assert h.status == HypothesisStatus.DEBUNKED

    def test_kill_recommendation_sets_status_and_score(self, graph):
        """survived_all=False + recommendation=kill => status DEBUNKED."""
        d = Debunker()
        h = _weak_hypothesis()
        h.transition_to(HypothesisStatus.UNDER_REVIEW)
        report = d.debunk(h, graph=graph)
        assert report.recommendation == "kill"
        assert h.status == HypothesisStatus.DEBUNKED

    def test_overall_score_recorded_for_calibration(self, graph):
        d = Debunker()
        h = _strong_hypothesis()
        report = d.debunk(h, graph=graph)
        if report.survived_all:
            assert "debunker_overall_score" in h.metadata
            assert h.metadata["debunker_overall_score"] == report.overall_score

    def test_report_serializable(self, graph):
        d = Debunker()
        report = d.debunk(_strong_hypothesis(), graph=graph)
        as_dict = report.to_dict()
        assert as_dict["hypothesis_id"]
        assert len(as_dict["attack_results"]) == 9

    def test_stats_tracked(self, graph):
        d = Debunker()
        d.debunk(_strong_hypothesis(), graph=graph)
        d.debunk(_weak_hypothesis(), graph=graph)
        stats = d.get_stats()
        assert stats["total_debunked"] >= 1
        assert stats["total_survived"] >= 1
