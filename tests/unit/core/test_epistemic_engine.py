"""Unit tests for the EpistemicEngine (v2 API)."""

from __future__ import annotations

import pytest

from chimera.core.epistemic_engine import EpistemicEngine
from chimera.models.evidence import (
    ChainOfCustody,
    Evidence,
    EvidenceSource,
    EvidenceType,
)
from chimera.models.hypothesis import Hypothesis, VulnerabilityClass


def _evidence(confidence: float = 0.9) -> Evidence:
    chain = ChainOfCustody()
    chain.add_step("test", "generate", "in", "out")
    chain.finalize()
    return Evidence(
        source=EvidenceSource.STATIC_ANALYSIS,
        evidence_type=EvidenceType.AST_NODE,
        data={"x": 1},
        chain_of_custody=chain,
        confidence=confidence,
        description="test evidence",
    )


class TestCalibration:
    def test_type_check(self):
        with pytest.raises(TypeError):
            EpistemicEngine().calibrate("not a hypothesis")

    def test_bounds_respected(self):
        eng = EpistemicEngine()
        h = Hypothesis(claim="c", confidence=0.9, differential_score=1.0)
        score = eng.calibrate(h)
        assert eng.min_confidence <= score <= eng.max_confidence

    def test_evidence_raises_confidence(self):
        eng = EpistemicEngine()
        bare = Hypothesis(claim="c", differential_score=0.5)
        with_ev = Hypothesis(claim="c", differential_score=0.5)
        with_ev.add_evidence(_evidence(0.9))
        with_ev.add_evidence(_evidence(0.85))
        assert eng.calibrate(with_ev) > eng.calibrate(bare)

    def test_adversarial_survival_raises_confidence(self):
        eng = EpistemicEngine()
        reviewed = Hypothesis(claim="c", differential_score=0.5)
        reviewed.metadata["debunker_overall_score"] = 0.9
        unreviewed = Hypothesis(claim="c", differential_score=0.5)
        assert eng.calibrate(reviewed) > eng.calibrate(unreviewed)

    def test_no_zero_evidence_death_spiral(self):
        """A strong differential + strong review must be able to pass 0.6."""
        eng = EpistemicEngine()
        h = Hypothesis(claim="c", differential_score=0.9)
        h.add_evidence(_evidence(0.9))
        h.add_evidence(_evidence(0.9))
        h.add_evidence(_evidence(0.9))
        h.metadata["debunker_overall_score"] = 0.9
        assert eng.calibrate(h) >= 0.6

    def test_weak_hypothesis_stays_below_threshold(self):
        eng = EpistemicEngine()
        h = Hypothesis(claim="c", differential_score=0.2)
        h.add_evidence(_evidence(0.4))
        assert eng.calibrate(h) < 0.6


class TestCounterHypotheses:
    def test_generates_counters(self):
        eng = EpistemicEngine()
        h = Hypothesis(
            claim="c", file_path="app.py",
            vulnerability_class=VulnerabilityClass.IDOR,
            differential_score=0.8,
        )
        counters = eng.generate_counter_hypotheses(h)
        assert len(counters) >= 2
        assert all(c.counter_hypotheses is not None for c in counters)
        assert all(c.falsifiers for c in counters)
        assert all("app.py" in c.claim for c in counters)

    def test_unknown_class_uses_fallback(self):
        eng = EpistemicEngine()
        h = Hypothesis(claim="c", file_path="f.py")
        counters = eng.generate_counter_hypotheses(h)
        assert counters

    def test_type_check(self):
        with pytest.raises(TypeError):
            EpistemicEngine().generate_counter_hypotheses(None)


class TestCalibrationLearning:
    def test_record_outcome_updates_bias(self):
        eng = EpistemicEngine()
        assert eng.calibration_bias == 0.0
        # Consistently tell the engine it was overconfident
        for i in range(10):
            eng.record_outcome(f"H{i}", predicted_confidence=0.9, was_confirmed=False)
        assert eng.calibration_bias > 0.2

    def test_record_outcome_validates_range(self):
        eng = EpistemicEngine()
        with pytest.raises(ValueError):
            eng.record_outcome("H", predicted_confidence=1.5, was_confirmed=True)

    def test_accuracy_metrics(self):
        eng = EpistemicEngine()
        eng.record_outcome("H1", 0.8, True)
        eng.record_outcome("H2", 0.4, False)
        metrics = eng.get_calibration_accuracy()
        assert metrics["sample_size"] == 2
        assert 0.0 <= metrics["brier_score"] <= 1.0

    def test_reset(self):
        eng = EpistemicEngine()
        eng.record_outcome("H1", 0.8, True)
        eng.reset_calibration()
        assert eng.calibration_bias == 0.0
        assert eng.get_calibration_accuracy()["sample_size"] == 0
