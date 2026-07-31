import pytest
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

class TestEpistemicMonitor:
    def test_rejects_low_confidence(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        hyp = Hypothesis(id='HYP-001', claim='Test', confidence=0.3)
        assert mon.interrogate(hyp) == False

    def test_accepts_strong_hypothesis(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        hyp = Hypothesis(id='HYP-002', claim='Strong', confidence=0.9, required_conditions=['c1'], evidence=[Evidence(source='test', data='x', confidence=0.9)])
        assert mon.interrogate(hyp) == True

    def test_known_bias(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        mon.register_bias('SQL injection', 0.5)
        hyp = Hypothesis(id='HYP-003', claim='SQL injection possible', confidence=0.9, required_conditions=['c1'], evidence=[Evidence(source='test', data='x', confidence=0.9)])
        assert mon.interrogate(hyp) == False
