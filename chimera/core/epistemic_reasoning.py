# chimera/core/epistemic_reasoning.py

from typing import List, Dict
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

class EpistemicReasoningEngine:
    """
    The diagram's 'Epistemic Reasoning Engine' — full confidence calibration,
    counter-hypothesis generation, and contradiction search.
    """
    
    def __init__(self, confidence_threshold: float = 0.6):
        self.threshold = confidence_threshold
        self.counter_hypotheses_generated: List[Hypothesis] = []
        self.contradictions_found: List[Dict] = []
    
    def evaluate(self, hypothesis: Hypothesis) -> Dict:
        """Full epistemic evaluation of a hypothesis."""
        result = {
            "hypothesis_id": hypothesis.id,
            "original_confidence": hypothesis.confidence,
            "survives_interrogation": False,
            "counter_hypotheses": [],
            "contradictions": [],
            "calibrated_confidence": hypothesis.confidence
        }
        
        # 1. Check basic thresholds
        if hypothesis.confidence < self.threshold:
            result["survives_interrogation"] = False
            return result
        
        # 2. Generate counter-hypotheses
        counters = self._generate_counter_hypotheses(hypothesis)
        result["counter_hypotheses"] = counters
        self.counter_hypotheses_generated.extend(counters)
        
        # 3. Search for contradictions in evidence
        contradictions = self._find_contradictions(hypothesis)
        result["contradictions"] = contradictions
        self.contradictions_found.extend(contradictions)
        
        # 4. Adjust confidence based on counter-evidence
        penalty = len(contradictions) * 0.15
        result["calibrated_confidence"] = max(0.0, hypothesis.confidence - penalty)
        
        # 5. Final verdict
        result["survives_interrogation"] = result["calibrated_confidence"] >= self.threshold
        
        return result
    
    def _generate_counter_hypotheses(self, hypothesis: Hypothesis) -> List[Hypothesis]:
        """
        'What else could explain this observation?'
        """
        counters = []
        
        # Counter 1: It's not a vulnerability, it's expected behavior
        c1 = hypothesis.model_copy(deep=True)
        c1.id = f"{hypothesis.id}-C1"
        c1.claim = f"[Counter] {hypothesis.claim} is actually expected behavior for this framework version"
        c1.confidence = 0.3
        c1.status = "proposed"
        counters.append(c1)
        
        # Counter 2: A defense layer we haven't detected prevents exploitation
        c2 = hypothesis.model_copy(deep=True)
        c2.id = f"{hypothesis.id}-C2"
        c2.claim = f"[Counter] {hypothesis.claim} is mitigated by an undetected WAF or RASP"
        c2.confidence = 0.25
        c2.status = "proposed"
        counters.append(c2)
        
        # Counter 3: The data flow doesn't actually reach the sink
        c3 = hypothesis.model_copy(deep=True)
        c3.id = f"{hypothesis.id}-C3"
        c3.claim = f"[Counter] Attacker cannot influence the data flow in {hypothesis.claim}"
        c3.confidence = 0.2
        c3.status = "proposed"
        counters.append(c3)
        
        return counters
    
    def _find_contradictions(self, hypothesis: Hypothesis) -> List[Dict]:
        """Search for internal contradictions in the hypothesis."""
        contradictions = []
        
        # Check: Does evidence support all required conditions?
        for condition in hypothesis.required_conditions:
            supported = any(
                condition.lower() in str(e.data).lower() or condition.lower() in e.source.lower()
                for e in hypothesis.evidence
            )
            if not supported:
                contradictions.append({
                    "type": "unsupported_condition",
                    "condition": condition,
                    "severity": "high"
                })
        
        # Check: Are falsifiers already present in evidence?
        for falsifier in hypothesis.falsifiers:
            present = any(
                falsifier.lower() in str(e.data).lower()
                for e in hypothesis.evidence
            )
            if present:
                contradictions.append({
                    "type": "falsifier_present",
                    "falsifier": falsifier,
                    "severity": "critical"
                })
        
        return contradictions