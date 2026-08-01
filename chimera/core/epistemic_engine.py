from typing import List, Dict, Optional
from datetime import datetime

from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


class EpistemicMonitor:
    """
    Interrogates Hypotheses before they become beliefs.
    """

    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        self.known_biases: Dict[str, float] = {}
        self.interrogation_history: List[Dict] = []

    def interrogate(self, hypothesis: Hypothesis) -> bool:
        failures = []
        
        if hypothesis.confidence < self.confidence_threshold:
            failures.append(f"Confidence {hypothesis.confidence} below threshold {self.confidence_threshold}")
        
        if not hypothesis.evidence:
            failures.append("Zero evidence provided")
        
        evidence_coverage = hypothesis.check_completeness()
        if evidence_coverage < 0.5:
            failures.append(f"Evidence coverage only {evidence_coverage:.2f}")
        
        for bias, failure_rate in self.known_biases.items():
            if bias.lower() in hypothesis.claim.lower():
                adjusted = hypothesis.confidence * (1 - failure_rate)
                if adjusted < self.confidence_threshold:
                    failures.append(f"Known bias '{bias}' reduces effective confidence to {adjusted:.2f}")
        
        critical_missing = [m for m in hypothesis.missing_information 
                           if "runtime" in m.lower() or "execution" in m.lower()]
        if len(critical_missing) > 2:
            failures.append(f"Too much missing runtime information: {len(critical_missing)} items")
        
        result = len(failures) == 0
        
        self.interrogation_history.append({
            "hypothesis_id": hypothesis.id,
            "timestamp": datetime.utcnow().isoformat(),
            "survived": result,
            "failures": failures,
            "original_confidence": hypothesis.confidence
        })
        
        return result

    def calibrate(self, hypothesis: Hypothesis, actual_outcome: str):
        was_correct = actual_outcome == "confirmed"
        if not was_correct:
            for condition in hypothesis.required_conditions:
                pass

    def register_bias(self, assumption_pattern: str, historical_failure_rate: float):
        self.known_biases[assumption_pattern] = historical_failure_rate

    def calibration_report(self) -> Dict:
        if not self.interrogation_history:
            return {"status": "no_interrogations"}
        
        total = len(self.interrogation_history)
        passed = sum(1 for h in self.interrogation_history if h["survived"])
        
        return {
            "total_interrogated": total,
            "survived": passed,
            "rejected": total - passed,
            "survival_rate": passed / total if total > 0 else 0,
            "known_biases": len(self.known_biases)
        }
