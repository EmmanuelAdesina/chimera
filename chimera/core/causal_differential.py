# chimera/core/causal_differential.py

from typing import List, Dict, Optional
from dataclasses import dataclass

from chimera.core.intent_model import IntentModelBuilder, ExpectedRule
from chimera.core.implementation_model import ImplementationModelBuilder, ActualBehavior
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

@dataclass
class DifferentialFinding:
    intent_rule: ExpectedRule
    actual_behavior: ActualBehavior
    violation_type: str  # "missing_sanitizer", "wrong_parser", "bypassed_control"
    explanation: str

class CausalDifferentialEngine:
    """
    The diagram's 'Causal Differential Engine' — compare Intent vs. Reality.
    """
    
    def __init__(self, intent_model: IntentModelBuilder, impl_model: ImplementationModelBuilder):
        self.intent = intent_model
        self.impl = impl_model
    
    def find_differentials(self) -> List[DifferentialFinding]:
        """Find all places where implementation violates intent."""
        findings = []
        
        for behavior in self.impl.get_all_behaviors():
            # Check if this behavior violates any intent rule
            violation = self.intent.check_violation(behavior.behavior)
            
            if violation:
                finding = DifferentialFinding(
                    intent_rule=violation,
                    actual_behavior=behavior,
                    violation_type=self._classify_violation(violation, behavior),
                    explanation=(
                        f"Developer intended: '{violation.rule}' "
                        f"but implementation shows: '{behavior.behavior}' "
                        f"at {behavior.location}"
                    )
                )
                findings.append(finding)
        
        return findings
    
    def _classify_violation(self, rule: ExpectedRule, behavior: ActualBehavior) -> str:
        if "parameterized" in rule.rule and "f-string" in behavior.behavior:
            return "missing_sanitizer"
        if "validate" in rule.rule and "direct" in behavior.behavior:
            return "bypassed_control"
        if "safe" in rule.rule and ("system" in behavior.sinks or "shell" in behavior.sinks):
            return "wrong_parser"
        return "general_violation"
    
    def to_hypotheses(self, findings: List[DifferentialFinding]) -> List[Hypothesis]:
        """Convert differentials to ranked hypotheses."""
        hypotheses = []
        
        for finding in findings:
            hyp = Hypothesis(
                id=f"HYP-DIFF-{hash(finding.explanation) % 10000:04d}",
                claim=finding.explanation,
                required_conditions=[
                    f"Intent documented: {finding.intent_rule.rule}",
                    f"Implementation found: {finding.actual_behavior.behavior}",
                    f"Location reachable: {finding.actual_behavior.location}",
                    f"Attacker can influence: {finding.actual_behavior.data_flow[0] if finding.actual_behavior.data_flow else 'input'}"
                ],
                evidence=[
                    Evidence(
                        source="causal_differential_engine",
                        data=finding.violation_type,
                        confidence=finding.intent_rule.confidence
                    )
                ],
                missing_information=[
                    "Runtime confirmation of exploitability",
                    "WAF or defense layer presence",
                    "Authentication requirements at entry point"
                ],
                falsifiers=[
                    "The intent rule was misinterpreted",
                    "A sanitizer exists in a parent function not analyzed",
                    "The sink is not actually reachable by attackers"
                ],
                confidence=finding.intent_rule.confidence * 0.8,
                status="proposed"
            )
            hypotheses.append(hyp)
        
        # Rank by confidence (information gain proxy)
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses