from typing import List, Optional
from dataclasses import dataclass

from chimera.models.causal import GrammarModel, ParserLayerModel, DifferentialReport, CascadeAnalysis
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


@dataclass
class ParserLayer:
    name: str
    grammar: GrammarModel
    sanitizer: Optional[str] = None


class CausalEngine:
    """
    Analyzes parser cascades for grammar differentials.
    Produces Hypothesis objects, not just reports.
    """

    def __init__(self):
        self.differentials: List[DifferentialReport] = []

    def analyze_cascade(self, layers: List[ParserLayer], target: str = "") -> List[Hypothesis]:
        hypotheses = []
        
        for i in range(len(layers) - 1):
            current = layers[i]
            next_layer = layers[i + 1]
            
            unescaped_meta = current.grammar.safe_chars & next_layer.grammar.meta_chars
            
            if unescaped_meta and not current.sanitizer:
                diff = DifferentialReport(
                    boundary=f"{current.name} -> {next_layer.name}",
                    dangerous_chars=unescaped_meta,
                    developer_assumption=f"{current.name} output is safe for {next_layer.name}",
                    actual_risk=f"Characters {unescaped_meta} are meta in {next_layer.name}",
                    fix_recommendation=f"Insert sanitizer at boundary: escape {unescaped_meta} for {next_layer.name} grammar",
                    confidence=0.95,
                    evidence=[f"No sanitizer between {current.name} and {next_layer.name}"]
                )
                
                hypothesis = self._differential_to_hypothesis(diff, target, layers)
                hypotheses.append(hypothesis)
        
        return hypotheses

    def _differential_to_hypothesis(self, diff: DifferentialReport, target: str, 
                                      layers: List[ParserLayer]) -> Hypothesis:
        chars = ", ".join(diff.dangerous_chars)
        
        claim = (
            f"Grammar differential at {diff.boundary}: "
            f"character(s) [{chars}] are data in the upstream layer "
            f"but meta-characters in the downstream layer, "
            f"and no sanitizer translates between grammars."
        )
        
        return Hypothesis(
            id=f"HYP-{hash(diff.boundary) % 10000:04d}",
            claim=claim,
            required_conditions=[
                f"Data flows from {diff.boundary.split(' -> ')[0]} to {diff.boundary.split(' -> ')[1]}",
                f"Character(s) {diff.dangerous_chars} appear in attacker-controlled input",
                f"No sanitizer exists at the boundary",
                f"Downstream layer interprets {diff.dangerous_chars} as control characters"
            ],
            evidence=[
                Evidence(
                    source="causal_engine",
                    data=diff.model_dump(),
                    confidence=diff.confidence,
                    metadata={"boundary": diff.boundary, "target": target}
                )
            ],
            missing_information=[
                "Attacker-controlled input path to the boundary",
                "Runtime execution confirmation",
                "WAF or defense layer interference"
            ],
            falsifiers=[
                f"Input never contains {diff.dangerous_chars}",
                "A sanitizer exists but was not detected",
                "Downstream layer is not actually reached by user input",
                "The application uses parameterized queries at a higher layer"
            ],
            confidence=diff.confidence * 0.7,
            status="proposed"
        )

    def full_analysis(self, target: str, layers: List[ParserLayer]) -> CascadeAnalysis:
        diffs = self.analyze_cascade(layers, target)
        
        layer_models = [
            ParserLayerModel(name=l.name, grammar=l.grammar, sanitizer=l.sanitizer)
            for l in layers
        ]
        
        return CascadeAnalysis(
            target=target,
            layers=layer_models,
            differentials=diffs,
            epistemic_confidence=0.95 if diffs else 0.1,
            causal_narrative=""
        )
