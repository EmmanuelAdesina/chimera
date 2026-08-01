# chimera/core/intent_model.py

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

@dataclass
class ExpectedRule:
    rule: str  # "All user input is validated before SQL construction"
    evidence: List[str]  # docstrings, type hints, function names
    confidence: float  # How sure we are this is the developer's intent

class IntentModelBuilder:
    """
    The diagram's 'Intent Model' — infer what the developer THOUGHT they built.
    """
    
    def __init__(self):
        self.rules: List[ExpectedRule] = []
    
    def from_docstrings(self, docstrings: List[str]) -> List[ExpectedRule]:
        """Extract security intent from docstrings."""
        rules = []
        for doc in docstrings:
            doc_lower = doc.lower()
            if "validate" in doc_lower or "sanitize" in doc_lower:
                rules.append(ExpectedRule(
                    rule="Input validation is intended",
                    evidence=[doc],
                    confidence=0.7
                ))
            if "parameterized" in doc_lower or "prepared statement" in doc_lower:
                rules.append(ExpectedRule(
                    rule="Parameterized queries are intended",
                    evidence=[doc],
                    confidence=0.9
                ))
            if "escape" in doc_lower:
                rules.append(ExpectedRule(
                    rule="Output escaping is intended",
                    evidence=[doc],
                    confidence=0.6
                ))
        self.rules.extend(rules)
        return rules
    
    def from_function_names(self, names: List[str]) -> List[ExpectedRule]:
        """Infer intent from naming conventions."""
        rules = []
        for name in names:
            name_lower = name.lower()
            if "safe_" in name_lower or "_safe" in name_lower:
                rules.append(ExpectedRule(
                    rule=f"{name} is intended to be safe",
                    evidence=[name],
                    confidence=0.5
                ))
            if "validate" in name_lower:
                rules.append(ExpectedRule(
                    rule=f"{name} is intended to validate input",
                    evidence=[name],
                    confidence=0.8
                ))
        self.rules.extend(rules)
        return rules
    
    def from_type_annotations(self, annotations: Dict[str, str]) -> List[ExpectedRule]:
        """Infer intent from type hints."""
        rules = []
        for var, type_hint in annotations.items():
            if "HttpRequest" in type_hint or "Request" in type_hint:
                rules.append(ExpectedRule(
                    rule=f"{var} is external input and should be treated as untrusted",
                    evidence=[f"{var}: {type_hint}"],
                    confidence=0.9
                ))
        self.rules.extend(rules)
        return rules
    
    def get_all_rules(self) -> List[ExpectedRule]:
        return self.rules
    
    def check_violation(self, implementation_fact: str) -> Optional[ExpectedRule]:
        """
        Check if an implementation fact violates an expected rule.
        e.g., implementation_fact: "f-string SQL construction found"
        matches rule: "Parameterized queries are intended"
        -> VIOLATION
        """
        for rule in self.rules:
            if "parameterized" in rule.rule and "f-string" in implementation_fact:
                return rule
            if "validate" in rule.rule and "direct usage" in implementation_fact:
                return rule
        return None