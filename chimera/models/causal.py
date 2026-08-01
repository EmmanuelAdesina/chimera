from pydantic import BaseModel, Field
from typing import Set, Dict, Optional, List

class GrammarModel(BaseModel):
    safe_chars: Set[str] = Field(default_factory=set, description="Characters treated as literal data")
    meta_chars: Set[str] = Field(default_factory=set, description="Characters with structural/control meaning")
    escape_rules: Dict[str, str] = Field(default_factory=dict, description="How meta chars are neutralized")

class ParserLayerModel(BaseModel):
    name: str
    grammar: GrammarModel
    sanitizer: Optional[str] = Field(default=None, description="Function/rule that translates output to next layer")
    source_location: Optional[str] = None

class DifferentialReport(BaseModel):
    boundary: str
    dangerous_chars: Set[str]
    developer_assumption: str
    actual_risk: str
    fix_recommendation: str
    confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)

class CascadeAnalysis(BaseModel):
    target: str
    layers: List[ParserLayerModel]
    differentials: List[DifferentialReport]
    epistemic_confidence: float = 0.0
    causal_narrative: str = ""

class BeliefModel(BaseModel):
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)
    interrogation_passed: bool = False
