from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from datetime import datetime

from chimera.models.evidence import Evidence

HypothesisStatus = Literal["proposed", "testing", "confirmed", "rejected"]

class Hypothesis(BaseModel):
    id: str = Field(description="Unique hypothesis identifier")
    claim: str = Field(description="The falsifiable claim")
    
    required_conditions: List[str] = Field(default_factory=list, description="What must be true for this claim to hold")
    evidence: List[Evidence] = Field(default_factory=list, description="Observations that support the claim")
    missing_information: List[str] = Field(default_factory=list, description="What we still need to know")
    falsifiers: List[str] = Field(default_factory=list, description="What observations would prove this claim false")
    confidence: float = Field(ge=0.0, le=1.0, default=0.0, description="Current belief strength")
    status: HypothesisStatus = Field(default="proposed")
    
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def add_evidence(self, evidence: Evidence) -> "Hypothesis":
        self.evidence.append(evidence)
        self.updated_at = datetime.utcnow().isoformat()
        return self
    
    def check_completeness(self) -> float:
        if not self.required_conditions:
            return 0.0
        return min(1.0, len(self.evidence) / max(1, len(self.required_conditions)))
    
    def is_falsified(self) -> bool:
        return False
