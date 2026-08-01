from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class Evidence(BaseModel):
    source: str = Field(description="Where this evidence came from: code, runtime, tool, llm")
    data: Any = Field(description="The actual evidence payload")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0, description="How much we trust this evidence")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Line numbers, file paths, request IDs, etc.")
