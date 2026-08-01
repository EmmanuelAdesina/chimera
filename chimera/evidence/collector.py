# chimera/evidence/collector.py

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

class EvidenceType(Enum):
    SOURCE_CODE = "source_code"
    AST = "ast"
    RUNTIME_TRACE = "runtime_trace"
    HTTP_TRAFFIC = "http_traffic"
    INFRASTRUCTURE = "infrastructure"  # Terraform, K8s, IAM
    BINARY_METADATA = "binary_metadata"

@dataclass
class EvidenceArtifact:
    type: EvidenceType
    source: str  # file path, URL, tool name
    raw_data: Any
    parsed_data: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class EvidenceCollector:
    """
    Unified ingestion for all evidence types.
    The diagram's 'Evidence Collection Layer' — single entry point.
    """
    
    def __init__(self):
        self.artifacts: List[EvidenceArtifact] = []
    
    def collect_source(self, file_path: str, language: str) -> EvidenceArtifact:
        with open(file_path, 'r') as f:
            code = f.read()
        
        artifact = EvidenceArtifact(
            type=EvidenceType.SOURCE_CODE,
            source=file_path,
            raw_data=code,
            metadata={"language": language, "lines": len(code.splitlines())}
        )
        self.artifacts.append(artifact)
        return artifact
    
    def collect_ast(self, file_path: str, ast_data: Any) -> EvidenceArtifact:
        artifact = EvidenceArtifact(
            type=EvidenceType.AST,
            source=file_path,
            raw_data=ast_data,
            metadata={"node_count": len(str(ast_data))}  # placeholder
        )
        self.artifacts.append(artifact)
        return artifact
    
    def collect_http_traffic(self, request: Dict, response: Dict) -> EvidenceArtifact:
        artifact = EvidenceArtifact(
            type=EvidenceType.HTTP_TRAFFIC,
            source=f"{request.get('method')} {request.get('url')}",
            raw_data={"request": request, "response": response},
            metadata={"status_code": response.get("status_code")}
        )
        self.artifacts.append(artifact)
        return artifact
    
    def collect_infrastructure(self, infra_type: str, config: Dict) -> EvidenceArtifact:
        artifact = EvidenceArtifact(
            type=EvidenceType.INFRASTRUCTURE,
            source=infra_type,
            raw_data=config,
            metadata={"resource_count": len(config)}
        )
        self.artifacts.append(artifact)
        return artifact
    
    def get_by_type(self, ev_type: EvidenceType) -> List[EvidenceArtifact]:
        return [a for a in self.artifacts if a.type == ev_type]
    
    def build_world_model_inputs(self) -> Dict[str, List[Any]]:
        """Feed into World Model Construction."""
        return {
            "source_code": [a.raw_data for a in self.get_by_type(EvidenceType.SOURCE_CODE)],
            "asts": [a.raw_data for a in self.get_by_type(EvidenceType.AST)],
            "http_traffic": [a.raw_data for a in self.get_by_type(EvidenceType.HTTP_TRAFFIC)],
            "infrastructure": [a.raw_data for a in self.get_by_type(EvidenceType.INFRASTRUCTURE)],
        }