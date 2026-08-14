"""
Chimera Evidence Model — Verifiable artifacts with chain of custody.

Every claim in Chimera must be backed by Evidence. Each piece of evidence
carries a complete chain of custody tracing it back to its source (AST node,
HTTP request/response, runtime trace, etc.). Evidence is immutable once created.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
import hashlib
import json


class EvidenceType(Enum):
    """Types of evidence Chimera collects."""
    AST_NODE = "ast_node"
    CFG_PATH = "cfg_path"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    RUNTIME_TRACE = "runtime_trace"
    STATE_TRANSITION = "state_transition"
    AUTH_DECORATOR = "auth_decorator"
    DATA_FLOW = "data_flow"
    SEMANTIC_GRAPH_NODE = "semantic_graph_node"
    SEMANTIC_GRAPH_EDGE = "semantic_graph_edge"
    DIFFERENTIAL_RESULT = "differential_result"
    EXPERIMENT_RESULT = "experiment_result"
    MEMORY_RETRIEVAL = "memory_retrieval"
    CODE_SNIPPET = "code_snippet"


class EvidenceSource(Enum):
    """Origin of the evidence."""
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    LLM_INFERENCE = "llm_inference"
    DIFFERENTIAL_ENGINE = "differential_engine"
    DEBUNKER = "debunker"
    MEMORY = "memory"
    MANUAL = "manual"
    EXPERIMENT = "experiment"


@dataclass
class ChainOfCustody:
    """
    Immutable record tracing how evidence was obtained.
    Each step documents the tool/method that produced or transformed the artifact.
    """
    steps: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    fingerprint: str = ""

    def add_step(
        self,
        tool: str,
        action: str,
        input_ref: str,
        output_ref: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a custody step. This is the only mutation allowed before fingerprinting."""
        if self.fingerprint:
            raise RuntimeError(
                "Cannot modify ChainOfCustody after fingerprinting. "
                "Create a new ChainOfCustody for derived evidence."
            )
        step = {
            "step_number": len(self.steps) + 1,
            "tool": tool,
            "action": action,
            "input_ref": input_ref,
            "output_ref": output_ref,
            "parameters": parameters or {},
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.steps.append(step)

    def finalize(self) -> str:
        """Compute and set the fingerprint. No further mutations allowed."""
        canonical = json.dumps(
            {"steps": self.steps, "created_at": self.created_at.isoformat()},
            sort_keys=True,
        )
        self.fingerprint = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        return self.fingerprint

    def verify(self) -> bool:
        """Verify the chain has not been tampered with."""
        if not self.fingerprint:
            return False
        canonical = json.dumps(
            {"steps": self.steps, "created_at": self.created_at.isoformat()},
            sort_keys=True,
        )
        expected = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        return self.fingerprint == expected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": self.steps,
            "created_at": self.created_at.isoformat(),
            "fingerprint": self.fingerprint,
            "verified": self.verify(),
        }


@dataclass
class Evidence:
    """
    A single piece of verifiable evidence.

    Attributes:
        id: Unique identifier for this evidence artifact.
        source: Where this evidence originated (static analysis, experiment, etc.).
        evidence_type: The kind of evidence (AST node, HTTP response, etc.).
        data: The actual evidence payload — structure depends on evidence_type.
        chain_of_custody: Immutable provenance record.
        timestamp: When this evidence was collected.
        file_path: Source file this evidence relates to (if applicable).
        line_range: Line range in the source file (start, end).
        confidence: Confidence in this evidence's accuracy (0.0-1.0).
        metadata: Additional context about this evidence.
        description: Human-readable summary of what this evidence shows.
    """
    id: str = field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:10].upper()}")
    source: EvidenceSource = EvidenceSource.STATIC_ANALYSIS
    evidence_type: EvidenceType = EvidenceType.AST_NODE
    data: Dict[str, Any] = field(default_factory=dict)
    chain_of_custody: ChainOfCustody = field(default_factory=ChainOfCustody)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    file_path: str = ""
    line_range: tuple = (0, 0)
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""

    def __post_init__(self):
        """Auto-finalize chain of custody if it has steps but no fingerprint."""
        if self.chain_of_custody.steps and not self.chain_of_custody.fingerprint:
            self.chain_of_custody.finalize()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize evidence to dictionary."""
        return {
            "id": self.id,
            "source": self.source.value,
            "evidence_type": self.evidence_type.value,
            "data": self.data,
            "chain_of_custody": self.chain_of_custody.to_dict(),
            "timestamp": self.timestamp.isoformat(),
            "file_path": self.file_path,
            "line_range": list(self.line_range),
            "confidence": self.confidence,
            "metadata": self.metadata,
            "description": self.description,
        }

    def derive(
        self,
        tool: str,
        action: str,
        new_data: Dict[str, Any],
        new_evidence_type: Optional[EvidenceType] = None,
        new_source: Optional[EvidenceSource] = None,
        description: str = "",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> "Evidence":
        """
        Create derived evidence from this piece, extending the chain of custody.
        This is how evidence propagates through the pipeline — each transformation
        creates new evidence with an extended chain.
        """
        new_chain = ChainOfCustody()
        # Carry forward all existing custody steps
        for step in self.chain_of_custody.steps:
            new_chain.add_step(**{k: v for k, v in step.items() if k != "step_number"})
        # Add the new transformation step
        new_chain.add_step(
            tool=tool,
            action=action,
            input_ref=self.id,
            output_ref=f"EVD-{uuid.uuid4().hex[:10].upper()}",
            parameters=parameters or {},
        )
        new_chain.finalize()

        return Evidence(
            source=new_source or self.source,
            evidence_type=new_evidence_type or self.evidence_type,
            data=new_data,
            chain_of_custody=new_chain,
            file_path=self.file_path,
            line_range=self.line_range,
            confidence=self.confidence * 0.9,  # Slight decay on derivation
            metadata={**self.metadata, "derived_from": self.id},
            description=description or f"Derived from {self.id} via {tool}.{action}",
        )

    @staticmethod
    def from_ast_node(
        file_path: str,
        node_type: str,
        node_data: Dict[str, Any],
        line: int,
        end_line: int,
        description: str = "",
    ) -> "Evidence":
        """Factory: create evidence from an AST node."""
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="PythonParser",
            action="extract_ast_node",
            input_ref=f"{file_path}:{line}-{end_line}",
            output_ref=ev_id,
            parameters={"node_type": node_type},
        )
        chain.finalize()
        return Evidence(
            source=EvidenceSource.STATIC_ANALYSIS,
            evidence_type=EvidenceType.AST_NODE,
            data={**node_data, "node_type": node_type},
            chain_of_custody=chain,
            file_path=file_path,
            line_range=(line, end_line),
            confidence=1.0,
            description=description or f"AST {node_type} at {file_path}:{line}",
        )

    @staticmethod
    def from_http_exchange(
        request: Dict[str, Any],
        response: Dict[str, Any],
        description: str = "",
    ) -> "Evidence":
        """Factory: create evidence from an HTTP request/response pair."""
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="ExperimentRunner",
            action="http_exchange",
            input_ref=request.get("url", "unknown"),
            output_ref=ev_id,
            parameters={"method": request.get("method", "GET")},
        )
        chain.finalize()
        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.HTTP_RESPONSE,
            data={"request": request, "response": response},
            chain_of_custody=chain,
            confidence=1.0,
            description=description or f"HTTP {request.get('method', 'GET')} to {request.get('url', 'unknown')}",
        )
