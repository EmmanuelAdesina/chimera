# chimera/core/world_model.py

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
import networkx as nx

@dataclass
class SystemObject:
    id: str
    type: str  # "endpoint", "database", "user_input", "auth_system", "file_system"
    properties: Dict[str, Any] = field(default_factory=dict)
    trust_level: float = 0.0  # 0 = untrusted (user input), 1 = trusted (kernel)

@dataclass
class TrustBoundary:
    id: str
    name: str
    from_objects: List[str]
    to_objects: List[str]
    controls: List[str]  # "waf", "auth_check", "input_validation"

@dataclass
class DataFlow:
    source: str
    sink: str
    path: List[str]
    transforms: List[str]  # "json_parse", "url_decode", "base64_decode"
    sanitizer: Optional[str] = None

class WorldModel:
    """
    The diagram's 'World Model Construction' — semantic graph of the system.
    """
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.objects: Dict[str, SystemObject] = {}
        self.boundaries: Dict[str, TrustBoundary] = {}
        self.data_flows: List[DataFlow] = []
    
    def add_object(self, obj: SystemObject):
        self.objects[obj.id] = obj
        self.graph.add_node(obj.id, **obj.properties, type=obj.type, trust=obj.trust_level)
    
    def add_trust_boundary(self, boundary: TrustBoundary):
        self.boundaries[boundary.id] = boundary
        for src in boundary.from_objects:
            for dst in boundary.to_objects:
                self.graph.add_edge(src, dst, boundary=boundary.id, controls=boundary.controls)
    
    def add_data_flow(self, flow: DataFlow):
        self.data_flows.append(flow)
        # Add edges for each transform step
        full_path = [flow.source] + flow.path + [flow.sink]
        for i in range(len(full_path) - 1):
            self.graph.add_edge(
                full_path[i], full_path[i+1],
                transforms=flow.transforms,
                sanitizer=flow.sanitizer
            )
    
    def find_unsanitized_flows(self) -> List[DataFlow]:
        """Find data flows from low-trust to high-trust without sanitizers."""
        risky = []
        for flow in self.data_flows:
            source_obj = self.objects.get(flow.source)
            sink_obj = self.objects.get(flow.sink)
            
            if source_obj and sink_obj:
                if source_obj.trust_level < 0.3 and sink_obj.trust_level > 0.7:
                    if not flow.sanitizer:
                        risky.append(flow)
        return risky
    
    def get_parser_cascade(self, flow: DataFlow) -> List[Dict]:
        """
        Extract the parser cascade for a specific data flow.
        Returns the sequence of parsers/transforms the data passes through.
        """
        cascade = []
        for transform in flow.transforms:
            cascade.append({
                "layer": transform,
                "type": "parser" if "parse" in transform else "transform"
            })
        return cascade
    
    def to_causal_engine_input(self) -> List[Dict]:
        """Convert world model to parser layer inputs for CausalEngine."""
        layers = []
        for flow in self.find_unsanitized_flows():
            cascade = self.get_parser_cascade(flow)
            if cascade:
                layers.append({
                    "flow_id": f"{flow.source}->{flow.sink}",
                    "cascade": cascade
                })
        return layers