"""
Chimera Semantic Graph — Dynamic knowledge graph of the target system.

The Semantic Graph is the backbone of Chimera's reasoning. It represents the
target system as a directed, typed graph where:
    - Nodes represent code entities (functions, classes, endpoints, variables,
      database models, state variables, auth decorators, etc.)
    - Edges represent relationships (calls, data flows, authorization dependencies,
      state transitions, inheritance, etc.)

This graph is built incrementally by the parsers and enriched by the
IntentModel and ImplementationModel. The Causal Differential Engine
operates ON this graph, finding contradictions between expected and
observed edges.

Node Types:
    FUNCTION, CLASS, ENDPOINT, VARIABLE, MODEL, DECORATOR, MIDDLEWARE,
    STATE_VARIABLE, TRANSITION, GUARD, DATABASE_TABLE, ROUTE

Edge Types:
    CALLS, CONTAINS, INHERITS, DECORATES, AUTHORIZES, FLOWS_TO,
    TRANSITIONS, GUARDS, READS, WRITES, IMPORTS, DEPENDS_ON
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid


class NodeType(Enum):
    """Types of nodes in the semantic graph."""
    FUNCTION = "function"
    CLASS = "class"
    ENDPOINT = "endpoint"
    VARIABLE = "variable"
    MODEL = "model"
    DECORATOR = "decorator"
    MIDDLEWARE = "middleware"
    STATE_VARIABLE = "state_variable"
    TRANSITION = "transition"
    GUARD = "guard"
    DATABASE_TABLE = "database_table"
    ROUTE = "route"
    FILE = "file"
    MODULE = "module"


class EdgeType(Enum):
    """Types of edges in the semantic graph."""
    CALLS = "calls"
    CONTAINS = "contains"
    INHERITS = "inherits"
    DECORATES = "decorates"
    AUTHORIZES = "authorizes"
    FLOWS_TO = "flows_to"
    TRANSITIONS = "transitions"
    GUARDS = "guards"
    READS = "reads"
    WRITES = "writes"
    IMPORTS = "imports"
    DEPENDS_ON = "depends_on"
    IMPLEMENTS = "implements"


@dataclass
class GraphNode:
    """A node in the semantic graph."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    node_type: NodeType = NodeType.FUNCTION
    name: str = ""
    file_path: str = ""
    line_range: Tuple[int, int] = (0, 0)
    properties: Dict[str, Any] = field(default_factory=dict)
    semantic_tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "name": self.name,
            "file_path": self.file_path,
            "line_range": list(self.line_range),
            "properties": self.properties,
            "semantic_tags": list(self.semantic_tags),
        }


@dataclass
class GraphEdge:
    """A directed, typed edge in the semantic graph."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.CALLS
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    semantic_tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "properties": self.properties,
            "weight": self.weight,
            "semantic_tags": list(self.semantic_tags),
        }


class SemanticGraph:
    """
    Dynamic semantic graph of the target system.

    This is the central data structure that all Chimera components operate on.
    It is built incrementally by parsers, enriched by models, and queried
    by the differential engine to find contradictions.

    The graph supports typed queries that are critical for the Causal
    Differential Engine: finding all authorization edges, all data flow
    paths, all state transitions, etc.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self._adjacency: Dict[str, List[str]] = {}
        self._reverse_adjacency: Dict[str, List[str]] = {}
        self._type_index: Dict[NodeType, Set[str]] = {}
        self._edge_type_index: Dict[EdgeType, Set[str]] = {}

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def add_node(self, node: GraphNode) -> str:
        """Add a node to the graph. Returns the node ID."""
        if node.id in self.nodes:
            # Merge properties on duplicate
            existing = self.nodes[node.id]
            existing.properties.update(node.properties)
            existing.semantic_tags.update(node.semantic_tags)
            return node.id

        self.nodes[node.id] = node
        self._adjacency.setdefault(node.id, [])
        self._reverse_adjacency.setdefault(node.id, [])
        self._type_index.setdefault(node.node_type, set()).add(node.id)
        return node.id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node by ID. Returns None if not found."""
        return self.nodes.get(node_id)

    def find_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        """Get all nodes of a given type."""
        ids = self._type_index.get(node_type, set())
        return [self.nodes[nid] for nid in ids if nid in self.nodes]

    def find_nodes_by_name(self, name: str) -> List[GraphNode]:
        """Find nodes by name (exact match)."""
        return [n for n in self.nodes.values() if n.name == name]

    def find_nodes_by_tag(self, tag: str) -> List[GraphNode]:
        """Find nodes that have a specific semantic tag."""
        return [n for n in self.nodes.values() if tag in n.semantic_tags]

    def find_nodes_in_file(self, file_path: str) -> List[GraphNode]:
        """Find all nodes belonging to a specific file."""
        return [n for n in self.nodes.values() if n.file_path == file_path]

    def find_endpoint_nodes(self) -> List[GraphNode]:
        """Find all HTTP endpoint nodes."""
        endpoints = self.find_nodes_by_type(NodeType.ENDPOINT)
        # Also check functions with route decorators
        for node in self.find_nodes_by_type(NodeType.FUNCTION):
            if any("route" in t or "endpoint" in t for t in node.semantic_tags):
                endpoints.append(node)
        return endpoints

    # ------------------------------------------------------------------
    # Edge operations
    # ------------------------------------------------------------------

    def add_edge(self, edge: GraphEdge) -> str:
        """Add a directed edge. Returns the edge ID."""
        if edge.source_id not in self.nodes:
            raise ValueError(f"Source node '{edge.source_id}' does not exist")
        if edge.target_id not in self.nodes:
            raise ValueError(f"Target node '{edge.target_id}' does not exist")

        # Check for duplicate
        for existing_edge in self.edges.values():
            if (
                existing_edge.source_id == edge.source_id
                and existing_edge.target_id == edge.target_id
                and existing_edge.edge_type == edge.edge_type
            ):
                # Merge instead of duplicate
                existing_edge.properties.update(edge.properties)
                existing_edge.semantic_tags.update(edge.semantic_tags)
                return existing_edge.id

        self.edges[edge.id] = edge
        self._adjacency[edge.source_id].append(edge.id)
        self._reverse_adjacency[edge.target_id].append(edge.id)
        self._edge_type_index.setdefault(edge.edge_type, set()).add(edge.id)
        return edge.id

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Retrieve an edge by ID."""
        return self.edges.get(edge_id)

    def get_outgoing_edges(self, node_id: str) -> List[GraphEdge]:
        """Get all edges originating from a node."""
        edge_ids = self._adjacency.get(node_id, [])
        return [self.edges[eid] for eid in edge_ids if eid in self.edges]

    def get_incoming_edges(self, node_id: str) -> List[GraphEdge]:
        """Get all edges pointing to a node."""
        edge_ids = self._reverse_adjacency.get(node_id, [])
        return [self.edges[eid] for eid in edge_ids if eid in self.edges]

    def find_edges_by_type(self, edge_type: EdgeType) -> List[GraphEdge]:
        """Get all edges of a given type."""
        ids = self._edge_type_index.get(edge_type, set())
        return [self.edges[eid] for eid in ids if eid in self.edges]

    def find_edges_between(
        self, source_id: str, target_id: str
    ) -> List[GraphEdge]:
        """Find all edges between two specific nodes."""
        return [
            e
            for e in self.get_outgoing_edges(source_id)
            if e.target_id == target_id
        ]

    # ------------------------------------------------------------------
    # Graph traversal
    # ------------------------------------------------------------------

    def neighbors(self, node_id: str) -> List[GraphNode]:
        """Get all direct neighbors of a node (outgoing)."""
        edges = self.get_outgoing_edges(node_id)
        return [
            self.nodes[e.target_id]
            for e in edges
            if e.target_id in self.nodes
        ]

    def predecessors(self, node_id: str) -> List[GraphNode]:
        """Get all nodes that point to this node."""
        edges = self.get_incoming_edges(node_id)
        return [
            self.nodes[e.source_id]
            for e in edges
            if e.source_id in self.nodes
        ]

    def bfs_path(
        self, start_id: str, end_id: str, edge_types: Optional[Set[EdgeType]] = None
    ) -> Optional[List[str]]:
        """
        Find shortest path between two nodes using BFS.
        Optionally filter by edge types.
        Returns list of node IDs or None if no path exists.
        """
        if start_id not in self.nodes or end_id not in self.nodes:
            return None
        if start_id == end_id:
            return [start_id]

        from collections import deque

        queue = deque([(start_id, [start_id])])
        visited = {start_id}

        while queue:
            current, path = queue.popleft()
            for edge in self.get_outgoing_edges(current):
                if edge_types and edge.edge_type not in edge_types:
                    continue
                if edge.target_id not in visited:
                    new_path = path + [edge.target_id]
                    if edge.target_id == end_id:
                        return new_path
                    visited.add(edge.target_id)
                    queue.append((edge.target_id, new_path))

        return None

    def find_data_flow_paths(
        self, start_id: str, end_id: str, max_depth: int = 10
    ) -> List[List[str]]:
        """
        Find all data flow paths between two nodes up to max_depth.
        Used to trace how user input propagates to sensitive operations.
        """
        if start_id not in self.nodes or end_id not in self.nodes:
            return []

        results: List[List[str]] = []
        flow_types = {EdgeType.FLOWS_TO, EdgeType.CALLS, EdgeType.READS, EdgeType.WRITES}

        def _dfs(current: str, path: List[str], visited: Set[str], depth: int) -> None:
            if depth > max_depth:
                return
            if current == end_id:
                results.append(list(path))
                return
            for edge in self.get_outgoing_edges(current):
                if edge.edge_type not in flow_types:
                    continue
                if edge.target_id in visited:
                    continue
                visited.add(edge.target_id)
                path.append(edge.target_id)
                _dfs(edge.target_id, path, visited, depth + 1)
                path.pop()
                visited.remove(edge.target_id)

        _dfs(start_id, [start_id], {start_id}, 0)
        return results

    def find_authorization_edges(self, node_id: str) -> List[GraphEdge]:
        """Find all authorization-related edges for a node."""
        auth_types = {EdgeType.AUTHORIZES, EdgeType.GUARDS, EdgeType.DECORATES}
        result = []
        for edge in self.get_incoming_edges(node_id):
            if edge.edge_type in auth_types:
                result.append(edge)
        # Also check outgoing decorator edges
        for edge in self.get_outgoing_edges(node_id):
            if edge.edge_type in auth_types:
                result.append(edge)
        return result

    # ------------------------------------------------------------------
    # Subgraph extraction
    # ------------------------------------------------------------------

    def extract_subgraph(self, node_ids: Set[str]) -> SemanticGraph:
        """Extract a subgraph containing only the specified nodes and edges between them."""
        sub = SemanticGraph()
        for nid in node_ids:
            if nid in self.nodes:
                sub.add_node(self.nodes[nid])
        for edge in self.edges.values():
            if edge.source_id in node_ids and edge.target_id in node_ids:
                sub.add_edge(edge)
        return sub

    def extract_endpoint_subgraph(self, endpoint_id: str, depth: int = 3) -> SemanticGraph:
        """Extract the subgraph reachable from an endpoint up to given depth."""
        if endpoint_id not in self.nodes:
            return SemanticGraph()

        reachable: Set[str] = set()
        current_level = {endpoint_id}
        for _ in range(depth):
            next_level: Set[str] = set()
            for nid in current_level:
                if nid not in reachable:
                    reachable.add(nid)
                    for edge in self.get_outgoing_edges(nid):
                        if edge.target_id not in reachable:
                            next_level.add(edge.target_id)
                    for edge in self.get_incoming_edges(nid):
                        if edge.source_id not in reachable:
                            next_level.add(edge.source_id)
            current_level = next_level
            if not current_level:
                break

        return self.extract_subgraph(reachable)

    # ------------------------------------------------------------------
    # Statistics and serialization
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Graph statistics."""
        type_counts = {}
        for ntype, ids in self._type_index.items():
            type_counts[ntype.value] = len(ids)
        edge_type_counts = {}
        for etype, ids in self._edge_type_index.items():
            edge_type_counts[etype.value] = len(ids)
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": type_counts,
            "edge_types": edge_type_counts,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the entire graph."""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
            "stats": self.stats(),
        }
