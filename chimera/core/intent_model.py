
"""
Chimera Intent Model -- Infers Expected Semantics from code and documentation.

The Intent Model represents what the developer INTENDED the system to do.
Constructed from: docstrings, naming conventions, decorators, type annotations,
and framework conventions.

CRITICAL: Uses AST traversal and semantic analysis, NOT substring matching.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Set

if TYPE_CHECKING:
    from chimera.core.semantic_graph import SemanticGraph, GraphNode


@dataclass
class IntentExpectation:
    """A single expected semantic property for a code entity."""
    entity_id: str
    entity_name: str
    expectation_type: str  # "auth", "ownership", "state_guard", "data_constraint"
    description: str
    confidence: float = 0.7
    source: str = ""
    semantic_tags: Set[str] = field(default_factory=set)
    scope: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "expectation_type": self.expectation_type,
            "description": self.description,
            "confidence": self.confidence,
            "source": self.source,
            "scope": self.scope,
            "data": self.data,
        }


class IntentModel:
    """
    Infers expected semantics from code artifacts by traversing the SemanticGraph.

    Signals used:
    1. Name analysis (delete_order, admin_dashboard encode intent)
    2. Decorator analysis (@login_required, @permission_required)
    3. Docstring analysis (explicit descriptions of expected behavior)
    4. Parameter analysis (user_id + current_user suggests ownership check)
    5. Route analysis (/{id} suggests ownership, mutating verbs suggest auth)
    """

    _AUTH_PATTERNS = {
        "admin": {"scope": "admin", "confidence": 0.9},
        "manage": {"scope": "admin", "confidence": 0.7},
        "superuser": {"scope": "superuser", "confidence": 0.95},
        "staff": {"scope": "staff", "confidence": 0.8},
    }
    _SENSITIVE_ACTIONS = [
        "delete", "update", "create", "approve", "reject",
        "transfer", "cancel", "refund", "assign", "promote",
        "demote", "disable", "enable", "reset", "change_password",
    ]
    _AUTH_DECORATORS = [
        "login_required", "permission_required", "staff_member_required",
        "admin_required", "superuser_required", "authentication_required",
        "ownership_required", "role_required", "has_permission",
    ]

    def __init__(self) -> None:
        self.expectations: List[IntentExpectation] = []
        self._expectation_index: Dict[str, List[IntentExpectation]] = {}

    def extract(self, graph: SemanticGraph) -> List[IntentExpectation]:
        """Extract all intent expectations from the semantic graph."""
        self.expectations = []
        self._expectation_index = {}
        from chimera.core.semantic_graph import NodeType

        for node in graph.find_nodes_by_type(NodeType.FUNCTION):
            self._analyze_function_node(node, graph)
        for node in graph.find_nodes_by_type(NodeType.ENDPOINT):
            self._analyze_endpoint_node(node, graph)
        for node in graph.find_nodes_by_type(NodeType.CLASS):
            self._analyze_class_node(node, graph)
        return self.expectations

    def get_expectations_for(self, entity_id: str) -> List[IntentExpectation]:
        """Get all expectations for a specific entity."""
        return self._expectation_index.get(entity_id, [])

    def has_expectation(self, entity_id: str, exp_type: str) -> bool:
        """Check if an entity has a specific type of expectation."""
        return any(
            exp.expectation_type == exp_type
            for exp in self.get_expectations_for(entity_id)
        )

    def _add_expectation(self, **kwargs: Any) -> None:
        """Create and register an IntentExpectation."""
        exp = IntentExpectation(**kwargs)
        self.expectations.append(exp)
        self._expectation_index.setdefault(exp.entity_id, []).append(exp)

    def _has_auth_expectation(self, entity_id: str) -> bool:
        return self.has_expectation(entity_id, "auth")

    def _has_expectation_type(self, entity_id: str, exp_type: str) -> bool:
        return self.has_expectation(entity_id, exp_type)

    def _analyze_function_node(self, node: GraphNode, graph: SemanticGraph) -> None:
        """Analyze a function node for intent signals using graph traversal."""
        name = node.name.lower()
        props = node.properties

        # Signal 1: Auth decorators found via graph edges (NOT substring matching)
        auth_edges = graph.find_authorization_edges(node.id)
        for edge in auth_edges:
            src = edge.source_id if edge.source_id != node.id else edge.target_id
            src_node = graph.get_node(src)
            if src_node and src_node.node_type.value == "decorator":
                dname = src_node.name.lower()
                if any(ad in dname for ad in self._AUTH_DECORATORS):
                    self._add_auth_expectation(
                        node, f"decorator:{src_node.name}",
                        src_node.properties.get("args", []),
                    )

        # Signal 2: Name encodes sensitive action + scope
        if self._has_sensitive_action(name):
            scope = self._infer_scope_from_name(name)
            if scope:
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="auth",
                    description=(
                        f"Function '{node.name}' performs sensitive action '{self._extract_action(name)}' "
                        f"and name suggests '{scope}' scope authorization is expected"
                    ),
                    confidence=0.65, source=f"name_analysis:{node.name}", scope=scope,
                )

        # Signal 3: Dual parameters suggest ownership check
        params = props.get("parameters", [])
        param_names = [p.get("name", "").lower() for p in params]
        has_owner = any("user_id" in pn or "owner" in pn for pn in param_names)
        has_requestor = any("current" in pn or "request" in pn for pn in param_names)
        if has_owner and has_requestor:
            self._add_expectation(
                entity_id=node.id, entity_name=node.name,
                expectation_type="ownership",
                description=(
                    f"Function '{node.name}' has both a resource owner parameter "
                    f"and a request/user context parameter, suggesting ownership check is expected"
                ),
                confidence=0.7, source=f"parameter_analysis:{node.name}",
            )

        # Signal 4: Docstring language
        docstring = props.get("docstring", "")
        if docstring:
            self._analyze_docstring(node, docstring)

    def _analyze_endpoint_node(self, node: GraphNode, graph: SemanticGraph) -> None:
        """Analyze an endpoint with route-aware intent inference."""
        self._analyze_function_node(node, graph)
        route = node.properties.get("route", "")
        method = node.properties.get("method", "GET").upper()

        # All mutating endpoints expect auth
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not self._has_auth_expectation(node.id):
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="auth",
                    description=(
                        f"Endpoint {method} {route} performs a mutating operation "
                        f"and is expected to require authentication"
                    ),
                    confidence=0.85, source=f"endpoint_analysis:{method} {route}",
                )

        # IDOR-prone routes
        if "{id}" in route or "<id>" in route or "<int:" in route:
            self._add_expectation(
                entity_id=node.id, entity_name=node.name,
                expectation_type="ownership",
                description=(
                    f"Endpoint {method} {route} has an ID parameter, "
                    f"suggesting resource ownership check is expected"
                ),
                confidence=0.75, source=f"route_analysis:{route}",
            )

    def _analyze_class_node(self, node: GraphNode, graph: SemanticGraph) -> None:
        """Analyze a class node for intent signals."""
        class_type = node.properties.get("class_type", "")

        if class_type in {"view", "viewset", "apiview"}:
            self._add_expectation(
                entity_id=node.id, entity_name=node.name,
                expectation_type="auth",
                description=(
                    f"Class '{node.name}' is a {class_type} and is expected "
                    f"to have authentication requirements"
                ),
                confidence=0.8, source=f"class_type_analysis:{class_type}",
            )

        if class_type == "model":
            fields = node.properties.get("fields", [])
            field_names = [f.get("name", "").lower() for f in fields]
            if any(kw in field_names for kw in ["user", "owner", "created_by"]):
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="ownership",
                    description=(
                        f"Model '{node.name}' has a user/owner field, "
                        f"suggesting instances should be owner-scoped"
                    ),
                    confidence=0.8, source=f"model_field_analysis:{node.name}",
                )

    def _analyze_docstring(self, node: GraphNode, docstring: str) -> None:
        """Extract intent signals from docstrings."""
        doc_lower = docstring.lower()
        for kw in ["only", "must be", "requires", "restricted", "authorized",
                     "authenticated", "admin", "owner", "permission"]:
            if kw in doc_lower and not self._has_auth_expectation(node.id):
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="auth",
                    description=f"Docstring of '{node.name}' contains '{kw}', suggesting auth intent",
                    confidence=0.5, source=f"docstring_analysis:{node.name}",
                )
                break
        for kw in ["own", "their", "belongs to", "the user's", "creator"]:
            if kw in doc_lower and not self._has_expectation_type(node.id, "ownership"):
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="ownership",
                    description=f"Docstring of '{node.name}' contains ownership language ('{kw}')",
                    confidence=0.5, source=f"docstring_analysis:{node.name}",
                )
                break

    def _add_auth_expectation(self, node: GraphNode, source: str, args: list) -> None:
        """Add an auth expectation from a decorator."""
        scope = "authenticated"
        if args:
            scope = str(args[0]) if args else "authenticated"
        self._add_expectation(
            entity_id=node.id, entity_name=node.name,
            expectation_type="auth",
            description=(
                f"Decorator on '{node.name}' ({source}) "
                f"indicates '{scope}' authorization is expected"
            ),
            confidence=0.9, source=source, scope=scope,
        )

    def _has_sensitive_action(self, name: str) -> bool:
        """Check if a function name implies a sensitive action."""
        return any(action in name.split("_") for action in self._SENSITIVE_ACTIONS)

    def _extract_action(self, name: str) -> str:
        """Extract the sensitive action word from a function name."""
        for part in name.split("_"):
            if part in self._SENSITIVE_ACTIONS:
                return part
        return name.split("_")[0]

    def _infer_scope_from_name(self, name: str) -> str:
        """Infer authorization scope from a function name."""
        for pattern, info in self._AUTH_PATTERNS.items():
            if pattern in name:
                return info["scope"]
        return ""
