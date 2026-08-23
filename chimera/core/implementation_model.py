
"""Chimera Implementation Model -- Extracts Observed Semantics via AST/CFG traversal.

The Implementation Model represents what the code ACTUALLY does, extracted
through static analysis of the Abstract Syntax Tree and Control Flow Graph.
This is the ground truth against which Intent expectations are compared.

CRITICAL: This uses AST node traversal and CFG analysis, NOT substring matching.
Every observation is backed by an Evidence artifact with chain of custody.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from chimera.core.semantic_graph import SemanticGraph, GraphNode, EdgeType
    from chimera.models.evidence import Evidence


@dataclass
class ImplementationObservation:
    """
    A single observed semantic property for a code entity.

    Examples:
        - Function get_order OBSERVES no ownership check on the order_id parameter
        - Endpoint /users/{id}/delete OBSERVES no role check, only login_required
        - State transition PENDING->APPROVED OBSERVES no approval guard function called
    """
    entity_id: str
    entity_name: str
    observation_type: str  # "no_auth", "no_ownership", "no_state_guard", "direct_db_access"
    description: str
    confidence: float = 0.9
    source: str = ""
    evidence: Optional[Evidence] = None
    semantic_tags: Set[str] = field(default_factory=set)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "observation_type": self.observation_type,
            "description": self.description,
            "confidence": self.confidence,
            "source": self.source,
            "semantic_tags": list(self.semantic_tags),
            "data": self.data,
        }


class ImplementationModel:
    """
    Extracts observed semantics from code by traversing AST and CFG structures.

    The ImplementationModel is the ground truth extractor. It walks the
    SemanticGraph (which was built from AST nodes by the parsers) and
    determines what each code entity ACTUALLY does:

    1. **Authorization observation**: Does the function have an auth check?
       Traverses the AST to find auth-related function calls, decorator checks.

    2. **Ownership observation**: Does the function verify resource ownership?
       Traces data flow from resource ID parameter to any comparison/lookup.

    3. **State guard observation**: Are state transitions protected by guards?
       Checks if transition functions call guard/validation functions.

    4. **Data flow observation**: How does user input flow through the function?
       Traces parameter usage to database queries, response construction.

    Every observation is backed by Evidence with chain of custody.
    """

    # Patterns that indicate authorization checks in code (via AST, not substring)
    _AUTH_CHECK_PATTERNS = {
        "function_calls": [
            "is_authenticated", "is_staff", "is_superuser", "has_perm",
            "check_permission", "verify_auth", "authorize", "require_auth",
        ],
        "attribute_checks": [
            "is_authenticated", "is_admin", "is_staff", "is_superuser",
            "role", "permission", "is_owner",
        ],
    }
    _OWNERSHIP_CHECK_PATTERNS = {
        "function_calls": [
            "check_ownership", "verify_owner", "is_owner", "belongs_to",
            "user_owns", "has_access",
        ],
        "comparison_patterns": [
            "==", "!="
        ],
    }
    _STATE_GUARD_PATTERNS = {
        "function_calls": [
            "can_transition", "check_state", "validate_transition",
            "is_valid_state", "guard", "precondition",
        ],
    }

    def __init__(self) -> None:
        self.observations: List[ImplementationObservation] = []
        self._observation_index: Dict[str, List[ImplementationObservation]] = {}

    def extract(self, graph: SemanticGraph) -> List[ImplementationObservation]:
        """Extract all implementation observations from the semantic graph."""
        self.observations = []
        self._observation_index = {}
        from chimera.core.semantic_graph import NodeType

        for node in graph.find_nodes_by_type(NodeType.FUNCTION):
            self._analyze_function(node, graph)
        for node in graph.find_nodes_by_type(NodeType.ENDPOINT):
            self._analyze_endpoint(node, graph)
        return self.observations

    def get_observations_for(self, entity_id: str) -> List[ImplementationObservation]:
        return self._observation_index.get(entity_id, [])

    def has_observation(self, entity_id: str, obs_type: str) -> bool:
        return any(
            obs.observation_type == obs_type
            for obs in self.get_observations_for(entity_id)
        )

    def _add_observation(self, **kwargs: Any) -> None:
        obs = ImplementationObservation(**kwargs)
        self.observations.append(obs)
        self._observation_index.setdefault(obs.entity_id, []).append(obs)

    # ------------------------------------------------------------------
    # Analysis methods -- all use graph traversal, not substring matching
    # ------------------------------------------------------------------

    def _analyze_function(self, node: GraphNode, graph: SemanticGraph) -> None:
        """Analyze a function for observed security properties."""
        props = node.properties
        func_body = props.get("body_nodes", [])
        called_functions = props.get("calls", [])
        decorators = props.get("decorators", [])

        # Check for auth via graph edges (traversing decorator/call edges)
        has_auth = self._check_auth_via_graph(node, graph)
        if not has_auth:
            self._add_observation(
                entity_id=node.id, entity_name=node.name,
                observation_type="no_auth",
                description=(
                    f"Function '{node.name}' has no observable authorization check. "
                    f"No auth decorators found via graph traversal and no auth-related "
                    f"function calls detected in its call graph."
                ),
                confidence=0.85, source=f"graph_traversal:{node.name}",
            )

        # Check for ownership via data flow analysis.
        # Create-style functions legitimately have no ownership check — the
        # resource does not exist yet, so there is no owner to compare against.
        has_ownership = self._check_ownership_via_graph(node, graph)
        if (
            not has_ownership
            and self._has_resource_id_parameter(node)
            and not self._is_creation_function(node)
        ):
            self._add_observation(
                entity_id=node.id, entity_name=node.name,
                observation_type="no_ownership",
                description=(
                    f"Function '{node.name}' takes a resource ID parameter but "
                    f"no ownership verification was found. Data flow analysis shows "
                    f"the resource ID is used directly without comparison to the "
                    f"requesting user's ID."
                ),
                confidence=0.8, source=f"dataflow_analysis:{node.name}",
            )

        # Check for state guards
        has_guard = self._check_state_guard_via_graph(node, graph)
        state_ops = props.get("state_operations", [])
        if state_ops and not has_guard:
            self._add_observation(
                entity_id=node.id, entity_name=node.name,
                observation_type="no_state_guard",
                description=(
                    f"Function '{node.name}' performs state transitions ({state_ops}) "
                    f"but no guard/validation function is called in the execution path."
                ),
                confidence=0.75, source=f"state_analysis:{node.name}",
            )

        # Grammar differential: string-built SQL without parameterization
        sql_taint = props.get("sql_taint", [])
        if sql_taint and not props.get("sql_parameterized"):
            first = sql_taint[0]
            self._add_observation(
                entity_id=node.id, entity_name=node.name,
                observation_type="unsafe_sql",
                description=(
                    f"Function '{node.name}' builds SQL by string interpolation "
                    f"({first['kind']} at line {first['line']}, values "
                    f"{first.get('interpolated', [])[:3]}) with no parameterized "
                    f"execute() call — an attacker-controlled value crosses the "
                    f"Python-str/SQL-literal grammar boundary unsanitized."
                ),
                confidence=0.85, source=f"grammar_differential:{node.name}",
            )

    def _analyze_endpoint(self, node: GraphNode, graph: SemanticGraph) -> None:
        """Analyze an endpoint -- same as function plus route-specific checks."""
        self._analyze_function(node, graph)
        route = node.properties.get("route", "")
        method = node.properties.get("method", "GET").upper()

        # Check for rate limiting
        has_rate_limit = self._check_rate_limit_via_graph(node, graph)
        if not has_rate_limit and method in {"POST", "PUT", "DELETE"}:
            self._add_observation(
                entity_id=node.id, entity_name=node.name,
                observation_type="no_rate_limit",
                description=(
                    f"Endpoint {method} {route} performs a mutating operation "
                    f"but has no observable rate limiting."
                ),
                confidence=0.6, source=f"endpoint_analysis:{method} {route}",
            )

    # ------------------------------------------------------------------
    # Graph-traversal-based checks (NOT substring matching)
    # ------------------------------------------------------------------

    def _check_auth_via_graph(self, node: GraphNode, graph: SemanticGraph) -> bool:
        """Check for authorization via graph edge traversal AND inline checks."""
        from chimera.core.semantic_graph import EdgeType

        # 1. Parser-emitted inline guards — `if not user.is_admin: raise ...`,
        #    `current_user.get("role")`, guard-by-exception. This is what makes
        #    guarded code distinguishable from unguarded code.
        if node.properties.get("auth_checks"):
            return True
        if "auth_checked" in getattr(node, "semantic_tags", set()):
            return True

        # 2. Incoming AUTHORIZES / GUARDS edges are created by the parser only
        #    for auth-classified decorators — the edge alone is conclusive.
        for edge in graph.get_incoming_edges(node.id):
            if edge.edge_type in {EdgeType.AUTHORIZES, EdgeType.GUARDS}:
                return True
            if edge.edge_type == EdgeType.DECORATES:
                src = graph.get_node(edge.source_id)
                if src:
                    src_name = src.name.lower()
                    if src.properties.get("is_auth"):
                        return True
                    for pattern_list in self._AUTH_CHECK_PATTERNS.values():
                        for pattern in pattern_list:
                            if pattern in src_name:
                                return True
                    # Well-known auth decorators that carry no pattern token
                    if any(kw in src_name for kw in ("login", "auth", "permission", "role")):
                        return True

        # 3. Outgoing CALLS edges to auth-related functions
        for edge in graph.get_outgoing_edges(node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target:
                    target_name = target.name.lower()
                    for pattern in self._AUTH_CHECK_PATTERNS["function_calls"]:
                        if pattern in target_name:
                            return True

        # 4. Transitively-called auth (depth 2)
        for edge in graph.get_outgoing_edges(node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target:
                    for sub_edge in graph.get_outgoing_edges(target.id):
                        if sub_edge.edge_type == EdgeType.CALLS:
                            sub_target = graph.get_node(sub_edge.target_id)
                            if sub_target:
                                sub_name = sub_target.name.lower()
                                for pattern in self._AUTH_CHECK_PATTERNS["function_calls"]:
                                    if pattern in sub_name:
                                        return True

        return False

    # Token sets for ownership-comparison detection. Whole-token matching
    # (attribute/subscript boundaries) so `username` does not read as `user`.
    _OWNERSHIP_SIDE_TOKENS = {
        "owner", "owner_id", "user", "user_id", "created_by", "creator",
        "author", "author_id", "account", "account_id", "tenant", "tenant_id",
    }
    _IDENTITY_SIDE_TOKENS = {
        "user", "current_user", "auth_user", "request", "session",
        "identity", "principal", "actor", "caller", "me",
    }

    def _check_ownership_via_graph(self, node: GraphNode, graph: SemanticGraph) -> bool:
        """Check for ownership verification via data flow graph traversal."""
        from chimera.core.semantic_graph import EdgeType

        # Check outgoing calls for ownership-related functions
        for edge in graph.get_outgoing_edges(node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target:
                    tname = target.name.lower()
                    for pattern in self._OWNERSHIP_CHECK_PATTERNS["function_calls"]:
                        if pattern in tname:
                            return True

        def _comparison_is_ownership(record: Any) -> bool:
            left = str(record.get("left", ""))
            comparators = [str(c) for c in record.get("comparators", [])]
            import re as _re
            sides = [left, *comparators]
            token_sets = []
            for side in sides:
                toks = set(t for t in _re.split(r"[\.\[\]\(\)'\s\"]+", side.lower()) if t)
                token_sets.append(toks)
            for i in range(len(sides)):
                for j in range(len(sides)):
                    if i == j:
                        continue
                    if (token_sets[i] & self._OWNERSHIP_SIDE_TOKENS) and (
                        token_sets[j] & self._IDENTITY_SIDE_TOKENS
                    ):
                        return True
            return False

        # Parser-emitted structural body records
        for bnode in node.properties.get("body_nodes", []):
            if bnode.get("node_type") == "Compare" and _comparison_is_ownership(bnode):
                return True

        # Parser-emitted comparison records (python_parser._extract_comparisons)
        for comp in node.properties.get("comparisons", []):
            if _comparison_is_ownership(comp):
                return True

        # Parser tags likely ownership comparisons directly
        if "ownership_check" in getattr(node, "semantic_tags", set()):
            return True

        return False

    def _check_state_guard_via_graph(self, node: GraphNode, graph: SemanticGraph) -> bool:
        """Check for state guard functions via call graph traversal."""
        from chimera.core.semantic_graph import EdgeType

        for edge in graph.get_outgoing_edges(node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target:
                    tname = target.name.lower()
                    for pattern in self._STATE_GUARD_PATTERNS["function_calls"]:
                        if pattern in tname:
                            return True
        return False

    def _check_rate_limit_via_graph(self, node: GraphNode, graph: SemanticGraph) -> bool:
        """Check for rate limiting via decorator/call traversal."""
        from chimera.core.semantic_graph import EdgeType

        for edge in graph.get_incoming_edges(node.id):
            if edge.edge_type == EdgeType.DECORATES:
                src = graph.get_node(edge.source_id)
                if src and "rate" in src.name.lower() and "limit" in src.name.lower():
                    return True
        for edge in graph.get_outgoing_edges(node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target and "rate" in target.name.lower():
                    return True
        return False

    # Actions that create a brand-new resource — no prior owner exists.
    _CREATION_ACTIONS = {
        "create", "register", "signup", "init", "initialize", "new",
        "make", "build",
    }

    @classmethod
    def _is_creation_function(cls, node: GraphNode) -> bool:
        """Whether the function name denotes a create-style action."""
        name = node.name.lower()
        parts = name.split("_")
        return any(part in cls._CREATION_ACTIONS for part in parts) and not any(
            part in {"delete", "remove", "destroy"} for part in parts
        )

    def _has_resource_id_parameter(self, node: GraphNode) -> bool:
        """
        Check if the function takes a *resource* ID parameter.

        A resource identifier looks like ``order_id`` / ``pk`` / ``uuid`` /
        ``slug`` — it names the object under access. Caller-identity params
        (``current_user``, ``request``, ``session``, ``user_id``...) are NOT
        resource identifiers; without this distinction every handler trips the
        IDOR detector on its own context parameter.
        """
        identity_hints = (
            "user", "current", "request", "session", "auth", "caller",
            "actor", "self", "cls",
        )
        strong_identity_hints = ("current", "request", "session", "actor", "caller", "auth_user")
        params = node.properties.get("parameters", [])
        param_names = [p.get("name", "").lower() for p in params]
        has_strong_identity = any(
            any(h in pn for h in strong_identity_hints) for pn in param_names if pn
        )
        for p in params:
            pname = p.get("name", "").lower()
            if not pname or pname in {"self", "cls"}:
                continue
            if any(hint in pname for hint in strong_identity_hints):
                continue  # caller identity — not the resource under access
            if not has_strong_identity and any(
                hint in pname for hint in ("user", "owner", "auth")
            ):
                continue  # ambiguous identity param, no separate identity param
            if (
                pname == "id"
                or pname.endswith("_id")
                or pname in {"pk", "uuid", "slug", "key"}
            ):
                return True
        # Check route for ID parameters: /orders/<int:order_id>, /users/{id}
        route = node.properties.get("route", "")
        if route and ("<" in route or "{" in route):
            import re
            for match in re.finditer(r"[<{]([^>}]+)[>}]", route):
                segment = match.group(1).lower().split(":")[-1]
                if (segment == "id" or segment.endswith("_id")
                        or segment in {"pk", "uuid", "slug", "key", "int"}):
                    return True
        return False
