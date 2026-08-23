
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
    # Actions that mutate protected state — an unauthenticated caller must
    # never trigger them, so they imply an auth expectation at minimum.
    _SENSITIVE_ACTIONS = [
        "delete", "update", "create", "approve", "reject",
        "transfer", "cancel", "refund", "assign", "promote",
        "demote", "disable", "enable", "reset", "change_password",
        "edit", "remove", "destroy", "purge", "grant", "revoke",
        "invite", "ban", "suspend", "execute", "deploy", "withdraw",
        "deposit", "charge", "pay", "checkout", "ship", "close",
        "escalate", "impersonate", "merge", "archive", "restore",
        "export", "download", "backup", "wipe",
    ]
    # Read-style actions that expose another user's resource — ownership
    # expectation applies (IDOR surface) even though no mutation occurs.
    _READ_ACTIONS = [
        "get", "fetch", "view", "read", "show", "detail", "retrieve",
        "list", "lookup", "load",
    ]
    # Create-style actions operate on a resource that does not exist yet —
    # an ownership expectation on them is a false-positive generator.
    _CREATION_ACTIONS = {
        "create", "register", "signup", "init", "initialize", "new",
        "make", "build",
    }
    # Parameter names that denote the *resource* being accessed (vs the
    # caller identity): order_id, post_id, pk, uuid, slug...
    _RESOURCE_ID_HINTS = ("_id", "id", "pk", "uuid", "slug", "key", "num")
    # Parameter names that denote the *caller's* identity, never a resource.
    _IDENTITY_PARAM_HINTS = (
        "user", "current", "request", "session", "auth", "caller",
        "actor", "self", "cls",
    )
    _AUTH_DECORATORS = [
        "login_required", "permission_required", "staff_member_required",
        "admin_required", "superuser_required", "authentication_required",
        "ownership_required", "role_required", "has_permission",
    ]
    # Docstring vocabulary that encodes *state-guard* intent, not auth intent.
    # "must be APPROVED and not already refunded" is a precondition on the
    # state machine — classifying it as auth poisons the differential engine.
    _STATE_GUARD_PHRASES = [
        "must be", "must not be", "already", "only when", "only if",
        "requires state", "not already", "in progress", "pending only",
        "approved only", "once", "twice",
    ]
    _AUTH_DOC_KEYWORDS = [
        "admin", "administrator", "staff", "superuser", "owner only",
        "authorized", "authenticated", "permission", "privileged",
        "role", "login required", "must be logged", "restricted to",
        "access control",
    ]
    _OWNERSHIP_DOC_KEYWORDS = [
        "own", "their own", "belongs to", "the user's", "creator",
        "owned by", "their order", "their account", "their profile",
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

        # Signal 2: Name encodes a sensitive action.
        #
        # Two sub-cases:
        #   a) scope is inferable from the name (admin_, manage_...) -> strong
        #      auth expectation for that scope.
        #   b) a sensitive action with no scope hint -> baseline auth
        #      expectation ("authenticated"). delete_order(), refund_payment(),
        #      etc. must never be callable anonymously.
        if self._has_sensitive_action(name):
            action = self._extract_action(name)
            scope = self._infer_scope_from_name(name)
            if scope:
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="auth",
                    description=(
                        f"Function '{node.name}' performs sensitive action '{action}' "
                        f"and name suggests '{scope}' scope authorization is expected"
                    ),
                    confidence=0.65, source=f"name_analysis:{node.name}", scope=scope,
                )
            elif action not in self._CREATION_ACTIONS:
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="auth",
                    description=(
                        f"Function '{node.name}' performs sensitive action '{action}'; "
                        f"at minimum an authenticated caller is expected"
                    ),
                    confidence=0.55, source=f"name_analysis:{node.name}",
                    scope="authenticated",
                )

        # Signal 3: Ownership expectation from parameter shape.
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
        elif self._takes_resource_identifier(node, param_names):
            action = self._extract_action(name)
            if action not in self._CREATION_ACTIONS:
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="ownership",
                    description=(
                        f"Function '{node.name}' acts on a resource identifier "
                        f"({self._takes_resource_identifier(node, param_names)}), "
                        f"suggesting a resource ownership check is expected"
                    ),
                    confidence=0.6, source=f"resource_param_analysis:{node.name}",
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

        # IDOR-prone routes: /orders/<int:order_id>, /users/{id}, ...
        if self._route_has_resource_id(route):
            self._add_expectation(
                entity_id=node.id, entity_name=node.name,
                expectation_type="ownership",
                description=(
                    f"Endpoint {method} {route} has an ID parameter, "
                    f"suggesting resource ownership check is expected"
                ),
                confidence=0.75, source=f"route_analysis:{route}",
            )

    @staticmethod
    def _route_has_resource_id(route: str) -> bool:
        """Whether a route template embeds a resource identifier segment."""
        if not route:
            return False
        import re
        for match in re.finditer(r"[<{]([^>}]+)[>}]", route):
            segment = match.group(1).lower()
            # Strip converter prefixes: <int:order_id> -> order_id
            segment = segment.split(":")[-1]
            if (
                segment == "id"
                or segment.endswith("_id")
                or segment in {"pk", "uuid", "slug", "key"}
                or segment in {"int", "str", "path", "float"}  # bare typed converters
            ):
                return True
        return False

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

    # Strong caller-identity hints: when one of these params exists, the
    # identity is already accounted for and generic `<x>_id` params are the
    # resource under access (even `user_id`).
    _STRONG_IDENTITY_HINTS = ("current", "request", "session", "actor", "caller", "auth_user")

    def _takes_resource_identifier(self, node: GraphNode, param_names: List[str]) -> str:
        """
        Return the name of the parameter that identifies the *resource* being
        accessed — e.g. ``order_id`` in ``delete_order(order_id, current_user)``
        — or an empty string.

        Caller-identity parameters (``current_user``, ``request``, ``session``)
        are excluded. When a strong identity param is present, generic
        ``user_id``-style params become resources again:
        ``list_user_orders(user_id, current_user)`` — the IDOR target is
        ``user_id``.
        """
        has_strong_identity = any(
            any(h in pn for h in self._STRONG_IDENTITY_HINTS) for pn in param_names if pn
        )
        candidates: List[str] = []
        for pn in param_names:
            if not pn or pn in {"self", "cls"}:
                continue
            if any(h in pn for h in self._STRONG_IDENTITY_HINTS):
                continue  # caller identity, not the resource
            if not has_strong_identity and any(
                h in pn for h in ("user", "owner", "auth")
            ):
                continue  # ambiguous identity param; no separate identity param
            if any(pn == hint or pn.endswith("_" + hint) for hint in self._RESOURCE_ID_HINTS):
                candidates.append(pn)

        # Route templates count too: /orders/<int:order_id>
        route = node.properties.get("route", "")
        if route and ("<" in route or "{" in route):
            candidates.append(f"route:{route}")

        return candidates[0] if candidates else ""

    def _analyze_docstring(self, node: GraphNode, docstring: str) -> None:
        """Extract intent signals from docstrings."""
        doc_lower = docstring.lower()

        # State-guard intent takes priority over auth intent for phrases like
        # "must be APPROVED" — a precondition on the workflow, not on identity.
        for kw in self._STATE_GUARD_PHRASES:
            if kw in doc_lower and not self._has_expectation_type(node.id, "state_guard"):
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="state_guard",
                    description=(
                        f"Docstring of '{node.name}' declares a state precondition "
                        f"('{kw}'), suggesting a state guard is expected"
                    ),
                    confidence=0.6, source=f"docstring_analysis:{node.name}",
                )
                break

        for kw in self._AUTH_DOC_KEYWORDS:
            if kw in doc_lower and not self._has_auth_expectation(node.id):
                self._add_expectation(
                    entity_id=node.id, entity_name=node.name,
                    expectation_type="auth",
                    description=f"Docstring of '{node.name}' contains '{kw}', suggesting auth intent",
                    confidence=0.5, source=f"docstring_analysis:{node.name}",
                )
                break

        for kw in self._OWNERSHIP_DOC_KEYWORDS:
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
