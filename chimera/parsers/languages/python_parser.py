"""
Chimera Python Parser — AST-based structural extraction for Python source files.

Builds the SemanticGraph from Python source code by walking the AST.  This is
the primary parser for Django/Flask/FastAPI applications and extracts:

    * Functions (name, parameters, decorators, docstrings, body structure)
    * Classes  (name, bases, methods, type detection: model/view/viewset)
    * Decorators (name, arguments — especially auth decorators)
    * Function calls within bodies (CALLS edges)
    * Data-flow traces (parameter → call / return)
    * State-machine patterns (status / state variable modifications)
    * Compare nodes (ownership-check detection)

All extraction uses Python's built-in ``ast`` module — **no substring matching**.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from chimera.core.semantic_graph import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    SemanticGraph,
)
from chimera.models.evidence import (
    ChainOfCustody,
    Evidence,
    EvidenceSource,
    EvidenceType,
)
from chimera.parsers.errors import ParseError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known auth / permission decorator names (Django, Flask, FastAPI)
# ---------------------------------------------------------------------------
_AUTH_DECORATORS: Set[str] = {
    "login_required",
    "permission_required",
    "user_passes_test",
    "authentication_classes",
    "permission_classes",
    "api_view",
    "action",
    "require_http_methods",
    "require_POST",
    "require_GET",
    "login_not_required",
}

_AUTH_MODULE_PREFIXES: Tuple[str, ...] = (
    "django.contrib.auth.decorators.",
    "django.contrib.admin.decorators.",
    "rest_framework.decorators.",
    "rest_framework.permissions.",
    "flask_login.login_required",
    "flask_principal",
)

# ---------------------------------------------------------------------------
# Framework base-class heuristics for class type detection
# ---------------------------------------------------------------------------
_MODEL_BASES: Set[str] = {
    "Model",
    "AbstractUser",
    "AbstractBaseUser",
    "BaseUserManager",
    "models.Model",
    "django.db.models.Model",
}

_VIEWSET_BASES: Set[str] = {
    "ModelViewSet",
    "ReadOnlyModelViewSet",
    "GenericViewSet",
    "ViewSet",
    "viewsets.ModelViewSet",
    "viewsets.ReadOnlyModelViewSet",
    "viewsets.GenericViewSet",
    "viewsets.ViewSet",
    "rest_framework.viewsets.ModelViewSet",
    "rest_framework.viewsets.ReadOnlyModelViewSet",
    "rest_framework.viewsets.GenericViewSet",
    "rest_framework.viewsets.ViewSet",
}

_VIEW_BASES: Set[str] = {
    "View",
    "TemplateView",
    "ListView",
    "DetailView",
    "CreateView",
    "UpdateView",
    "DeleteView",
    "FormView",
    "APIView",
    "GenericAPIView",
    "views.View",
    "views.APIView",
    "generic.GenericAPIView",
    "generics.ListAPIView",
    "generics.RetrieveAPIView",
    "generics.CreateAPIView",
    "generics.UpdateAPIView",
    "generics.DestroyAPIView",
    "generics.ListCreateAPIView",
    "generics.RetrieveUpdateAPIView",
    "generics.RetrieveDestroyAPIView",
    "generics.RetrieveUpdateDestroyAPIView",
    "rest_framework.views.APIView",
    "rest_framework.generics.GenericAPIView",
    "flask.views.MethodView",
    "flask.views.View",
}

# State-variable name hints
_STATE_VAR_NAMES: Set[str] = {
    "status",
    "state",
    "phase",
    "stage",
    "step",
    "workflow_state",
}

# ---------------------------------------------------------------------------
# Inline authorization-check vocabulary.
#
# These attribute / key names indicate an inline guard such as
# ``if not current_user.is_admin: raise PermissionError`` or
# ``current_user.get("role") != "admin"``.  The implementation model consumes
# the emitted ``auth_checks`` property — keeping this vocabulary alive here is
# what makes guarded code distinguishable from unguarded code.
# ---------------------------------------------------------------------------
_AUTH_ATTRIBUTE_NAMES: Set[str] = {
    "is_admin",
    "is_staff",
    "is_superuser",
    "is_authenticated",
    "is_anonymous",
    "is_owner",
    "is_moderator",
    "role",
    "roles",
    "permission",
    "permissions",
    "perms",
    "scope",
    "scopes",
    "group",
    "groups",
    "allowed",
    "authorize",
    "authorized",
    "can_access",
}

# Exceptions whose raise constitutes an explicit authorization guard.
_AUTH_EXCEPTION_NAMES: Set[str] = {
    "PermissionError",
    "PermissionDenied",
    "AuthenticationError",
    "NotAuthenticated",
    "AuthorizationError",
    "AccessDenied",
    "Forbidden",
    "Unauthorized",
}

# Identity-side tokens for ownership comparisons (`current_user`, `request.user`, ...)
_IDENTITY_TOKENS: Set[str] = {
    "user",
    "current_user",
    "auth_user",
    "request",
    "session",
    "identity",
    "principal",
    "actor",
    "caller",
    "me",
}

# Ownership-side tokens (`obj.owner`, `record.user_id`, `created_by`, ...)
_OWNERSHIP_TOKENS: Set[str] = {
    "owner",
    "owner_id",
    "user",
    "user_id",
    "created_by",
    "creator",
    "author",
    "author_id",
    "account",
    "account_id",
    "tenant",
    "tenant_id",
}

# Create-style actions: these legitimately operate on not-yet-owned resources.
_CREATION_ACTIONS: Set[str] = {
    "create",
    "register",
    "signup",
    "sign_up",
    "init",
    "initialize",
    "new",
    "add",
    "make",
    "build",
}


# ---------------------------------------------------------------------------
# Helper data-classes
# ---------------------------------------------------------------------------


@dataclass
class _ParamInfo:
    """Parsed parameter metadata."""
    name: str
    annotation: str = ""
    default_value: Optional[str] = None
    is_self: bool = False
    is_cls: bool = False
    is_variadic: bool = False
    is_kw_only: bool = False


@dataclass
class _CallInfo:
    """Parsed function-call metadata."""
    name: str
    line: int
    col: int
    args: List[str] = field(default_factory=list)
    is_method_call: bool = False
    object_name: str = ""


@dataclass
class _CompareInfo:
    """Parsed Compare-node metadata."""
    left: str
    ops: List[str]
    comparators: List[str]
    line: int


# ---------------------------------------------------------------------------
# PythonParser
# ---------------------------------------------------------------------------


class PythonParser:
    """
    AST-based parser that populates a :class:`SemanticGraph` from Python source.

    Parameters
    ----------
    framework_hints : dict, optional
        Additional framework-specific base-class or decorator names to
        recognise during class-type and auth detection.
    """

    # ------------------------------------------------------------------
    # Public API surface
    # ------------------------------------------------------------------

    #: Stable parser identifier (used by orchestrator / capability registry).
    name: str = "python_ast"

    #: File extensions this parser handles.
    extensions: Tuple[str, ...] = (".py", ".pyi")

    def __init__(self, framework_hints: Optional[Dict[str, Set[str]]] = None) -> None:
        self._hints = framework_hints or {}
        self._evidence: List[Evidence] = []
        self.graph: SemanticGraph = SemanticGraph()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(
        self,
        file_path: str,
        source: str,
        graph: Optional[SemanticGraph] = None,
    ) -> List[Evidence]:
        """
        Parse *source* (Python source text from *file_path*) and populate *graph*.

        Returns a list of :class:`Evidence` objects collected during parsing.

        Parameters
        ----------
        file_path : str
            Path of the source file (used for node provenance).
        source : str
            Python source text. ``None`` or whitespace-only input yields an
            empty evidence list rather than raising.
        graph : SemanticGraph, optional
            Graph to populate. When ``None`` the parser populates its own
            graph, available as ``self.graph`` afterwards.

        Raises
        ------
        ParseError
            If the source cannot be parsed by the ``ast`` module. Carries
            file path, line number, and a snippet of the offending line.
        """
        self._evidence.clear()
        if graph is not None and not isinstance(graph, SemanticGraph):
            raise TypeError(
                f"graph must be a SemanticGraph instance (or None), got "
                f"{type(graph).__name__}. Pass SemanticGraph() — a plain dict "
                f"or networkx.Graph is not compatible with the parser cascade."
            )
        target_graph = graph if graph is not None else SemanticGraph()
        self.graph = target_graph

        if not source or not source.strip():
            return []

        # Strip a UTF-8 BOM defensively — feedparser-style files crash ast.parse.
        if source.startswith("\ufeff"):
            source = source.lstrip("\ufeff")

        try:
            tree = ast.parse(source, filename=file_path or "<unknown>")
        except SyntaxError as exc:
            raise ParseError.from_syntax_error(
                exc, file_path or "<unknown>", source, parser=self.name
            ) from exc
        except (ValueError, TypeError, RecursionError, MemoryError) as exc:
            raise ParseError(
                f"unparseable Python source: {exc}",
                file_path=file_path or "<unknown>",
                parser=self.name,
            ) from exc

        # Walk top-level statements
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                self._process_function(node, file_path, target_graph)
            elif isinstance(node, ast.ClassDef):
                self._process_class(node, file_path, target_graph)
            elif isinstance(node, ast.Import):
                self._process_import(node, file_path, target_graph)
            elif isinstance(node, ast.ImportFrom):
                self._process_import_from(node, file_path, target_graph)

        return list(self._evidence)

    # ------------------------------------------------------------------
    # Top-level node processors
    # ------------------------------------------------------------------

    def _process_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        file_path: str,
        graph: SemanticGraph,
        class_node_id: Optional[str] = None,
    ) -> Optional[str]:
        """Process a function / async-function node and return its graph node ID."""
        func_node = self._visit_function(node, file_path)
        func_id = graph.add_node(func_node)

        # CONTAINS edge from class (or file) to function
        parent_id = class_node_id or self._ensure_file_node(file_path, graph)
        if parent_id:
            graph.add_edge(GraphEdge(
                source_id=parent_id,
                target_id=func_id,
                edge_type=EdgeType.CONTAINS,
                properties={"container": "class" if class_node_id else "module"},
            ))

        # Process decorators
        for dec_node in node.decorator_list:
            dec_gnode = self._visit_decorator(dec_node, file_path)
            if dec_gnode is not None:
                dec_id = graph.add_node(dec_gnode)
                graph.add_edge(GraphEdge(
                    source_id=dec_id,
                    target_id=func_id,
                    edge_type=EdgeType.DECORATES,
                    properties={"decorator_name": dec_gnode.name},
                ))
                # Tag auth decorators
                if self._is_auth_decorator(dec_gnode.name):
                    graph.add_edge(GraphEdge(
                        source_id=dec_id,
                        target_id=func_id,
                        edge_type=EdgeType.AUTHORIZES,
                        properties={"mechanism": dec_gnode.name},
                    ))
                    func_node.semantic_tags.add("auth_protected")

        # CALLS edges
        calls = self._extract_calls(node)
        for call in calls:
            call_node = GraphNode(
                node_type=NodeType.FUNCTION,
                name=call.name,
                file_path=file_path,
                line_range=(call.line, call.line),
                properties={"call_site": True},
                semantic_tags={"call_site"},
            )
            call_id = graph.add_node(call_node)
            graph.add_edge(GraphEdge(
                source_id=func_id,
                target_id=call_id,
                edge_type=EdgeType.CALLS,
                properties={
                    "args": call.args,
                    "is_method_call": call.is_method_call,
                    "object_name": call.object_name,
                },
            ))

        # Data-flow edges
        flows = self._extract_data_flow(node)
        for flow in flows:
            param_name = flow["parameter"]
            target_name = flow.get("target", "")
            flow_type = flow.get("flow_type", "call")
            # We don't always have a target node, so store in properties
            func_node.properties.setdefault("data_flows", []).append(flow)
            if target_name:
                func_node.semantic_tags.add("data_flow_traced")

        # State operations
        state_ops = self._extract_state_operations(node)
        if state_ops:
            func_node.properties["state_operations"] = state_ops
            func_node.semantic_tags.add("state_modifier")

        # Comparisons
        comparisons = self._extract_comparisons(node)
        if comparisons:
            func_node.properties["comparisons"] = [
                {
                    "left": c.left,
                    "ops": c.ops,
                    "comparators": c.comparators,
                    "line": c.line,
                }
                for c in comparisons
            ]
            # Tag likely ownership checks: obj.user == request.user
            for comp in comparisons:
                if self._looks_like_ownership_check(comp):
                    func_node.semantic_tags.add("ownership_check")

        # Inline authorization checks (is_admin gates, PermissionError raises…)
        auth_checks = self._extract_auth_checks(node)
        if auth_checks:
            func_node.properties["auth_checks"] = auth_checks
            func_node.semantic_tags.add("auth_checked")

        # SQL grammar differentials — string-built queries vs parameterization
        sql_taint, sql_parameterized = self._extract_sql_taint(node)
        if sql_taint:
            func_node.properties["sql_taint"] = sql_taint
            func_node.semantic_tags.add("sql_construction")
        if sql_parameterized:
            func_node.properties["sql_parameterized"] = True
            func_node.semantic_tags.add("sql_parameterized")

        # Structural body records — what the implementation model traverses.
        func_node.properties["body_nodes"] = self._build_body_records(
            node, comparisons, auth_checks
        )

        # Collect evidence
        self._evidence.append(Evidence.from_ast_node(
            file_path=file_path,
            node_type="FunctionDef",
            node_data={
                "name": func_node.name,
                "parameters": [p.name for p in self._parse_args(node.args)],
                "decorators": [self._decorator_name(d) for d in node.decorator_list],
                "has_docstring": ast.get_docstring(node) is not None,
            },
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            description=f"Function {func_node.name} at {file_path}:{node.lineno}",
        ))

        return func_id

    def _process_class(
        self, node: ast.ClassDef, file_path: str, graph: SemanticGraph
    ) -> Optional[str]:
        """Process a ClassDef node and return its graph node ID."""
        class_node = self._visit_class(node, file_path)
        class_id = graph.add_node(class_node)

        # CONTAINS edge from file module to class
        file_id = self._ensure_file_node(file_path, graph)
        if file_id:
            graph.add_edge(GraphEdge(
                source_id=file_id,
                target_id=class_id,
                edge_type=EdgeType.CONTAINS,
                properties={"container": "module"},
            ))

        # INHERITS edges for each base
        for base in node.bases:
            base_name = self._resolve_name(base)
            base_node = GraphNode(
                node_type=NodeType.CLASS,
                name=base_name,
                file_path="",
                properties={"is_external_base": True},
            )
            base_id = graph.add_node(base_node)
            graph.add_edge(GraphEdge(
                source_id=class_id,
                target_id=base_id,
                edge_type=EdgeType.INHERITS,
                properties={"base_name": base_name},
            ))

        # Process class-level decorators (e.g. @register on models)
        for dec_node in node.decorator_list:
            dec_gnode = self._visit_decorator(dec_node, file_path)
            if dec_gnode is not None:
                dec_id = graph.add_node(dec_gnode)
                graph.add_edge(GraphEdge(
                    source_id=dec_id,
                    target_id=class_id,
                    edge_type=EdgeType.DECORATES,
                    properties={"decorator_name": dec_gnode.name},
                ))

        # Process methods inside the class
        for item in ast.iter_child_nodes(node):
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._process_function(item, file_path, graph, class_node_id=class_id)

        # Collect evidence
        self._evidence.append(Evidence.from_ast_node(
            file_path=file_path,
            node_type="ClassDef",
            node_data={
                "name": class_node.name,
                "bases": [self._resolve_name(b) for b in node.bases],
                "class_type": class_node.properties.get("class_type", "unknown"),
                "methods": [
                    n.name for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                ],
            },
            line=node.lineno,
            end_line=node.end_lineno or node.lineno,
            description=f"Class {class_node.name} ({class_node.properties.get('class_type', 'unknown')}) at {file_path}:{node.lineno}",
        ))

        return class_id

    def _process_import(self, node: ast.Import, file_path: str, graph: SemanticGraph) -> None:
        """Create IMPORTS edges for ``import X`` statements."""
        file_id = self._ensure_file_node(file_path, graph)
        if file_id is None:
            return
        for alias in node.names:
            mod_name = alias.name
            mod_node = GraphNode(
                node_type=NodeType.MODULE,
                name=mod_name,
                file_path="",
                properties={"alias": alias.asname or ""},
            )
            mod_id = graph.add_node(mod_node)
            graph.add_edge(GraphEdge(
                source_id=file_id,
                target_id=mod_id,
                edge_type=EdgeType.IMPORTS,
                properties={"alias": alias.asname or ""},
            ))

    def _process_import_from(self, node: ast.ImportFrom, file_path: str, graph: SemanticGraph) -> None:
        """Create IMPORTS edges for ``from X import Y`` statements."""
        file_id = self._ensure_file_node(file_path, graph)
        if file_id is None:
            return
        module_name = node.module or ""
        mod_node = GraphNode(
            node_type=NodeType.MODULE,
            name=module_name,
            file_path="",
        )
        mod_id = graph.add_node(mod_node)
        graph.add_edge(GraphEdge(
            source_id=file_id,
            target_id=mod_id,
            edge_type=EdgeType.IMPORTS,
            properties={"level": node.level or 0},
        ))
        for alias in node.names:
            imported_node = GraphNode(
                node_type=NodeType.FUNCTION,
                name=alias.name,
                file_path="",
                properties={"imported_from": module_name, "alias": alias.asname or ""},
                semantic_tags={"imported"},
            )
            imp_id = graph.add_node(imported_node)
            graph.add_edge(GraphEdge(
                source_id=file_id,
                target_id=imp_id,
                edge_type=EdgeType.IMPORTS,
                properties={"from_module": module_name, "alias": alias.asname or ""},
            ))

    # ------------------------------------------------------------------
    # Node builders  (return GraphNode but do NOT add to graph)
    # ------------------------------------------------------------------

    def _visit_function(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef], file_path: str
    ) -> GraphNode:
        """
        Build a :class:`GraphNode` from an ``ast.FunctionDef`` / ``ast.AsyncFunctionDef``.

        Extracts: name, parameters (with type annotations), decorators, docstring,
        and structural properties (is_async, body line range).
        """
        params = self._parse_args(node.args)
        docstring = ast.get_docstring(node)

        decorator_names = [self._decorator_name(d) for d in node.decorator_list]
        properties: Dict[str, Any] = {
            "is_async": isinstance(node, ast.AsyncFunctionDef),
            "parameters": [
                {
                    "name": p.name,
                    "annotation": p.annotation,
                    "default": p.default_value,
                    "is_self": p.is_self,
                    "is_cls": p.is_cls,
                }
                for p in params
            ],
            "has_docstring": docstring is not None,
            "decorator_names": decorator_names,
            # Alias consumed by ImplementationModel / IntentModel.
            "decorators": decorator_names,
            "body_start": node.body[0].lineno if node.body else node.lineno,
        }
        if docstring:
            properties["docstring"] = docstring

        # Detect endpoint patterns + extract route metadata
        semantic_tags: Set[str] = set()
        for dec in node.decorator_list:
            dec_name = self._decorator_name(dec)
            if self._is_route_decorator(dec_name):
                semantic_tags.add("route")
                semantic_tags.add("endpoint")
                route_info = self._extract_route_info(dec, dec_name)
                if route_info.get("route"):
                    properties.setdefault("route", route_info["route"])
                if route_info.get("method"):
                    properties.setdefault("method", route_info["method"])

        node_type = NodeType.ENDPOINT if "endpoint" in semantic_tags else NodeType.FUNCTION

        return GraphNode(
            node_type=node_type,
            name=node.name,
            file_path=file_path,
            line_range=(node.lineno, node.end_lineno or node.lineno),
            properties=properties,
            semantic_tags=semantic_tags,
        )

    def _visit_class(self, node: ast.ClassDef, file_path: str) -> GraphNode:
        """
        Build a :class:`GraphNode` from an ``ast.ClassDef``.

        Extracts: name, bases, class_type heuristic, methods list.
        """
        bases = [self._resolve_name(b) for b in node.bases]
        class_type = self._detect_class_type(node)
        methods = [
            n.name for n in node.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        docstring = ast.get_docstring(node)
        fields = self._extract_class_fields(node)

        node_type_map = {
            "model": NodeType.MODEL,
            "viewset": NodeType.CLASS,
            "view": NodeType.CLASS,
        }
        node_type = node_type_map.get(class_type, NodeType.CLASS)

        semantic_tags: Set[str] = {f"class_type:{class_type}"}
        if class_type == "model":
            semantic_tags.add("orm_model")

        return GraphNode(
            node_type=node_type,
            name=node.name,
            file_path=file_path,
            line_range=(node.lineno, node.end_lineno or node.lineno),
            properties={
                "bases": bases,
                "class_type": class_type,
                "methods": methods,
                "fields": fields,
                "has_docstring": docstring is not None,
                "decorator_names": [self._decorator_name(d) for d in node.decorator_list],
            },
            semantic_tags=semantic_tags,
        )

    def _extract_class_fields(self, node: ast.ClassDef) -> List[Dict[str, Any]]:
        """
        Extract simple class-level field declarations (ORM-style).

        Handles::

            status = models.CharField(choices=[("pending", ...), ...])
            owner = models.ForeignKey("User")
            balance: float = 0.0
        """
        fields: List[Dict[str, Any]] = []

        for stmt in node.body:
            field_name = ""
            annotation = ""
            value_node: Optional[ast.expr] = None

            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(
                stmt.targets[0], ast.Name
            ):
                field_name = stmt.targets[0].id
                value_node = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                field_name = stmt.target.id
                annotation = self._resolve_name(stmt.annotation)
                value_node = stmt.value
            else:
                continue

            ftype = annotation or (
                self._resolve_name(value_node.func)
                if isinstance(value_node, ast.Call)
                else type(value_node).__name__ if value_node is not None else ""
            )

            field: Dict[str, Any] = {"name": field_name, "type": ftype}

            # choices=[("pending", "Pending"), ...] — ORM enum fields
            if isinstance(value_node, ast.Call):
                for kw in value_node.keywords:
                    if kw.arg == "choices" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        choices: List[Any] = []
                        for elt in kw.value.elts:
                            if isinstance(elt, (ast.List, ast.Tuple)) and elt.elts:
                                first = elt.elts[0]
                                choices.append(
                                    first.value if isinstance(first, ast.Constant) else str(first)
                                )
                            elif isinstance(elt, ast.Constant):
                                choices.append(elt.value)
                        if choices:
                            field["choices"] = choices

            fields.append(field)

        return fields

    def _visit_decorator(
        self, node: ast.expr, file_path: str
    ) -> Optional[GraphNode]:
        """
        Build a :class:`GraphNode` for a decorator, or ``None`` if unresolvable.

        Handles plain names (``@login_required``), attribute access
        (``@decorators.login_required``), and calls with arguments
        (``@permission_required('app.change_order')``).
        """
        name = self._decorator_name(node)
        if not name:
            return None

        args: List[str] = []
        if isinstance(node, ast.Call):
            for arg in node.args:
                args.append(self._resolve_name(arg))
            if node.keywords:
                for kw in node.keywords:
                    args.append(f"{kw.arg}={self._resolve_name(kw.value)}")

        is_auth = self._is_auth_decorator(name)
        semantic_tags: Set[str] = {"decorator"}
        if is_auth:
            semantic_tags.add("auth_decorator")

        return GraphNode(
            node_type=NodeType.DECORATOR,
            name=name,
            file_path=file_path,
            line_range=(node.lineno, node.end_lineno or node.lineno),
            properties={
                "arguments": args,
                "is_auth": is_auth,
                "is_call_decorator": isinstance(node, ast.Call),
            },
            semantic_tags=semantic_tags,
        )

    # ------------------------------------------------------------------
    # Internal extraction helpers
    # ------------------------------------------------------------------

    def _extract_calls(self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> List[_CallInfo]:
        """Walk the function body and return all function-call sites."""
        calls: List[_CallInfo] = []

        for child in ast.walk(func_node):
            if isinstance(child, ast.Call):
                call_info = self._parse_call_node(child)
                if call_info is not None:
                    calls.append(call_info)

        return calls

    def _extract_data_flow(
        self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> List[Dict[str, Any]]:
        """
        Trace which parameters flow to which function-call arguments and
        return statements.  Returns a list of flow descriptors.

        This is a *conservative* static analysis — it tracks names through
        simple assignments but does not follow aliasing through containers.
        """
        params = {p.name for p in self._parse_args(func_node.args) if not p.is_self and not p.is_cls}
        if not params:
            return []

        flows: List[Dict[str, Any]] = []
        # Track simple aliases:  alias -> original parameter name
        aliases: Dict[str, str] = dict((p, p) for p in params)

        for node in ast.walk(func_node):
            # Track simple re-assignments: param = expr
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        src_name = self._resolve_name(node.value)
                        if src_name in aliases:
                            aliases[target.id] = aliases[src_name]

            # param used as positional arg in a call
            if isinstance(node, ast.Call):
                call_name = self._resolve_name(node.func)
                for arg in node.args:
                    arg_name = self._resolve_name(arg)
                    if arg_name in aliases:
                        flows.append({
                            "parameter": aliases[arg_name],
                            "target": call_name,
                            "flow_type": "call_arg",
                            "line": node.lineno,
                        })

                # Keyword args where the value is a parameter
                for kw in node.keywords:
                    kw_val = self._resolve_name(kw.value)
                    if kw_val in aliases:
                        flows.append({
                            "parameter": aliases[kw_val],
                            "target": call_name,
                            "flow_type": "call_kwarg",
                            "keyword": kw.arg,
                            "line": node.lineno,
                        })

            # param returned
            if isinstance(node, ast.Return) and node.value is not None:
                ret_name = self._resolve_name(node.value)
                if ret_name in aliases:
                    flows.append({
                        "parameter": aliases[ret_name],
                        "target": "return",
                        "flow_type": "return",
                        "line": node.lineno,
                    })

        return flows

    def _extract_state_operations(
        self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> List[Dict[str, Any]]:
        """
        Find assignments that look like state-machine transitions.

        A state operation is detected when a variable whose name matches
        ``_STATE_VAR_NAMES`` (or any attribute ending in ``.status`` / ``.state``)
        is the target of an assignment.
        """
        ops: List[Dict[str, Any]] = []

        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    target_name = self._resolve_name(target)
                    state_key = self._state_key_for_target(target, target_name)
                    if state_key:
                        ops.append({
                            "variable": state_key,
                            "new_value": self._resolve_name(node.value),
                            "line": node.lineno,
                            "kind": "assignment",
                        })

        # Augmented assignments (e.g. obj.status += 1) — covered by walk above,
        # but explicitly check AugAssign nodes
        for node in ast.walk(func_node):
            if isinstance(node, ast.AugAssign):
                target_name = self._resolve_name(node.target)
                if self._is_state_variable(target_name):
                    ops.append({
                        "variable": target_name,
                        "operation": self._aug_op_symbol(node.op),
                        "value": self._resolve_name(node.value),
                        "line": node.lineno,
                        "kind": "augmented_assignment",
                    })

        return ops

    # ------------------------------------------------------------------
    # SQL grammar-differential extraction (injection taint)
    # ------------------------------------------------------------------

    _SQL_KEYWORDS = re.compile(
        r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET|UNION|DROP)\b",
        re.IGNORECASE,
    )

    def _extract_sql_taint(
        self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Detect string-constructed SQL (injection surface) and parameterization.

        A taint finding requires BOTH:
          1. a SQL-looking literal (SELECT/INSERT/...), and
          2. an interpolated non-constant value (f-string, concat, %, .format).

        A function is parameterized when it calls ``execute(...)`` /
        ``executemany(...)`` with a second argument (the parameter tuple) —
        the sanitizer in the grammar cascade.
        """
        taints: List[Dict[str, Any]] = []
        parameterized = False

        def _names_in(node: ast.expr) -> List[str]:
            names = []
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name):
                    names.append(sub.id)
                elif isinstance(sub, ast.Attribute):
                    names.append(self._resolve_name(sub))
                elif isinstance(sub, ast.Subscript):
                    names.append(self._resolve_name(sub))
            return [n for n in names if n and not n.startswith(("'", '"'))]

        for node in ast.walk(func_node):
            # f"...{value}..." with SQL keywords
            if isinstance(node, ast.JoinedStr):
                literal = "".join(
                    v.value for v in node.values if isinstance(v, ast.Constant)
                )
                if self._SQL_KEYWORDS.search(literal):
                    interpolated = [
                        name
                        for v in node.values
                        if isinstance(v, ast.FormattedValue)
                        for name in _names_in(v.value)
                    ]
                    if interpolated:
                        taints.append({
                            "kind": "fstring",
                            "detail": f"f-string SQL with interpolation of {interpolated[:4]}",
                            "interpolated": interpolated,
                            "line": node.lineno,
                        })

            # "..." % params  (printf-style)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if self._SQL_KEYWORDS.search(node.left.value):
                        interpolated = _names_in(node.right)
                        taints.append({
                            "kind": "printf",
                            "detail": "printf-style SQL formatting",
                            "interpolated": interpolated,
                            "line": node.lineno,
                        })

            # "SELECT ... " + variable  (concatenation)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left_is_sqlstr = (
                    isinstance(node.left, ast.Constant)
                    and isinstance(node.left.value, str)
                    and bool(self._SQL_KEYWORDS.search(node.left.value))
                )
                right_is_sqlstr = (
                    isinstance(node.right, ast.Constant)
                    and isinstance(node.right.value, str)
                    and bool(self._SQL_KEYWORDS.search(node.right.value))
                )
                if left_is_sqlstr:
                    interpolated = _names_in(node.right)
                    if interpolated:
                        taints.append({
                            "kind": "concat",
                            "detail": "SQL string concatenation",
                            "interpolated": interpolated,
                            "line": node.lineno,
                        })
                elif right_is_sqlstr:
                    interpolated = _names_in(node.left)
                    if interpolated:
                        taints.append({
                            "kind": "concat",
                            "detail": "SQL string concatenation",
                            "interpolated": interpolated,
                            "line": node.lineno,
                        })

            # "...{}...".format(value)
            elif isinstance(node, ast.Call):
                func = node.func
                attr = func.attr.lower() if isinstance(func, ast.Attribute) else ""
                if isinstance(func, ast.Attribute) and attr == "format":
                    base = func.value
                    if isinstance(base, ast.Constant) and isinstance(base.value, str):
                        if self._SQL_KEYWORDS.search(base.value):
                            interpolated = [n for a in node.args for n in _names_in(a)]
                            if interpolated:
                                taints.append({
                                    "kind": "format",
                                    "detail": "str.format SQL construction",
                                    "interpolated": interpolated,
                                    "line": node.lineno,
                                })
                # Parameterization sanitizer: conn.execute(sql, (params,))
                if isinstance(func, ast.Attribute) and attr in {
                    "execute", "executemany",
                }:
                    if len(node.args) >= 2 or node.keywords:
                        parameterized = True

        return taints, parameterized

    @staticmethod
    def _state_key_for_target(target: ast.expr, resolved_name: str) -> str:
        """
        Return the normalized state-variable key for an assignment target,
        or "" if the target is not a state variable.

        Handles the three idioms::

            status = "APPROVED"            -> "status"
            order.status = "APPROVED"      -> "order.status"
            refund["status"] = "APPROVED"  -> "refund.status"
        """
        if PythonParser._is_state_variable(resolved_name):
            return resolved_name
        if isinstance(target, ast.Subscript):
            slice_node = target.slice
            key = ""
            if isinstance(slice_node, ast.Constant) and isinstance(slice_node.value, str):
                key = slice_node.value
            if key in _STATE_VAR_NAMES:
                base = PythonParser._resolve_name(target.value)
                return f"{base}.{key}" if base else key
        return ""

    def _extract_comparisons(
        self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> List[_CompareInfo]:
        """Walk the function body and collect all ``Compare`` nodes."""
        comparisons: List[_CompareInfo] = []

        for node in ast.walk(func_node):
            if isinstance(node, ast.Compare):
                left = self._resolve_name(node.left)
                ops = [self._op_symbol(op) for op in node.ops]
                comparators = [self._resolve_name(c) for c in node.comparators]
                comparisons.append(_CompareInfo(
                    left=left,
                    ops=ops,
                    comparators=comparators,
                    line=node.lineno,
                ))

        return comparisons

    # ------------------------------------------------------------------
    # Inline authorization-check extraction
    # ------------------------------------------------------------------

    def _extract_auth_checks(
        self, func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> List[Dict[str, Any]]:
        """
        Detect inline authorization guards within a function body.

        Recognized idioms:

        1. Attribute/key guards — ``if not user.is_admin: ...``,
           ``user.get("role") == "admin"``, ``if not is_staff:``
        2. Guard-by-exception — ``raise PermissionError(...)``,
           ``raise HTTPException(status_code=403)``, ``abort(403)``
        3. Auth predicate calls — ``has_permission(...)``, ``check_role(...)``

        Returns a list of records: ``{"kind", "detail", "line"}``.
        """
        checks: List[Dict[str, Any]] = []

        for node in ast.walk(func_node):
            # If gates whose test mentions an auth attribute / predicate call
            if isinstance(node, ast.If):
                guard = self._classify_guard_expression(node.test)
                if guard:
                    checks.append({
                        "kind": guard,
                        "detail": self._resolve_name(node.test) if isinstance(node.test, ast.Name) else ast.dump(node.test)[:160],
                        "line": node.lineno,
                    })
                    continue  # don't double-count nested compares below

            # Explicit auth exceptions
            if isinstance(node, ast.Raise):
                exc_name = self._resolve_name(node.exc) if node.exc else ""
                exc_leaf = exc_name.split(".")[-1].rstrip("()")
                if exc_leaf in _AUTH_EXCEPTION_NAMES:
                    checks.append({
                        "kind": "auth_raise",
                        "detail": f"raise {exc_name}",
                        "line": node.lineno,
                    })

            # abort(403) / abort(401) — Flask guard idiom
            if isinstance(node, ast.Call):
                call_name = self._resolve_name(node.func)
                if call_name.split(".")[-1] == "abort":
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and arg.value in (401, 403):
                            checks.append({
                                "kind": "auth_abort",
                                "detail": f"abort({arg.value})",
                                "line": node.lineno,
                            })

            # Return of HTTP 401/403 — guard-by-response
            if isinstance(node, ast.Return) and node.value is not None:
                ret_text = self._resolve_name(node.value)
                if isinstance(node.value, ast.Constant) and node.value.value in (401, 403):
                    checks.append({
                        "kind": "auth_response",
                        "detail": f"return {ret_text}",
                        "line": node.lineno,
                    })

        return checks

    def _classify_guard_expression(self, test: ast.expr) -> str:
        """
        Classify an ``if`` test: ``"auth_attribute"``, ``"auth_call"``,
        ``"auth_compare"`` or ``""`` (no auth signal).

        Pure AST analysis — identifiers resolved via symbol table, substrings
        only applied to the leaf name of an attribute chain.
        """
        names: Set[str] = set()
        calls: Set[str] = set()
        has_compare = False

        for sub in ast.walk(test):
            if isinstance(sub, ast.Name):
                names.add(sub.id.lower())
            elif isinstance(sub, ast.Attribute):
                names.add(sub.attr.lower())
            elif isinstance(sub, ast.Call):
                leaf = self._resolve_name(sub.func).split(".")[-1].lower()
                calls.add(leaf)
                # .get("is_admin") — dict-style attribute access
                for arg in sub.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        names.add(arg.value.lower())
                for kw in sub.keywords:
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        names.add(kw.value.value.lower())
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                names.add(sub.value.lower())
            elif isinstance(sub, ast.Compare):
                has_compare = True

        if names & _AUTH_ATTRIBUTE_NAMES:
            return "auth_compare" if has_compare else "auth_attribute"

        auth_predicates = {
            "has_perm", "has_permission", "check_permission", "check_perms",
            "check_role", "require_role", "is_authorized", "authorize",
            "verify_permission", "ensure_admin", "check_auth", "require_permission",
            "user_passes_test",
        }
        if calls & auth_predicates:
            return "auth_call"

        return ""

    def _build_body_records(
        self,
        func_node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        comparisons: List[_CompareInfo],
        auth_checks: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Build the structural ``body_nodes`` records consumed by the
        ImplementationModel.  Each record is a small dict describing one
        security-relevant body element (comparisons, auth gates, raises).
        """
        records: List[Dict[str, Any]] = []
        for comp in comparisons:
            records.append({
                "node_type": "Compare",
                "left": comp.left,
                "ops": comp.ops,
                "comparators": comp.comparators,
                "line": comp.line,
            })
        for check in auth_checks:
            records.append({
                "node_type": "AuthCheck",
                "kind": check["kind"],
                "detail": check["detail"],
                "line": check["line"],
            })
        return records

    def _extract_route_info(self, dec: ast.expr, dec_name: str) -> Dict[str, str]:
        """
        Extract ``route`` path and HTTP ``method`` from a routing decorator.

        Handles::

            @app.route("/orders/<int:order_id>", methods=["DELETE"])
            @router.get("/users/{user_id}")
            @app.delete("/items/{item_id}")
        """
        info: Dict[str, str] = {}
        leaf = dec_name.split(".")[-1].rstrip("()").lower()

        # Verb-style decorators encode the method in their name.
        verb_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        if leaf in verb_methods:
            info["method"] = leaf.upper()

        if isinstance(dec, ast.Call):
            # First string positional arg is the route path.
            for arg in dec.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("/"):
                        info.setdefault("route", arg.value)
                        break
            for kw in dec.keywords:
                if kw.arg in ("rule", "path", "url"):
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        info.setdefault("route", kw.value.value)
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            info.setdefault("method", elt.value.upper())
                            break
        return info

    # ------------------------------------------------------------------
    # Class-type detection
    # ------------------------------------------------------------------

    def _detect_class_type(self, class_node: ast.ClassDef) -> str:
        """
        Infer whether a class is a *model*, *viewset*, *view*, or generic
        *class* based on its base classes and decorators.

        Returns one of: ``"model"``, ``"viewset"``, ``"view"``, ``"class"``.
        """
        bases = [self._resolve_name(b) for b in class_node.bases]

        # Check decorators first (e.g. @register on model-like classes)
        for dec in class_node.decorator_list:
            dec_name = self._decorator_name(dec)
            if dec_name in ("register", "model", "table"):
                return "model"

        # Check bases against known sets
        for base in bases:
            base_simple = base.split(".")[-1]
            full_base = base
            if base_simple in {b.split(".")[-1] for b in _MODEL_BASES} or full_base in _MODEL_BASES:
                return "model"
            if base_simple in {b.split(".")[-1] for b in _VIEWSET_BASES} or full_base in _VIEWSET_BASES:
                return "viewset"
            if base_simple in {b.split(".")[-1] for b in _VIEW_BASES} or full_base in _VIEW_BASES:
                return "view"

        # Check framework hints
        hint_models = self._hints.get("model_bases", set())
        hint_views = self._hints.get("view_bases", set())
        hint_viewsets = self._hints.get("viewset_bases", set())
        for base in bases:
            if base in hint_models or base.split(".")[-1] in hint_models:
                return "model"
            if base in hint_viewsets or base.split(".")[-1] in hint_viewsets:
                return "viewset"
            if base in hint_views or base.split(".")[-1] in hint_views:
                return "view"

        # Heuristic: classes with a Meta subclass containing managed = True / db_table
        for item in class_node.body:
            if isinstance(item, ast.ClassDef) and item.name == "Meta":
                for stmt in item.body:
                    if isinstance(stmt, ast.Assign):
                        for target in stmt.targets:
                            if isinstance(target, ast.Name) and target.id == "managed":
                                return "model"
                            if isinstance(target, ast.Name) and target.id == "db_table":
                                return "model"

        return "class"

    # ------------------------------------------------------------------
    # Low-level AST helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_args(args: ast.arguments) -> List[_ParamInfo]:
        """Parse an ``ast.arguments`` node into a list of ``_ParamInfo``."""
        result: List[_ParamInfo] = []

        # posonlyargs (Python 3.8+)
        for arg in getattr(args, "posonlyargs", []):
            result.append(_ParamInfo(
                name=arg.arg,
                annotation=PythonParser._annotation_str(arg.annotation),
            ))

        # Regular args
        for arg in args.args:
            result.append(_ParamInfo(
                name=arg.arg,
                annotation=PythonParser._annotation_str(arg.annotation),
                is_self=(arg.arg == "self"),
                is_cls=(arg.arg == "cls"),
            ))

        # *args
        if args.vararg:
            result.append(_ParamInfo(
                name=args.vararg.arg,
                annotation=PythonParser._annotation_str(args.vararg.annotation),
                is_variadic=True,
            ))

        # Keyword-only args
        for arg in args.kwonlyargs:
            result.append(_ParamInfo(
                name=arg.arg,
                annotation=PythonParser._annotation_str(arg.annotation),
                is_kw_only=True,
            ))

        # **kwargs
        if args.kwarg:
            result.append(_ParamInfo(
                name=args.kwarg.arg,
                annotation=PythonParser._annotation_str(args.kwarg.annotation),
            ))

        # Attach defaults — defaults align to the *last* N positional args
        defaults = args.defaults
        kw_defaults = args.kw_defaults
        pos_params = [p for p in result if not p.is_variadic and not p.is_kw_only]
        offset = len(pos_params) - len(defaults)
        for i, default_node in enumerate(defaults):
            idx = offset + i
            if 0 <= idx < len(pos_params):
                pos_params[idx].default_value = PythonParser._literal_str(default_node)

        # kw_defaults
        kw_params = [p for p in result if p.is_kw_only]
        for i, kd in enumerate(kw_defaults):
            if i < len(kw_params) and kd is not None:
                kw_params[i].default_value = PythonParser._literal_str(kd)

        return result

    def _parse_call_node(self, node: ast.Call) -> Optional[_CallInfo]:
        """Extract call metadata from an ``ast.Call`` node."""
        name = self._resolve_name(node.func)
        if not name:
            return None

        is_method = isinstance(node.func, ast.Attribute)
        obj_name = ""
        if is_method:
            obj_name = self._resolve_name(node.func.value)

        arg_strs = [self._resolve_name(a) for a in node.args]
        for kw in node.keywords:
            arg_strs.append(f"{kw.arg}={self._resolve_name(kw.value)}")

        return _CallInfo(
            name=name,
            line=node.lineno,
            col=node.col_offset,
            args=arg_strs,
            is_method_call=is_method,
            object_name=obj_name,
        )

    @staticmethod
    def _resolve_name(node: ast.expr) -> str:
        """
        Produce a human-readable dotted name from an AST expression node.

        Handles ``Name``, ``Attribute``, ``Call`` (returns callee name),
        ``Constant``, ``Subscript``, ``Starred``, ``Tuple``, ``List``, and
        falls back to ``<expr>`` for anything else.
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = PythonParser._resolve_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return PythonParser._resolve_name(node.func) + "()"
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return repr(node.value)
            return repr(node.value)
        if isinstance(node, ast.Subscript):
            val = PythonParser._resolve_name(node.value)
            sl = PythonParser._resolve_name(node.slice)
            return f"{val}[{sl}]"
        if isinstance(node, ast.Starred):
            return f"*{PythonParser._resolve_name(node.value)}"
        if isinstance(node, (ast.List, ast.Tuple)):
            elts = ", ".join(PythonParser._resolve_name(e) for e in node.elts)
            if isinstance(node, ast.List):
                return f"[{elts}]"
            return f"({elts})"
        if isinstance(node, ast.IfExp):
            return "<ifexpr>"
        if isinstance(node, ast.Lambda):
            return "<lambda>"
        return "<expr>"

    @staticmethod
    def _annotation_str(annotation: Optional[ast.expr]) -> str:
        """Return a readable string for a type annotation, or empty string."""
        if annotation is None:
            return ""
        return PythonParser._resolve_name(annotation)

    @staticmethod
    def _literal_str(node: ast.expr) -> str:
        """Return a readable string for a default value."""
        if isinstance(node, ast.Constant):
            return repr(node.value)
        return PythonParser._resolve_name(node)

    @staticmethod
    def _op_symbol(op: ast.AST) -> str:
        """Map an ``ast`` comparison operator to its string symbol."""
        op_map = {
            ast.Eq: "==",
            ast.NotEq: "!=",
            ast.Lt: "<",
            ast.LtE: "<=",
            ast.Gt: ">",
            ast.GtE: ">=",
            ast.Is: "is",
            ast.IsNot: "is not",
            ast.In: "in",
            ast.NotIn: "not in",
        }
        return op_map.get(type(op), "??")

    @staticmethod
    def _aug_op_symbol(op: ast.AST) -> str:
        """Map an ``ast`` augmented-assignment operator to its string symbol."""
        op_map = {
            ast.Add: "+=",
            ast.Sub: "-=",
            ast.Mult: "*=",
            ast.Div: "/=",
            ast.FloorDiv: "//=",
            ast.Mod: "%=",
            ast.Pow: "**=",
            ast.BitAnd: "&=",
            ast.BitOr: "|=",
            ast.BitXor: "^=",
        }
        return op_map.get(type(op), "??")

    @staticmethod
    def _decorator_name(node: ast.expr) -> str:
        """Extract the fully-qualified decorator name from an AST node."""
        return PythonParser._resolve_name(node)

    @staticmethod
    def _is_auth_decorator(name: str) -> bool:
        """Return ``True`` if *name* looks like an auth / permission decorator."""
        leaf = name.split(".")[-1].rstrip("()")
        if leaf in _AUTH_DECORATORS:
            return True
        # Check full-qualified names
        for prefix in _AUTH_MODULE_PREFIXES:
            if name.startswith(prefix) or f"{prefix}.{leaf}" == name:
                return True
        # Keyword heuristics
        lower = leaf.lower()
        return any(kw in lower for kw in ("login", "auth", "permission", "require"))

    @staticmethod
    def _is_route_decorator(name: str) -> bool:
        """Return ``True`` if *name* looks like a routing decorator."""
        leaf = name.split(".")[-1].rstrip("()")
        return leaf in {
            "route",
            "api_view",
            "action",
            "app_route",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "url",
            "endpoint",
        }

    @staticmethod
    def _is_state_variable(name: str) -> bool:
        """Return ``True`` if *name* looks like a state / status variable."""
        # Direct match on well-known names
        if name in _STATE_VAR_NAMES:
            return True
        # Attribute access like obj.status or self.state
        parts = name.split(".")
        if len(parts) >= 2 and parts[-1] in _STATE_VAR_NAMES:
            return True
        return False

    @staticmethod
    def _looks_like_ownership_check(comp: _CompareInfo) -> bool:
        """
        Heuristic: an ownership check compares an ``.owner`` / ``.user_id``
        attribute against the requestor identity (``request.user``,
        ``current_user['id']``, ``session.user``...).

        Both ``==`` (assert-style) and ``!=`` (guard-by-exception) count —
        what matters is that the resource owner is compared to the caller:

            order["owner"] != current_user["id"]  -> raise  (guard)
            order.owner == request.user                        (assertion)
        """
        if not ({"==", "!="} & set(comp.ops)):
            return False

        sides = [comp.left.lower(), *(c.lower() for c in comp.comparators)]

        def _side_tokens(side: str) -> Set[str]:
            # Split on attribute/subscript boundaries and match whole tokens
            # so `username` does not masquerade as `user`.
            tokens = set(re.split(r"[\.\[\]\(\)'\s\"]+", side))
            tokens.discard("")
            return tokens

        side_tokens = [_side_tokens(s) for s in sides]
        for i in range(len(sides)):
            for j in range(len(sides)):
                if i == j:
                    continue
                if (side_tokens[i] & _OWNERSHIP_TOKENS) and (
                    side_tokens[j] & _IDENTITY_TOKENS
                ):
                    return True
        return False

    # ------------------------------------------------------------------
    # File node helper
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_file_node(file_path: str, graph: SemanticGraph) -> Optional[str]:
        """Create a FILE node for *file_path* if one doesn't exist yet."""
        existing = graph.find_nodes_in_file(file_path)
        for n in existing:
            if n.node_type == NodeType.FILE:
                return n.id
        node = GraphNode(
            node_type=NodeType.FILE,
            name=file_path,
            file_path=file_path,
            properties={},
            semantic_tags={"source_file"},
        )
        return graph.add_node(node)
