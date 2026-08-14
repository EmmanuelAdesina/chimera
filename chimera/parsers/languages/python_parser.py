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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

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

    def __init__(self, framework_hints: Optional[Dict[str, Set[str]]] = None) -> None:
        self._hints = framework_hints or {}
        self._evidence: List[Evidence] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, file_path: str, source: str, graph: SemanticGraph) -> List[Evidence]:
        """
        Parse *source* (Python source text from *file_path*) and populate *graph*.

        Returns a list of :class:`Evidence` objects collected during parsing.

        Raises
        ------
        SyntaxError
            If the source cannot be parsed by the ``ast`` module.
        """
        self._evidence.clear()
        tree = ast.parse(source, filename=file_path)

        # Walk top-level statements
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                self._process_function(node, file_path, graph)
            elif isinstance(node, ast.ClassDef):
                self._process_class(node, file_path, graph)
            elif isinstance(node, ast.Import):
                self._process_import(node, file_path, graph)
            elif isinstance(node, ast.ImportFrom):
                self._process_import_from(node, file_path, graph)

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
            "decorator_names": [self._decorator_name(d) for d in node.decorator_list],
            "body_start": node.body[0].lineno if node.body else node.lineno,
        }
        if docstring:
            properties["docstring"] = docstring

        # Detect endpoint patterns
        semantic_tags: Set[str] = set()
        for dec in node.decorator_list:
            dec_name = self._decorator_name(dec)
            if self._is_route_decorator(dec_name):
                semantic_tags.add("route")
                semantic_tags.add("endpoint")

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
                "has_docstring": docstring is not None,
                "decorator_names": [self._decorator_name(d) for d in node.decorator_list],
            },
            semantic_tags=semantic_tags,
        )

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
                    if self._is_state_variable(target_name):
                        ops.append({
                            "variable": target_name,
                            "new_value": self._resolve_name(node.value),
                            "line": node.lineno,
                            "kind": "assignment",
                        })
            elif isinstance(node, ast.Attribute):
                # Also catch method calls like order.approve() — these are
                # handled via _extract_calls, but we tag them as state ops here.
                pass

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
        Heuristic: an ownership check compares an ``.owner`` or ``.user``
        attribute against ``request.user`` (or similar).
        """
        left_lower = comp.left.lower()
        for comparator in comp.comparators:
            comp_lower = comparator.lower()
            # obj.user == request.user  /  obj.owner == self.request.user
            has_owner_attr = (".user" in left_lower or ".owner" in left_lower
                              or ".user" in comp_lower or ".owner" in comp_lower)
            has_request = "request" in left_lower or "request" in comp_lower
            if has_owner_attr and has_request and "==" in comp.ops:
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
