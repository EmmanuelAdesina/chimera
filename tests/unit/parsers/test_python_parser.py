"""Unit tests for the AST-based Python parser."""

from __future__ import annotations

import pytest

from chimera.core.semantic_graph import NodeType, SemanticGraph
from chimera.parsers.errors import ParseError
from chimera.parsers.languages.python_parser import PythonParser


class TestParserAPI:
    def test_name_attribute(self):
        assert PythonParser().name == "python_ast"

    def test_extensions(self):
        assert ".py" in PythonParser().extensions


class TestRobustness:
    def test_none_graph_creates_own(self):
        p = PythonParser()
        p.parse("a.py", "x = 1\n", None)
        assert isinstance(p.graph, SemanticGraph)

    def test_none_source_returns_empty(self):
        assert PythonParser().parse("a.py", None, None) == []

    def test_blank_source_returns_empty(self):
        assert PythonParser().parse("a.py", "   \n\t\n", None) == []

    def test_malformed_syntax_raises_parse_error_with_context(self):
        p = PythonParser()
        with pytest.raises(ParseError) as excinfo:
            p.parse("broken.py", "def broken(:\n    pass\n", None)
        err = excinfo.value
        assert err.file_path == "broken.py"
        assert err.line == 1
        assert "broken" in str(err) and "broken.py:1" in str(err)

    def test_utf8_bom_is_tolerated(self):
        p = PythonParser()
        evidence = p.parse("bom.py", "\ufeffx = 1\n", None)
        assert isinstance(evidence, list)  # no SyntaxError from U+FEFF


class TestFunctionExtraction:
    def test_function_node_created(self, graph):
        p = PythonParser()
        p.parse("m.py", "def hello(a, b=1):\n    return a\n", graph)
        fns = graph.find_nodes_by_type(NodeType.FUNCTION)
        names = [f.name for f in fns]
        assert "hello" in names

    def test_parameters_extracted(self, graph):
        p = PythonParser()
        p.parse("m.py", "def f(order_id: int, current_user):\n    pass\n", graph)
        fn = next(n for n in graph.nodes.values() if n.name == "f")
        names = [prm["name"] for prm in fn.properties["parameters"]]
        assert names == ["order_id", "current_user"]

    def test_ownership_check_detected_guard_by_exception(self, graph):
        """order['owner'] != current_user['id'] -> PermissionError is a guard."""
        src = (
            "def get_order(order_id, current_user):\n"
            "    order = ORDERS[order_id]\n"
            "    if order[\"owner\"] != current_user[\"id\"]:\n"
            "        raise PermissionError(\"no\")\n"
            "    return order\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "get_order")
        assert "ownership_check" in fn.semantic_tags

    def test_inline_auth_check_detected(self, graph):
        src = (
            "def admin_area(current_user):\n"
            "    if not current_user.get(\"is_admin\"):\n"
            "        raise PermissionError(\"admin\")\n"
            "    return 1\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "admin_area")
        checks = fn.properties.get("auth_checks", [])
        assert checks, "expected inline auth checks to be recorded"
        assert "auth_checked" in fn.semantic_tags
        kinds = {c["kind"] for c in checks}
        assert kinds & {"auth_attribute", "auth_compare", "auth_call", "auth_raise"}

    def test_raise_permission_error_alone_counts(self, graph):
        src = (
            "def f(user):\n"
            "    if not user.is_staff:\n"
            "        raise PermissionError\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "f")
        assert fn.properties.get("auth_checks")

    def test_no_auth_check_on_plain_function(self, graph):
        p = PythonParser()
        p.parse("m.py", "def add(a, b):\n    return a + b\n", graph)
        fn = next(n for n in graph.nodes.values() if n.name == "add")
        assert not fn.properties.get("auth_checks")
        assert "ownership_check" not in fn.semantic_tags

    def test_ownership_check_not_false_positive_on_username(self, graph):
        """`username == other` must not be read as an ownership guard."""
        src = (
            "def greet(username, other):\n"
            "    if username == other:\n"
            "        return True\n"
            "    return False\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "greet")
        assert "ownership_check" not in fn.semantic_tags

    def test_route_extraction(self, graph):
        src = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route(\"/orders/<int:order_id>\", methods=[\"DELETE\"])\n"
            "def delete_order(order_id):\n"
            "    return \"ok\"\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "delete_order")
        assert fn.node_type == NodeType.ENDPOINT
        assert fn.properties.get("route") == "/orders/<int:order_id>"
        assert fn.properties.get("method") == "DELETE"

    def test_body_nodes_populated(self, graph):
        src = (
            "def f(order_id, current_user):\n"
            "    if order_id == current_user[\"last\"]:\n"
            "        return 1\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "f")
        body = fn.properties.get("body_nodes", [])
        assert any(b.get("node_type") == "Compare" for b in body)


class TestClassExtraction:
    def test_model_fields_with_choices(self, graph):
        src = (
            "class Order(Model):\n"
            "    status = CharField(choices=[(\"pending\", \"Pending\"), (\"approved\", \"Approved\")])\n"
            "    owner = ForeignKey(\"User\")\n"
        )
        p = PythonParser()
        p.parse("models.py", src, graph)
        cls = next(n for n in graph.nodes.values() if n.name == "Order")
        assert cls.properties.get("class_type") == "model"
        fields = {f["name"]: f for f in cls.properties.get("fields", [])}
        assert "status" in fields and "owner" in fields
        assert fields["status"].get("choices") == ["pending", "approved"]

    def test_state_subscript_assignment(self, graph):
        src = (
            "def approve(refund_id):\n"
            "    refund = REFUNDS[refund_id]\n"
            "    refund[\"status\"] = \"APPROVED\"\n"
        )
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "approve")
        ops = fn.properties.get("state_operations", [])
        assert ops, "expected subscript state assignment to be captured"
        assert any(op["variable"].endswith("status") for op in ops)

    def test_state_attribute_assignment(self, graph):
        src = "def ship(order):\n    order.status = \"SHIPPED\"\n"
        p = PythonParser()
        p.parse("m.py", src, graph)
        fn = next(n for n in graph.nodes.values() if n.name == "ship")
        ops = fn.properties.get("state_operations", [])
        assert ops and ops[0]["variable"] == "order.status"
