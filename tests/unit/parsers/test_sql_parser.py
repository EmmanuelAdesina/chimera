"""Unit tests for the regex-based SQL DDL parser."""

from __future__ import annotations

from chimera.core.semantic_graph import EdgeType, NodeType, SemanticGraph
from chimera.parsers.languages.sql_parser import SQLParser


SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE
);

CREATE TABLE orgs (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE memberships (
    user_id INTEGER NOT NULL,
    org_id INTEGER NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT uq_pair UNIQUE (user_id, org_id),
    CHECK (user_id > 0)
);
"""


class TestRobustness:
    def test_none_graph_creates_own(self):
        p = SQLParser()
        p.parse("s.sql", "CREATE TABLE t (id INT);", None)
        assert isinstance(p.graph, SemanticGraph)
        assert p.graph.find_nodes_by_type(NodeType.DATABASE_TABLE)

    def test_none_source_returns_empty(self):
        assert SQLParser().parse("s.sql", None, None) == []

    def test_garbage_does_not_raise(self):
        assert SQLParser().parse("s.sql", "THIS IS NOT SQL (((", None) == []

    def test_partial_statement_does_not_raise(self):
        p = SQLParser()
        result = p.parse("s.sql", "CREATE TABLE broken (id INT", None)
        assert isinstance(result, list)


class TestExtraction:
    def test_tables_created(self):
        p = SQLParser()
        p.parse("schema.sql", SCHEMA, None)
        tables = {n.name for n in p.graph.find_nodes_by_type(NodeType.DATABASE_TABLE)}
        assert {"users", "orgs", "memberships"} <= tables

    def test_foreign_key_edges(self):
        p = SQLParser()
        p.parse("schema.sql", SCHEMA, None)
        fk_edges = [
            e for e in p.graph.edges.values()
            if e.edge_type == EdgeType.DEPENDS_ON
            and e.properties.get("relationship") == "foreign_key"
        ]
        pairs = set()
        for e in fk_edges:
            src = p.graph.get_node(e.source_id).name
            dst = p.graph.get_node(e.target_id).name
            pairs.add((src, dst))
        assert ("users", "orgs") in pairs
        assert ("memberships", "users") in pairs

    def test_column_constraints(self):
        p = SQLParser()
        p.parse("schema.sql", SCHEMA, None)
        users = next(n for n in p.graph.nodes.values() if n.name == "users")
        cols = {c["name"]: c for c in users.properties["columns"]}
        assert cols["email"]["not_null"] is True
        assert cols["email"]["is_unique"] is True
        assert cols["id"]["is_primary_key"] is True

    def test_unique_and_check_constraints(self):
        p = SQLParser()
        p.parse("schema.sql", SCHEMA, None)
        memberships = next(n for n in p.graph.nodes.values() if n.name == "memberships")
        assert memberships.properties["unique_constraints"]
        assert memberships.properties["check_constraints"]

    def test_evidence_produced(self):
        p = SQLParser()
        evidence = p.parse("schema.sql", SCHEMA, None)
        assert len(evidence) == 3  # one per CREATE TABLE
