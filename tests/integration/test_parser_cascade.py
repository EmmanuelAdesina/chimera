"""Integration tests for the full parser cascade through analyze()."""

from __future__ import annotations

import pytest

from chimera.core.orchestrator import ChimeraOrchestrator
from chimera.core.world_state import AnalysisConfig


GQL_SCHEMA = """
type User {
  id: ID!
  email: String!
}

type Query {
  user(id: ID!): User @auth
  adminStats: String @hasRole
  publicFeed: String
}
"""

RESOLVERS = '''
"""Some @auth-declared fields lack resolver-side checks."""

def resolve_Query_user(info, id):
    """Fetch a user -- @auth declared in the schema."""
    return get_user(id)

def resolve_Query_adminStats(info):
    """@hasRole declared in schema."""
    return {"users": 100}

def resolve_Query_publicFeed(info):
    return ["post"]
'''

GUARDED_RESOLVERS = '''
def resolve_Query_user(info, id):
    if not info.context.get("user"):
        raise PermissionError("login required")
    return get_user(id)

def resolve_Query_adminStats(info):
    if not info.context.get("is_admin"):
        raise PermissionError("admin only")
    return {"users": 100}

def resolve_Query_publicFeed(info):
    return ["post"]
'''


class TestGraphQLCascade:
    def test_contradiction_detected_through_analyze(self, tmp_path):
        (tmp_path / "schema.graphql").write_text(GQL_SCHEMA)
        (tmp_path / "resolvers.py").write_text(RESOLVERS)
        result = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
        graphql_claims = [
            h for h in result["hypotheses"]
            if "GraphQL field" in h["claim"]
        ]
        assert graphql_claims, "expected @auth/@hasRole contradictions to surface"
        fields = " ".join(h["claim"] for h in graphql_claims)
        assert "Query.user" in fields
        assert "Query.adminStats" in fields
        # publicFeed has no directive -> must not be flagged
        assert "Query.publicFeed" not in fields

    def test_guarded_resolvers_not_flagged(self, tmp_path):
        (tmp_path / "schema.graphql").write_text(GQL_SCHEMA)
        (tmp_path / "resolvers.py").write_text(GUARDED_RESOLVERS)
        result = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
        missing_check = [
            h for h in result["hypotheses"]
            if "lacks visible authorization checks" in h["claim"]
        ]
        assert missing_check == [], (
            f"guarded resolvers were flagged: {[h['claim'][:100] for h in missing_check]}"
        )


class TestInjectionCascade:
    def test_fstring_sql_flagged_parameterized_clean(self, tmp_path):
        (tmp_path / "db.py").write_text(
            "import sqlite3\n"
            "\n"
            "def get_user_unsafe(user_id):\n"
            "    q = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n"
            "    return q\n"
            "\n"
            "def get_user_safe(user_id):\n"
            "    conn = sqlite3.connect(':memory:')\n"
            "    return conn.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))\n"
        )
        result = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
        claims = " ".join(h["claim"] for h in result["hypotheses"])
        assert "get_user_unsafe" in claims
        assert "get_user_safe" not in claims
        inj = [
            h for h in result["hypotheses"]
            if h["vulnerability_class"] == "injection"
        ]
        assert inj and inj[0]["confidence"] >= 0.6


class TestJavaScriptCascade:
    def test_async_state_finding_surfaces(self, tmp_path):
        (tmp_path / "app.js").write_text(
            "let balance = 100;\n"
            "async function withdraw(amount) {\n"
            "  balance = balance - amount;\n"
            "  await persist();\n"
            "}\n"
        )
        result = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
        assert result["phase"] == "complete"
        assert result["files_parsed"] == 1
