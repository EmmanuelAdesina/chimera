"""GraphQL intent versus resolver implementation analysis.

The parser deliberately uses a small, dependency-free schema reader.  It is
not a GraphQL validator; it extracts directive contracts that can be compared
with Python resolver ASTs.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, List

from chimera.models import Evidence, EvidenceSource, EvidenceType


class GraphQLCausalParser:
    """Build directive contracts and report missing resolver checks."""

    _TYPE_RE = re.compile(r"\btype\s+(\w+)[^{]*\{(.*?)\}", re.DOTALL)
    _FIELD_RE = re.compile(r"^\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*[\[\]!\w]+(?P<dirs>[^\n]*)")
    _DIRECTIVE_RE = re.compile(r"@(\w+)")

    def __init__(self) -> None:
        self.schema_directives: Dict[str, List[str]] = {}
        self.resolver_implementations: Dict[str, ast.AST] = {}

    def parse_schema(self, schema_content: str) -> Dict[str, List[str]]:
        """Extract field directives from ``type`` blocks."""
        for type_match in self._TYPE_RE.finditer(schema_content):
            type_name, body = type_match.groups()
            for line in body.splitlines():
                field_match = self._FIELD_RE.match(line)
                if not field_match:
                    continue
                directives = self._DIRECTIVE_RE.findall(field_match.group("dirs"))
                if directives:
                    self.schema_directives[f"{type_name}.{field_match.group(1)}"] = directives
        return self.schema_directives

    def parse_resolvers(self, ast_tree: ast.AST) -> Dict[str, ast.AST]:
        """Index resolver functions using ``Type_field_resolver`` naming."""
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.endswith("_resolver"):
                key = node.name[: -len("_resolver")].replace("_", ".", 1)
                self.resolver_implementations[key] = node
        return self.resolver_implementations

    def generate_contradictions(self) -> List[Evidence]:
        """Return evidence for protected fields whose resolver has no auth call."""
        findings: List[Evidence] = []
        for field_key, directives in self.schema_directives.items():
            if not {"auth", "hasRole", "requiresAuth"}.intersection(directives):
                continue
            resolver = self.resolver_implementations.get(field_key)
            if resolver is None:
                continue
            calls = {n.func.id for n in ast.walk(resolver) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
            if not {"check_auth", "verify_token", "authorize", "require_auth"}.intersection(calls):
                findings.append(Evidence(
                    source=EvidenceSource.STATIC_ANALYSIS,
                    evidence_type=EvidenceType.DATA_FLOW,
                    data={"field": field_key, "directives": directives},
                    confidence=0.95,
                    description=f"Schema mandates {directives} for {field_key}, but its resolver has no authorization check.",
                ))
        return findings
