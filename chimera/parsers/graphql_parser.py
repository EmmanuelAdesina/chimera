"""
GraphQL parser for intent-vs-implementation reasoning.

Extracts:
- schema field contracts
- directives such as @auth, @hasRole, @rateLimit
- resolver naming conventions
- contradictions where declared intent is not visible in resolver implementation
"""

from __future__ import annotations

import ast
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


@dataclass
class GraphQLFieldContract:
    type_name: str
    field_name: str
    return_type: str = ""
    directives: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.type_name}.{self.field_name}"


class GraphQLCausalParser:
    directive_pattern = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)")
    type_block_pattern = re.compile(
        r"(?:type|extend\s+type)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:[^{]*)\{(?P<body>.*?)\}",
        re.DOTALL,
    )
    field_pattern = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:\s*([^@\n]+?)"
        r"(?P<directives>(?:\s+@[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)*)\s*(?:#.*)?$",
        re.MULTILINE,
    )

    auth_markers = {
        "auth",
        "authenticated",
        "hasRole",
        "requiresRole",
        "permission",
        "requiresPermission",
        "rateLimit",
    }

    implementation_auth_terms = {
        "check_auth",
        "authorize",
        "authorization",
        "permission",
        "has_role",
        "require_role",
        "verify_token",
        "is_authenticated",
        "current_user",
        "jwt",
        "session",
    }

    def parse_schema(self, schema_content: str) -> Dict[str, GraphQLFieldContract]:
        contracts: Dict[str, GraphQLFieldContract] = {}

        for type_match in self.type_block_pattern.finditer(schema_content):
            type_name = type_match.group(1)
            body = type_match.group("body")

            for field_match in self.field_pattern.finditer(body):
                field_name = field_match.group(1)
                return_type = field_match.group(2).strip()
                directive_blob = field_match.group("directives") or ""
                directives = self.directive_pattern.findall(directive_blob)

                contract = GraphQLFieldContract(
                    type_name=type_name,
                    field_name=field_name,
                    return_type=return_type,
                    directives=directives,
                )
                contracts[contract.key] = contract

        return contracts

    def map_python_resolvers(self, tree: ast.AST) -> Dict[str, ast.AST]:
        """
        Map Python resolver function names to GraphQL Type.field keys.

        Supported conventions:
        - resolve_User_email
        - User_email_resolver
        - user_email_resolver
        - resolve_email on classes named UserResolver or User
        """
        resolvers: Dict[str, ast.AST] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                key = self._resolver_key_from_function(node.name)
                if key:
                    resolvers[key] = node

            if isinstance(node, ast.ClassDef):
                type_name = node.name.replace("Resolver", "")
                for child in node.body:
                    if isinstance(child, ast.FunctionDef) and child.name.startswith("resolve_"):
                        field = child.name.replace("resolve_", "", 1)
                        resolvers[f"{type_name}.{field}"] = child

        return resolvers

    def find_contradictions(
        self,
        contracts: Dict[str, GraphQLFieldContract],
        resolvers: Dict[str, ast.AST],
    ) -> List[Evidence]:
        evidence: List[Evidence] = []

        for key, contract in contracts.items():
            guarded = any(d in self.auth_markers for d in contract.directives)
            if not guarded:
                continue

            resolver = resolvers.get(key)
            if resolver is None:
                evidence.append(self._evidence(
                    key=key,
                    description=f"GraphQL field {key} declares security directives {contract.directives}, but no resolver mapping was found.",
                    data={"contract": contract.__dict__, "contradiction": "missing_resolver"},
                    confidence=0.7,
                ))
                continue

            implementation = ast.dump(resolver).lower()
            has_auth_logic = any(term.lower() in implementation for term in self.implementation_auth_terms)

            if not has_auth_logic:
                evidence.append(self._evidence(
                    key=key,
                    description=f"GraphQL field {key} declares {contract.directives}, but resolver implementation lacks visible authorization checks.",
                    data={"contract": contract.__dict__, "contradiction": "missing_auth_check"},
                    confidence=0.85,
                ))

        return evidence

    def analyze_python_resolvers(self, schema_content: str, python_source: str) -> List[Evidence]:
        contracts = self.parse_schema(schema_content)
        tree = ast.parse(python_source)
        resolvers = self.map_python_resolvers(tree)
        return self.find_contradictions(contracts, resolvers)

    def _resolver_key_from_function(self, name: str) -> Optional[str]:
        if name.startswith("resolve_"):
            parts = name.replace("resolve_", "", 1).split("_")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}"
            return None

        if name.endswith("_resolver"):
            parts = name.replace("_resolver", "").split("_")
            if len(parts) >= 2:
                return f"{parts[0]}.{parts[1]}"

        return None

    def _evidence(self, key: str, description: str, data: Dict[str, Any], confidence: float) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="GraphQLCausalParser",
            action="intent_implementation_diff",
            input_ref=key,
            output_ref=ev_id,
            parameters={"field": key},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.DIFFERENTIAL_ENGINE,
            evidence_type=EvidenceType.DIFFERENTIAL_RESULT,
            data=data,
            chain_of_custody=chain,
            confidence=confidence,
            description=description,
            metadata={"parser": "graphql", "field": key},
        )
