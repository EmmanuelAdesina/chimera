"""Best-effort JavaScript async boundary analysis using Tree-sitter."""
from __future__ import annotations

from typing import Any, List, Optional


class AsyncPromiseAnalyzer:
    """Find async functions containing both state writes and await boundaries."""

    def __init__(self) -> None:
        self.parser: Optional[Any] = None
        try:
            from tree_sitter import Parser
            import tree_sitter_javascript as javascript
            parser = Parser()
            try:
                from tree_sitter import Language
                parser.language = Language(javascript.language())
            except (AttributeError, TypeError):  # tree-sitter < 0.22
                parser.set_language(javascript.language())
            self.parser = parser
        except (ImportError, OSError, TypeError):
            # JavaScript support is optional; the rest of Chimera must work without it.
            self.parser = None

    def analyze_race_conditions(self, code_bytes: bytes) -> List[dict]:
        if self.parser is None:
            return []
        tree = self.parser.parse(code_bytes)
        vulnerabilities: List[dict] = []
        for node in self._walk(tree.root_node):
            if node.type not in {"function_declaration", "method_definition", "arrow_function"}:
                continue
            text = node.text.decode("utf-8", errors="ignore")
            if "async" not in text or not self._find(node, {"await_expression"}):
                continue
            if self._find(node, {"assignment_expression", "update_expression"}):
                vulnerabilities.append({
                    "vector": "ASYNC_TOCTOU",
                    "location": node.start_point,
                    "description": "State mutation crosses an await resolution boundary; review for TOCTOU races.",
                })
        return vulnerabilities

    def _walk(self, node: Any):
        yield node
        for child in node.children:
            yield from self._walk(child)

    def _find(self, node: Any, types: set[str]) -> bool:
        return any(candidate.type in types for candidate in self._walk(node))
