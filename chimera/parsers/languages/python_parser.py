import ast
from typing import Any, Optional
from chimera.parsers.base import BaseParser
from chimera.models.causal import ParserLayerModel, GrammarModel

class PythonParser(BaseParser):
    """Extracts parser layer info from Python AST."""

    @property
    def name(self) -> str:
        return "python_ast"

    def parse(self, source: str) -> ParserLayerModel:
        tree = ast.parse(source)
        return ParserLayerModel(
            name="Python_str",
            grammar=GrammarModel(
                safe_chars=set(chr(i) for i in range(32, 127)),
                meta_chars=set()
            ),
            sanitizer=None
        )

    def detect_sanitizer(self, source: Any) -> Optional[str]:
        return None
