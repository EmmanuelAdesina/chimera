from typing import Any, Optional
from chimera.parsers.base import BaseParser
from chimera.models.causal import ParserLayerModel, GrammarModel

class SQLParser(BaseParser):
    """Models SQL literal grammar."""

    @property
    def name(self) -> str:
        return "sql_literal"

    def parse(self, source: str) -> ParserLayerModel:
        return ParserLayerModel(
            name="SQL_literal",
            grammar=GrammarModel(
                safe_chars=set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "),
                meta_chars={"'", '"', ";", "--", "/*"}
            ),
            sanitizer=None
        )

    def detect_sanitizer(self, source: Any) -> Optional[str]:
        return None
