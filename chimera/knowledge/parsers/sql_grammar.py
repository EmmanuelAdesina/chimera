# chimera/knowledge/parsers/sql_grammar.py

from typing import Set, Dict

class SQLGrammar:
    """
    Machine-readable SQL grammar rules for differential analysis.
    Not a full parser — just the security-relevant meta-character sets.
    """
    
    # Characters that change query structure
    META_CHARS: Set[str] = {"'", '"', ";", "--", "/*", "*/", "xp_", "union", "select", "insert", "delete", "drop"}
    
    # Characters that are always safe in string literals
    SAFE_LITERAL_CHARS: Set[str] = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
    
    # Common escape sequences
    ESCAPE_RULES: Dict[str, str] = {
        "'": "''",           # Standard SQL
        "\\'": "\\'",        # MySQL
        "'": "\\'",          # PostgreSQL
    }
    
    # Dialect-specific behaviors
    DIALECTS = {
        "mysql": {
            "meta_chars": {"'", '"', ";", "#", "/*", "*/", "0x"},  # 0x hex literal
            "comment_styles": ["-- ", "#", "/* */"],
            "stacked_queries": True
        },
        "postgresql": {
            "meta_chars": {"'", '"', ";", "/*", "*/", "$$"},
            "comment_styles": ["-- ", "/* */"],
            "stacked_queries": True
        },
        "sqlite": {
            "meta_chars": {"'", '"', ";", "/*", "*/"},
            "comment_styles": ["-- ", "/* */"],
            "stacked_queries": False  # SQLite doesn't support stacked by default
        }
    }
    
    @classmethod
    def get_differential_risk(cls, upstream_safe: Set[str], dialect: str = "mysql") -> Set[str]:
        """Return chars that are safe upstream but meta in this SQL dialect."""
        dialect_meta = cls.DIALECTS.get(dialect, cls.DIALECTS["mysql"])["meta_chars"]
        return upstream_safe & dialect_meta