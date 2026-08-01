from typing import List, Dict, Optional, Any
import sqlite3
import json
from datetime import datetime

from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


class StructuredMemory:
    """
    SQLite-backed source of truth.
    Stores: hypotheses, findings, decisions, failures.
    """

    def __init__(self, db_path: str = "./data/memory.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        import os
        os.makedirs("data", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                claim TEXT NOT NULL,
                required_conditions TEXT,
                evidence TEXT,
                missing_information TEXT,
                falsifiers TEXT,
                confidence REAL,
                status TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                hypothesis_id TEXT,
                target TEXT,
                severity TEXT,
                description TEXT,
                proof TEXT,
                timestamp TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY,
                context TEXT,
                action TEXT,
                reasoning TEXT,
                outcome TEXT,
                timestamp TEXT
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS failures (
                id INTEGER PRIMARY KEY,
                hypothesis_id TEXT,
                failure_type TEXT,
                root_cause TEXT,
                correction TEXT,
                timestamp TEXT
            )
        """)
        
        conn.commit()
        conn.close()

    def store_hypothesis(self, hypothesis: Hypothesis):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO hypotheses
            (id, claim, required_conditions, evidence, missing_information,
             falsifiers, confidence, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            hypothesis.id,
            hypothesis.claim,
            json.dumps(hypothesis.required_conditions),
            json.dumps([e.model_dump() for e in hypothesis.evidence]),
            json.dumps(hypothesis.missing_information),
            json.dumps(hypothesis.falsifiers),
            hypothesis.confidence,
            hypothesis.status,
            hypothesis.created_at,
            hypothesis.updated_at
        ))
        conn.commit()
        conn.close()

    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM hypotheses WHERE id = ?", (hypothesis_id,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return Hypothesis(
            id=row[0],
            claim=row[1],
            required_conditions=json.loads(row[2]),
            evidence=[Evidence(**e) for e in json.loads(row[3])],
            missing_information=json.loads(row[4]),
            falsifiers=json.loads(row[5]),
            confidence=row[6],
            status=row[7],
            created_at=row[8],
            updated_at=row[9]
        )

    def store_failure(self, hypothesis_id: str, failure_type: str, 
                      root_cause: str, correction: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO failures
            (hypothesis_id, failure_type, root_cause, correction, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (hypothesis_id, failure_type, root_cause, correction, 
              datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

    def get_failure_patterns(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            SELECT failure_type, root_cause, COUNT(*) as count
            FROM failures
            GROUP BY failure_type, root_cause
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        rows = c.fetchall()
        conn.close()
        return [
            {"type": r[0], "cause": r[1], "count": r[2]}
            for r in rows
        ]


class SemanticMemory:
    """
    Vector-backed retrieval memory.
    NOT the source of truth. Derived from structured memory.
    """
    def __init__(self, backend: str = "sqlite_vec"):
        self.backend = backend
        self._embeddings: Dict[str, List[float]] = {}

    def index_hypothesis(self, hypothesis: Hypothesis):
        pass

    def query_similar(self, text: str, k: int = 5) -> List[str]:
        return []

    def index_code_pattern(self, pattern_id: str, code_snippet: str,
                           metadata: Dict[str, Any]):
        pass


class ChimeraMemory:
    """Unified interface: structured is truth, semantic is retrieval."""
    def __init__(self, db_path: str = "./data/memory.db"):
        self.structured = StructuredMemory(db_path)
        self.semantic = SemanticMemory()
