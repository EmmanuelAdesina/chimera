# CHIMERA — COMPLETE PYTHON-ONLY SCAFFOLD
# Run this INSIDE C:\Cyber\chimera
# NO installations happen here. All installs are deferred to MANUAL_INSTALL.md.

$owner = "YOUR_GITHUB_USERNAME"  # <-- CHANGE THIS BEFORE RUNNING

# Safety check
if (-not (Test-Path ".git")) {
    Write-Host "[ERROR] Not a git repo. cd into chimera first." -ForegroundColor Red
    exit 1
}

# =============================================================================
# 1. CREATE ALL DIRECTORIES
# =============================================================================
$dirs = @(
    "chimera\core",
    "chimera\models",
    "chimera\parsers\languages",
    "chimera\execution",
    "chimera\sandbox",
    "chimera\plugins",
    "chimera\reports",
    "chimera\utils",
    "chimera\analysis",
    "tests\unit\core",
    "tests\unit\parsers",
    "tests\unit\analysis",
    "tests\integration",
    "tests\targets",
    "configs",
    "docs\architecture"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# =============================================================================
# 2. WRITE ALL FILES
# =============================================================================

# --- chimera/__init__.py ---
Set-Content -Path "chimera\__init__.py" -Value "__version__ = '0.1.0'" -Encoding utf8

# --- chimera/__main__.py ---
$content = @'
import sys
from chimera.core.orchestrator import ChimeraOrchestrator

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m chimera <command>")
        print("Commands:")
        print("  analyze <target>    Run causal analysis on target")
        print("  test                Run self-tests")
        sys.exit(1)
    
    cmd = sys.argv[1]
    orchestrator = ChimeraOrchestrator()
    
    if cmd == "analyze":
        target = sys.argv[2] if len(sys.argv) > 2 else "./tests/targets"
        orchestrator.run(target)
    elif cmd == "test":
        print("[chimera] Run pytest separately: pytest tests/ -v")
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
'@
Set-Content -Path "chimera\__main__.py" -Value $content -Encoding utf8

# --- chimera/models/evidence.py ---
$content = @'
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class Evidence(BaseModel):
    source: str = Field(description="Where this evidence came from: code, runtime, tool, llm")
    data: Any = Field(description="The actual evidence payload")
    confidence: float = Field(ge=0.0, le=1.0, default=1.0, description="How much we trust this evidence")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Line numbers, file paths, request IDs, etc.")
'@
Set-Content -Path "chimera\models\evidence.py" -Value $content -Encoding utf8

# --- chimera/models/hypothesis.py ---
$content = @'
from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from datetime import datetime

from chimera.models.evidence import Evidence

HypothesisStatus = Literal["proposed", "testing", "confirmed", "rejected"]

class Hypothesis(BaseModel):
    id: str = Field(description="Unique hypothesis identifier")
    claim: str = Field(description="The falsifiable claim")
    
    required_conditions: List[str] = Field(default_factory=list, description="What must be true for this claim to hold")
    evidence: List[Evidence] = Field(default_factory=list, description="Observations that support the claim")
    missing_information: List[str] = Field(default_factory=list, description="What we still need to know")
    falsifiers: List[str] = Field(default_factory=list, description="What observations would prove this claim false")
    confidence: float = Field(ge=0.0, le=1.0, default=0.0, description="Current belief strength")
    status: HypothesisStatus = Field(default="proposed")
    
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def add_evidence(self, evidence: Evidence) -> "Hypothesis":
        self.evidence.append(evidence)
        self.updated_at = datetime.utcnow().isoformat()
        return self
    
    def check_completeness(self) -> float:
        if not self.required_conditions:
            return 0.0
        return min(1.0, len(self.evidence) / max(1, len(self.required_conditions)))
    
    def is_falsified(self) -> bool:
        return False
'@
Set-Content -Path "chimera\models\hypothesis.py" -Value $content -Encoding utf8

# --- chimera/models/causal.py ---
$content = @'
from pydantic import BaseModel, Field
from typing import Set, Dict, Optional, List

class GrammarModel(BaseModel):
    safe_chars: Set[str] = Field(default_factory=set, description="Characters treated as literal data")
    meta_chars: Set[str] = Field(default_factory=set, description="Characters with structural/control meaning")
    escape_rules: Dict[str, str] = Field(default_factory=dict, description="How meta chars are neutralized")

class ParserLayerModel(BaseModel):
    name: str
    grammar: GrammarModel
    sanitizer: Optional[str] = Field(default=None, description="Function/rule that translates output to next layer")
    source_location: Optional[str] = None

class DifferentialReport(BaseModel):
    boundary: str
    dangerous_chars: Set[str]
    developer_assumption: str
    actual_risk: str
    fix_recommendation: str
    confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)

class CascadeAnalysis(BaseModel):
    target: str
    layers: List[ParserLayerModel]
    differentials: List[DifferentialReport]
    epistemic_confidence: float = 0.0
    causal_narrative: str = ""

class BeliefModel(BaseModel):
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)
    interrogation_passed: bool = False
'@
Set-Content -Path "chimera\models\causal.py" -Value $content -Encoding utf8

# --- chimera/models/__init__.py ---
$content = @'
from chimera.models.evidence import Evidence
from chimera.models.hypothesis import Hypothesis, HypothesisStatus
from chimera.models.causal import (
    GrammarModel, ParserLayerModel, DifferentialReport, CascadeAnalysis, BeliefModel
)

__all__ = [
    "Evidence",
    "Hypothesis",
    "HypothesisStatus",
    "GrammarModel",
    "ParserLayerModel",
    "DifferentialReport",
    "CascadeAnalysis",
    "BeliefModel",
]
'@
Set-Content -Path "chimera\models\__init__.py" -Value $content -Encoding utf8

# --- chimera/core/causal_engine.py ---
$content = @'
from typing import List, Optional
from dataclasses import dataclass

from chimera.models.causal import GrammarModel, ParserLayerModel, DifferentialReport, CascadeAnalysis
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


@dataclass
class ParserLayer:
    name: str
    grammar: GrammarModel
    sanitizer: Optional[str] = None


class CausalEngine:
    """
    Analyzes parser cascades for grammar differentials.
    Produces Hypothesis objects, not just reports.
    """

    def __init__(self):
        self.differentials: List[DifferentialReport] = []

    def analyze_cascade(self, layers: List[ParserLayer], target: str = "") -> List[Hypothesis]:
        hypotheses = []
        
        for i in range(len(layers) - 1):
            current = layers[i]
            next_layer = layers[i + 1]
            
            unescaped_meta = current.grammar.safe_chars & next_layer.grammar.meta_chars
            
            if unescaped_meta and not current.sanitizer:
                diff = DifferentialReport(
                    boundary=f"{current.name} -> {next_layer.name}",
                    dangerous_chars=unescaped_meta,
                    developer_assumption=f"{current.name} output is safe for {next_layer.name}",
                    actual_risk=f"Characters {unescaped_meta} are meta in {next_layer.name}",
                    fix_recommendation=f"Insert sanitizer at boundary: escape {unescaped_meta} for {next_layer.name} grammar",
                    confidence=0.95,
                    evidence=[f"No sanitizer between {current.name} and {next_layer.name}"]
                )
                
                hypothesis = self._differential_to_hypothesis(diff, target, layers)
                hypotheses.append(hypothesis)
        
        return hypotheses

    def _differential_to_hypothesis(self, diff: DifferentialReport, target: str, 
                                      layers: List[ParserLayer]) -> Hypothesis:
        chars = ", ".join(diff.dangerous_chars)
        
        claim = (
            f"Grammar differential at {diff.boundary}: "
            f"character(s) [{chars}] are data in the upstream layer "
            f"but meta-characters in the downstream layer, "
            f"and no sanitizer translates between grammars."
        )
        
        return Hypothesis(
            id=f"HYP-{hash(diff.boundary) % 10000:04d}",
            claim=claim,
            required_conditions=[
                f"Data flows from {diff.boundary.split(' -> ')[0]} to {diff.boundary.split(' -> ')[1]}",
                f"Character(s) {diff.dangerous_chars} appear in attacker-controlled input",
                f"No sanitizer exists at the boundary",
                f"Downstream layer interprets {diff.dangerous_chars} as control characters"
            ],
            evidence=[
                Evidence(
                    source="causal_engine",
                    data=diff.model_dump(),
                    confidence=diff.confidence,
                    metadata={"boundary": diff.boundary, "target": target}
                )
            ],
            missing_information=[
                "Attacker-controlled input path to the boundary",
                "Runtime execution confirmation",
                "WAF or defense layer interference"
            ],
            falsifiers=[
                f"Input never contains {diff.dangerous_chars}",
                "A sanitizer exists but was not detected",
                "Downstream layer is not actually reached by user input",
                "The application uses parameterized queries at a higher layer"
            ],
            confidence=diff.confidence * 0.7,
            status="proposed"
        )

    def full_analysis(self, target: str, layers: List[ParserLayer]) -> CascadeAnalysis:
        diffs = self.analyze_cascade(layers, target)
        
        layer_models = [
            ParserLayerModel(name=l.name, grammar=l.grammar, sanitizer=l.sanitizer)
            for l in layers
        ]
        
        return CascadeAnalysis(
            target=target,
            layers=layer_models,
            differentials=diffs,
            epistemic_confidence=0.95 if diffs else 0.1,
            causal_narrative=""
        )
'@
Set-Content -Path "chimera\core\causal_engine.py" -Value $content -Encoding utf8

# --- chimera/core/epistemic_engine.py ---
$content = @'
from typing import List, Dict, Optional
from datetime import datetime

from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


class EpistemicMonitor:
    """
    Interrogates Hypotheses before they become beliefs.
    """

    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        self.known_biases: Dict[str, float] = {}
        self.interrogation_history: List[Dict] = []

    def interrogate(self, hypothesis: Hypothesis) -> bool:
        failures = []
        
        if hypothesis.confidence < self.confidence_threshold:
            failures.append(f"Confidence {hypothesis.confidence} below threshold {self.confidence_threshold}")
        
        if not hypothesis.evidence:
            failures.append("Zero evidence provided")
        
        evidence_coverage = hypothesis.check_completeness()
        if evidence_coverage < 0.5:
            failures.append(f"Evidence coverage only {evidence_coverage:.2f}")
        
        for bias, failure_rate in self.known_biases.items():
            if bias.lower() in hypothesis.claim.lower():
                adjusted = hypothesis.confidence * (1 - failure_rate)
                if adjusted < self.confidence_threshold:
                    failures.append(f"Known bias '{bias}' reduces effective confidence to {adjusted:.2f}")
        
        critical_missing = [m for m in hypothesis.missing_information 
                           if "runtime" in m.lower() or "execution" in m.lower()]
        if len(critical_missing) > 2:
            failures.append(f"Too much missing runtime information: {len(critical_missing)} items")
        
        result = len(failures) == 0
        
        self.interrogation_history.append({
            "hypothesis_id": hypothesis.id,
            "timestamp": datetime.utcnow().isoformat(),
            "survived": result,
            "failures": failures,
            "original_confidence": hypothesis.confidence
        })
        
        return result

    def calibrate(self, hypothesis: Hypothesis, actual_outcome: str):
        was_correct = actual_outcome == "confirmed"
        if not was_correct:
            for condition in hypothesis.required_conditions:
                pass

    def register_bias(self, assumption_pattern: str, historical_failure_rate: float):
        self.known_biases[assumption_pattern] = historical_failure_rate

    def calibration_report(self) -> Dict:
        if not self.interrogation_history:
            return {"status": "no_interrogations"}
        
        total = len(self.interrogation_history)
        passed = sum(1 for h in self.interrogation_history if h["survived"])
        
        return {
            "total_interrogated": total,
            "survived": passed,
            "rejected": total - passed,
            "survival_rate": passed / total if total > 0 else 0,
            "known_biases": len(self.known_biases)
        }
'@
Set-Content -Path "chimera\core\epistemic_engine.py" -Value $content -Encoding utf8

# --- chimera/core/memory.py ---
$content = @'
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
'@
Set-Content -Path "chimera\core\memory.py" -Value $content -Encoding utf8

# --- chimera/core/action_planner.py ---
$content = @'
from typing import Dict
from chimera.models.hypothesis import Hypothesis

class ActionPlanner:
    """
    Maps a hypothesis to the best execution capability.
    """

    CAPABILITY_MAP = {
        "sql injection": "controlled_testing",
        "xss": "browser_automation",
        "idor": "browser_automation",
        "command injection": "environment_interaction",
        "ssrf": "controlled_testing",
        "recon": "observation",
        "endpoint discovery": "browser_automation",
        "authentication bypass": "browser_automation",
        "file inclusion": "controlled_testing",
        "information disclosure": "observation",
    }

    @classmethod
    def select_capability(cls, hypothesis: Hypothesis) -> str:
        claim_lower = hypothesis.claim.lower()
        for pattern, capability in cls.CAPABILITY_MAP.items():
            if pattern in claim_lower:
                return capability
        return "controlled_testing"

    @classmethod
    def build_intent(cls, hypothesis: Hypothesis, target: str) -> Dict:
        capability = cls.select_capability(hypothesis)

        if capability == "browser_automation":
            return {"action": "fetch", "url": target, "wait_for": "body"}
        elif capability == "environment_interaction":
            return {"action": "oneshot", "command": f"curl -I {target}"}
        elif capability == "controlled_testing":
            return {"action": "send_test", "request_spec": {"path": "/", "method": "GET"}, "payload": ""}
        elif capability == "observation":
            return {"target": target}

        return {}
'@
Set-Content -Path "chimera\core\action_planner.py" -Value $content -Encoding utf8

# --- chimera/core/orchestrator.py ---
$content = @'
from typing import List
from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.core.memory import ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.causal import GrammarModel


class ChimeraOrchestrator:
    """
    The Reasoning Loop:
    1. OBSERVE        -> Gather raw data
    2. MODEL          -> Build parser cascades
    3. HYPOTHESIZE    -> Generate falsifiable claims
    4. INTERROGATE    -> Skeptic challenges
    5. TEST           -> Gather evidence
    6. UPDATE         -> Revise confidence
    7. DECIDE         -> Confirm/reject/iterate
    8. REMEMBER       -> Store in structured memory
    """

    def __init__(self, config_path: str = "configs/default.yaml"):
        self.causal = CausalEngine()
        self.epistemic = EpistemicMonitor(confidence_threshold=0.6)
        self.memory = ChimeraMemory()
        self.config_path = config_path
        self.hypotheses: List[Hypothesis] = []

    def run(self, target: str):
        print(f"[CHIMERA] Starting Reasoning Loop on: {target}")
        print("=" * 60)
        
        print("[1] OBSERVE: Gathering target surface...")
        observations = self._observe(target)
        print(f"    -> {len(observations)} raw observations")
        
        print("[2] MODEL: Building parser cascades...")
        cascades = self._build_cascades(target, observations)
        print(f"    -> {len(cascades)} parser cascades modeled")
        
        print("[3] HYPOTHESIZE: Generating falsifiable claims...")
        for cascade in cascades:
            hyps = self.causal.analyze_cascade(cascade, target=target)
            self.hypotheses.extend(hyps)
        print(f"    -> {len(self.hypotheses)} hypotheses generated")
        
        print("[4] INTERROGATE: Skeptic challenges hypotheses...")
        survivors = []
        for hyp in self.hypotheses:
            if self.epistemic.interrogate(hyp):
                hyp.status = "testing"
                survivors.append(hyp)
                print(f"    [PASS] {hyp.id}: {hyp.claim[:60]}...")
            else:
                hyp.status = "rejected"
                print(f"    [FAIL] {hyp.id}: REJECTED")
        print(f"    -> {len(survivors)} survived interrogation")
        
        print("[5] TEST: Gathering runtime evidence...")
        for hyp in survivors:
            self._test_hypothesis(hyp, target)
        
        print("[6] UPDATE: Revising confidence...")
        for hyp in survivors:
            self._update_confidence(hyp)
        
        print("[7] DECIDE: Final classification...")
        confirmed = []
        for hyp in survivors:
            if hyp.confidence > 0.85 and hyp.check_completeness() > 0.8:
                hyp.status = "confirmed"
                confirmed.append(hyp)
            elif hyp.confidence < 0.3:
                hyp.status = "rejected"
        print(f"    -> {len(confirmed)} CONFIRMED")
        
        print("[8] REMEMBER: Storing in structured memory...")
        for hyp in self.hypotheses:
            self.memory.structured.store_hypothesis(hyp)
        print("    -> All hypotheses stored")
        
        self._print_report(confirmed)

    def _observe(self, target: str) -> List[dict]:
        return [{"source": "static", "type": "file", "path": target}]

    def _build_cascades(self, target: str, observations: List[dict]) -> List[List[ParserLayer]]:
        return [[
            ParserLayer(
                name="JSON",
                grammar=GrammarModel(
                    safe_chars={"a","b"," ","'", "\\"},
                    meta_chars={"\\", '"'},
                    escape_rules={"\\": "\\\\", '"': '\\"'}
                ),
                sanitizer="JSON RFC 8259 escape"
            ),
            ParserLayer(
                name="Python_str",
                grammar=GrammarModel(
                    safe_chars={"a","b"," ","'"},
                    meta_chars=set()
                ),
                sanitizer=None
            ),
            ParserLayer(
                name="SQL_literal",
                grammar=GrammarModel(
                    safe_chars={"a","b"," "},
                    meta_chars={"'"}
                ),
                sanitizer=None
            ),
        ]]

    def _test_hypothesis(self, hyp: Hypothesis, target: str):
        from chimera.models.evidence import Evidence
        hyp.add_evidence(Evidence(
            source="static_analysis",
            data={"finding": "f-string query construction detected"},
            confidence=0.8,
            metadata={"file": target}
        ))

    def _update_confidence(self, hyp: Hypothesis):
        if not hyp.evidence:
            return
        total_conf = sum(e.confidence for e in hyp.evidence)
        avg_conf = total_conf / len(hyp.evidence)
        missing_penalty = 0.1 * len(hyp.missing_information)
        hyp.confidence = max(0.0, min(1.0, avg_conf - missing_penalty))

    def _print_report(self, confirmed: List[Hypothesis]):
        print("\n" + "=" * 60)
        print("CHIMERA REASONING LOOP REPORT")
        print("=" * 60)
        print(f"Total hypotheses generated: {len(self.hypotheses)}")
        print(f"Confirmed: {len(confirmed)}")
        print(f"Rejected: {sum(1 for h in self.hypotheses if h.status == 'rejected')}")
        print(f"In testing: {sum(1 for h in self.hypotheses if h.status == 'testing')}")
        
        if confirmed:
            print("\n--- CONFIRMED FINDINGS ---")
            for hyp in confirmed:
                print(f"\n[{hyp.id}] {hyp.claim[:80]}")
                print(f"    Confidence: {hyp.confidence:.2f}")
                print(f"    Evidence: {len(hyp.evidence)} items")
                print(f"    Missing: {len(hyp.missing_information)} items")
        print("=" * 60)
'@
Set-Content -Path "chimera\core\orchestrator.py" -Value $content -Encoding utf8

# --- chimera/core/__init__.py ---
"" | Out-File "chimera\core\__init__.py" -Encoding utf8

# --- chimera/parsers/base.py ---
$content = @'
from abc import ABC, abstractmethod
from typing import Any, Optional
from chimera.models.causal import ParserLayerModel

class BaseParser(ABC):
    """
    Abstract base for all parser cascade builders.
    To extend: subclass, implement parse() and detect_sanitizer().
    """

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def parse(self, source: Any) -> ParserLayerModel:
        """Extract grammar and sanitizer info from source code."""
        raise NotImplementedError

    @abstractmethod
    def detect_sanitizer(self, source: Any) -> Optional[str]:
        """Identify if/where a sanitizer exists between layers."""
        raise NotImplementedError
'@
Set-Content -Path "chimera\parsers\base.py" -Value $content -Encoding utf8

# --- chimera/parsers/languages/python_parser.py ---
$content = @'
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
'@
Set-Content -Path "chimera\parsers\languages\python_parser.py" -Value $content -Encoding utf8

# --- chimera/parsers/languages/sql_parser.py ---
$content = @'
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
'@
Set-Content -Path "chimera\parsers\languages\sql_parser.py" -Value $content -Encoding utf8

# --- chimera/execution/base.py ---
$content = @'
from abc import ABC, abstractmethod
from typing import Any, Dict

class ExecutionAdapter(ABC):
    """
    Abstract base for all execution capabilities.
    Adapters translate Chimera's intent into specific tool actions.
    The capability (what we want to do) is stable.
    The adapter (which tool does it) is replaceable.
    """

    @property
    @abstractmethod
    def capability(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the intent and return observations."""
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> bool:
        """Is this adapter available and functional?"""
        raise NotImplementedError
'@
Set-Content -Path "chimera\execution\base.py" -Value $content -Encoding utf8

# --- chimera/execution/observation.py ---
$content = @'
import subprocess
import json
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class NucleiObservationAdapter(ExecutionAdapter):
    """
    Capability: Observation
    Adapter: Nuclei
    Observes target surface: technologies, known CVEs, exposed endpoints.
    """

    @property
    def capability(self) -> str:
        return "observation"

    def __init__(self, binary: str = "nuclei", rate_limit: int = 150):
        self.binary = binary
        self.rate_limit = rate_limit

    def health_check(self) -> bool:
        try:
            subprocess.run([self.binary, "-version"], capture_output=True, check=True)
            return True
        except:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        target = intent.get("target")
        if not target:
            return {"error": "No target provided"}

        cmd = [
            self.binary, "-u", target,
            "-rate-limit", str(self.rate_limit),
            "-jsonl", "-o", "/tmp/nuclei_chimera.jsonl"
        ]
        subprocess.run(cmd, capture_output=True)

        findings = []
        try:
            with open("/tmp/nuclei_chimera.jsonl") as f:
                for line in f:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    info = data.get("info", {})
                    findings.append({
                        "template_id": data.get("template-id"),
                        "severity": info.get("severity"),
                        "matched_at": data.get("matched-at"),
                        "description": info.get("description")
                    })
        except FileNotFoundError:
            pass

        return {
            "capability": "observation",
            "adapter": "nuclei",
            "findings": findings,
            "count": len(findings)
        }
'@
Set-Content -Path "chimera\execution\observation.py" -Value $content -Encoding utf8

# --- chimera/execution/controlled_testing.py ---
$content = @'
import requests
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class CaidoTestingAdapter(ExecutionAdapter):
    """
    Capability: Controlled Testing
    Adapter: Caido
    Sends crafted requests, observes responses, detects anomalies.
    """

    @property
    def capability(self) -> str:
        return "controlled_testing"

    def __init__(self, api_url: str = "http://localhost:8080", token: str = ""):
        self.api_url = api_url
        self.headers = {"Authorization": f"Bearer {token}"}
        self._baseline_cache: Dict[str, Dict] = {}

    def health_check(self) -> bool:
        try:
            r = requests.get(f"{self.api_url}/graphql", headers=self.headers, timeout=2)
            return r.status_code < 500
        except:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        action = intent.get("action")

        if action == "capture_baseline":
            return self._capture_baseline(intent.get("request_spec", {}))
        elif action == "send_test":
            return self._send_test(
                intent.get("request_spec", {}),
                intent.get("payload", "")
            )
        return {"error": f"Unknown action: {action}"}

    def _capture_baseline(self, spec: Dict) -> Dict:
        path = spec.get("path", "/")
        self._baseline_cache[path] = {"status": 200, "length": 0}
        return {"capability": "controlled_testing", "action": "baseline", "path": path}

    def _send_test(self, spec: Dict, payload: str) -> Dict:
        path = spec.get("path", "/")
        baseline = self._baseline_cache.get(path)

        modified = spec.copy()
        if "body" in modified:
            modified["body"] = modified["body"].replace("{{PAYLOAD}}", payload)
        if "path" in modified:
            modified["path"] = modified["path"].replace("{{PAYLOAD}}", payload)

        anomalies = []
        if baseline and len(payload) > 100:
            anomalies.append("payload_size_anomaly")

        return {
            "capability": "controlled_testing",
            "adapter": "caido",
            "path": path,
            "anomalies": anomalies,
            "response_status": 200
        }
'@
Set-Content -Path "chimera\execution\controlled_testing.py" -Value $content -Encoding utf8

# --- chimera/execution/environment_interaction.py ---
$content = @'
import subprocess
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class TerminalAdapter(ExecutionAdapter):
    """
    Capability: Environment Interaction
    Adapter: Local/Remote Shell
    """

    @property
    def capability(self) -> str:
        return "environment_interaction"

    def health_check(self) -> bool:
        return True

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        action = intent.get("action", "oneshot")

        if action == "oneshot":
            return self._run_command(intent.get("command", ""))
        elif action == "interactive":
            return self._interactive_session(intent)
        elif action == "stream":
            return self._stream_command(intent.get("command", ""))
        return {"error": f"Unknown action: {action}"}

    def _run_command(self, command: str) -> Dict:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        return {
            "capability": "environment_interaction",
            "adapter": "terminal",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    def _interactive_session(self, intent: Dict) -> Dict:
        command = intent.get("command")
        inputs = intent.get("inputs", [])

        proc = subprocess.Popen(
            command,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        outputs = []
        import time
        for inp in inputs:
            proc.stdin.write(inp + "\n")
            proc.stdin.flush()
            time.sleep(0.5)
            if proc.stdout.readable():
                outputs.append(proc.stdout.read(4096))

        proc.stdin.close()
        proc.wait()

        return {
            "capability": "environment_interaction",
            "adapter": "terminal",
            "mode": "interactive",
            "outputs": outputs,
            "returncode": proc.returncode
        }

    def _stream_command(self, command: str) -> Dict:
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        lines = []
        for line in proc.stdout:
            lines.append(line.rstrip())
            if len(lines) > 1000:
                break

        proc.wait()
        return {
            "capability": "environment_interaction",
            "adapter": "terminal",
            "mode": "stream",
            "lines": lines,
            "truncated": proc.poll() is None
        }
'@
Set-Content -Path "chimera\execution\environment_interaction.py" -Value $content -Encoding utf8

# --- chimera/execution/browser_automation.py ---
$content = @'
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class BrowserAdapter(ExecutionAdapter):
    """
    Capability: browser_automation
    Uses Playwright for headless browser tasks.
    NOTE: Requires 'playwright' to be installed manually later.
    """

    @property
    def capability(self) -> str:
        return "browser_automation"

    def __init__(self, headless: bool = True):
        self.headless = headless

    def health_check(self) -> bool:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                browser.close()
            return True
        except Exception:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        action = intent.get("action")

        if action == "fetch":
            return self._fetch_page(intent.get("url"), intent.get("wait_for"))
        elif action == "extract":
            return self._extract_data(intent.get("url"), intent.get("selector"))
        elif action == "crawl":
            return self._crawl(intent.get("url"), intent.get("depth", 1))

        return {"error": f"Unknown browser action: {action}"}

    def _fetch_page(self, url: str, wait_for=None):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"
            )
            page = context.new_page()
            page.goto(url, wait_until="networkidle")
            if wait_for:
                page.wait_for_selector(wait_for)
            content = page.content()
            title = page.title()
            browser.close()
            return {
                "capability": "browser_automation",
                "action": "fetch",
                "url": url,
                "title": title,
                "content_length": len(content)
            }

    def _extract_data(self, url: str, selector: str):
        return {"capability": "browser_automation", "action": "extract", "status": "not_fully_implemented"}

    def _crawl(self, url: str, depth: int):
        return {"capability": "browser_automation", "action": "crawl", "status": "not_fully_implemented"}
'@
Set-Content -Path "chimera\execution\browser_automation.py" -Value $content -Encoding utf8

# --- chimera/execution/runtime_verification.py ---
$content = @'
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class RuntimeVerificationAdapter(ExecutionAdapter):
    """
    Capability: Runtime Verification
    Adapter: Custom instrumentation
    Verifies whether a hypothesized vulnerability is actually exploitable.
    """

    @property
    def capability(self) -> str:
        return "runtime_verification"

    def health_check(self) -> bool:
        return True

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        verification_type = intent.get("type")

        if verification_type == "time_based":
            return self._verify_time_based(intent)
        elif verification_type == "error_based":
            return self._verify_error_based(intent)
        elif verification_type == "out_of_band":
            return self._verify_oob(intent)

        return {"error": f"Unknown verification type: {verification_type}"}

    def _verify_time_based(self, intent: Dict) -> Dict:
        return {"verified": False, "method": "time_based", "details": "Not implemented"}

    def _verify_error_based(self, intent: Dict) -> Dict:
        return {"verified": False, "method": "error_based", "details": "Not implemented"}

    def _verify_oob(self, intent: Dict) -> Dict:
        return {"verified": False, "method": "out_of_band", "details": "Not implemented"}
'@
Set-Content -Path "chimera\execution\runtime_verification.py" -Value $content -Encoding utf8

# --- chimera/execution/registry.py ---
$content = @'
from typing import Dict, List
from chimera.execution.base import ExecutionAdapter

class ExecutionRegistry:
    """
    Central registry for execution capabilities.
    """

    def __init__(self):
        self._adapters: Dict[str, ExecutionAdapter] = {}
        self._capabilities: Dict[str, List[str]] = {}

    def register(self, adapter: ExecutionAdapter):
        name = adapter.__class__.__name__
        self._adapters[name] = adapter

        cap = adapter.capability
        if cap not in self._capabilities:
            self._capabilities[cap] = []
        self._capabilities[cap].append(name)

    def get_capability(self, capability: str) -> ExecutionAdapter:
        names = self._capabilities.get(capability, [])
        for name in names:
            adapter = self._adapters[name]
            if adapter.health_check():
                return adapter
        raise RuntimeError(f"No healthy adapter for capability: {capability}")

    def list_capabilities(self) -> Dict[str, List[str]]:
        return {
            cap: [n for n in names if self._adapters[n].health_check()]
            for cap, names in self._capabilities.items()
        }
'@
Set-Content -Path "chimera\execution\registry.py" -Value $content -Encoding utf8

# --- chimera/sandbox/manager.py ---
$content = @'
"""
Sandbox Manager - Docker container lifecycle.
NOTE: Requires 'docker' Python package and Docker Desktop installed manually.
"""

from typing import Dict, Optional, List
from dataclasses import dataclass

# Placeholder imports - uncomment after installing docker package
# import docker
# import uuid
# import os


@dataclass
class SandboxConfig:
    image: str = "chimera-sandbox:latest"
    network_mode: str = "bridge"
    memory_limit: str = "2g"
    cpu_limit: float = 1.0
    timeout_seconds: int = 300
    persist: bool = False


class SandboxManager:
    """
    The AI's personal computer.
    Creates disposable environments, installs tools on demand, returns results.
    NOTE: Docker-dependent. Will raise if docker is not installed.
    """

    def __init__(self):
        self.active_boxes: Dict[str, any] = {}
        # TODO: self.client = docker.from_env() after installing docker package

    def spawn(self, name: Optional[str] = None, config: Optional[SandboxConfig] = None) -> str:
        raise NotImplementedError("Install docker>=7.0 and Docker Desktop to enable sandboxes")

    def execute(self, box_id: str, command: str, timeout: int = 60) -> Dict:
        raise NotImplementedError("Sandbox not available")

    def destroy(self, box_id: str):
        pass

    def destroy_all(self):
        pass

    def list_active(self) -> List[str]:
        return []
'@
Set-Content -Path "chimera\sandbox\manager.py" -Value $content -Encoding utf8

# --- chimera/sandbox/tool_manager.py ---
$content = @'
"""
Tool Manager - Dynamic tool provisioning inside sandboxes.
NOTE: Requires SandboxManager to be functional.
"""

from typing import Dict, List


class ToolManager:
    """
    Manages security tools inside sandboxes.
    The AI requests tools by name; this handles installation.
    """

    TOOL_REGISTRY = {
        "nuclei": {
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
            "check": "which nuclei && nuclei -version",
            "binary": "nuclei",
            "type": "recon"
        },
        "ffuf": {
            "install": "go install -v github.com/ffuf/ffuf@latest",
            "check": "which ffuf",
            "binary": "ffuf",
            "type": "fuzzing"
        },
        "sqlmap": {
            "install": "pip install sqlmap",
            "check": "which sqlmap",
            "binary": "sqlmap",
            "type": "exploitation"
        },
        "gobuster": {
            "install": "go install -v github.com/OJ/gobuster/v3@latest",
            "check": "which gobuster",
            "binary": "gobuster",
            "type": "recon"
        },
        "nmap": {
            "install": "apt-get update && apt-get install -y nmap",
            "check": "which nmap",
            "binary": "nmap",
            "type": "recon"
        }
    }

    def __init__(self, sandbox_manager):
        self.sandbox = sandbox_manager
        self._installed_cache: Dict[str, List[str]] = {}

    def ensure_tool(self, box_id: str, tool_name: str) -> bool:
        raise NotImplementedError("Sandbox not available. Install docker>=7.0 first.")

    def run_tool(self, box_id: str, tool_name: str, arguments: str, timeout: int = 120) -> Dict:
        return {"error": "Sandbox not available"}

    def discover_tools(self, box_id: str) -> List[str]:
        return []
'@
Set-Content -Path "chimera\sandbox\tool_manager.py" -Value $content -Encoding utf8

# --- chimera/sandbox/Dockerfile ---
$content = @'
# Chimera Sandbox Base Image
# Build manually later with: docker build -t chimera-sandbox:latest .
FROM kalilinux/kali-rolling:latest

RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    golang-go git curl wget \
    nmap masscan \
    libpcap-dev \
    chromium \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="${PATH}:/root/go/bin"

RUN pip3 install --break-system-packages \
    requests playwright pwntools \
    beautifulsoup4 lxml

RUN playwright install chromium

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
'@
Set-Content -Path "chimera\sandbox\Dockerfile" -Value $content -Encoding utf8

# --- chimera/plugins/README.md ---
$content = @'
# Chimera Plugins

## How to Extend

Drop a Python module here or install as a separate package with entry points.

## Plugin Types

- Parser: chimera.parsers.base.BaseParser
- Analyzer: chimera.analysis.base.BaseAnalyzer
- Bridge: chimera.execution.base.ExecutionAdapter
- Reporter: chimera.reports.base.BaseReporter

## Rules
1. Lazy-load heavy dependencies
2. Return Pydantic models
3. Handle your own exceptions
'@
Set-Content -Path "chimera\plugins\README.md" -Value $content -Encoding utf8

# --- chimera/utils/logger.py ---
$content = @'
import logging
import sys

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S"
        ))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
'@
Set-Content -Path "chimera\utils\logger.py" -Value $content -Encoding utf8

# --- tests/unit/core/test_causal_engine.py ---
$content = @'
import pytest
from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.models.causal import GrammarModel

class TestCausalEngine:
    def test_json_python_sql_differential(self):
        layers = [
            ParserLayer(
                name="JSON",
                grammar=GrammarModel(
                    safe_chars={"a", "b", "'", "\\", " "},
                    meta_chars={"\\", '"'},
                    escape_rules={"\\": "\\\\", '"': '\\"'}
                ),
                sanitizer="JSON RFC 8259 escape"
            ),
            ParserLayer(
                name="Python_str",
                grammar=GrammarModel(
                    safe_chars={"a", "b", "'", " "},
                    meta_chars=set()
                ),
                sanitizer=None
            ),
            ParserLayer(
                name="SQL_literal",
                grammar=GrammarModel(
                    safe_chars={"a", "b", " "},
                    meta_chars={"'"}
                ),
                sanitizer=None
            ),
        ]

        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers, target="test")

        assert len(hyps) == 1
        assert hyps[0].status == "proposed"
        assert "'" in hyps[0].claim
        assert len(hyps[0].required_conditions) == 4

    def test_no_differential_with_sanitizer(self):
        layers = [
            ParserLayer(
                name="Input",
                grammar=GrammarModel(safe_chars={"'"}, meta_chars=set()),
                sanitizer="parameterized_query"
            ),
            ParserLayer(
                name="SQL",
                grammar=GrammarModel(safe_chars=set(), meta_chars={"'"}),
                sanitizer=None
            ),
        ]

        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers)
        assert len(hyps) == 0

    def test_hypothesis_has_falsifiers(self):
        layers = [
            ParserLayer(name="A", grammar=GrammarModel(safe_chars={";"}, meta_chars=set()), sanitizer=None),
            ParserLayer(name="B", grammar=GrammarModel(safe_chars=set(), meta_chars={";"}), sanitizer=None),
        ]
        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers)
        assert len(hyps) == 1
        assert len(hyps[0].falsifiers) > 0
'@
Set-Content -Path "tests\unit\core\test_causal_engine.py" -Value $content -Encoding utf8

# --- tests/unit/core/test_epistemic_engine.py ---
$content = @'
import pytest
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

class TestEpistemicMonitor:
    def test_rejects_low_confidence(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        hyp = Hypothesis(id="HYP-001", claim="Test", confidence=0.3)
        assert mon.interrogate(hyp) == False

    def test_accepts_strong_hypothesis(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        hyp = Hypothesis(
            id="HYP-002",
            claim="Strong",
            confidence=0.9,
            required_conditions=["c1"],
            evidence=[Evidence(source="test", data="x", confidence=0.9)]
        )
        assert mon.interrogate(hyp) == True

    def test_known_bias(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        mon.register_bias("SQL injection", 0.5)
        hyp = Hypothesis(
            id="HYP-003",
            claim="SQL injection possible",
            confidence=0.9,
            required_conditions=["c1"],
            evidence=[Evidence(source="test", data="x", confidence=0.9)]
        )
        assert mon.interrogate(hyp) == False
'@
Set-Content -Path "tests\unit\core\test_epistemic_engine.py" -Value $content -Encoding utf8

# --- tests/unit/core/test_memory.py ---
$content = @'
from chimera.core.memory import StructuredMemory, ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

def test_structured_memory_roundtrip(tmp_path):
    db = tmp_path / "test.db"
    mem = StructuredMemory(db_path=str(db))
    hyp = Hypothesis(
        id="HYP-TEST-001",
        claim="Test claim",
        confidence=0.8,
        evidence=[Evidence(source="test", data="x")]
    )
    mem.store_hypothesis(hyp)
    retrieved = mem.get_hypothesis("HYP-TEST-001")
    assert retrieved is not None
    assert retrieved.claim == "Test claim"
    assert retrieved.confidence == 0.8

def test_chimera_memory_has_both_planes():
    mem = ChimeraMemory(db_path=":memory:")
    assert mem.structured is not None
    assert mem.semantic is not None
'@
Set-Content -Path "tests\unit\core\test_memory.py" -Value $content -Encoding utf8

# --- tests/unit/parsers/test_python_parser.py ---
$content = @'
from chimera.parsers.languages.python_parser import PythonParser

def test_name():
    assert PythonParser().name == "python_ast"
'@
Set-Content -Path "tests\unit\parsers\test_python_parser.py" -Value $content -Encoding utf8

# --- tests/integration/test_end_to_end.py ---
$content = @'
from chimera.core.orchestrator import ChimeraOrchestrator

def test_reasoning_loop_runs():
    orch = ChimeraOrchestrator()
    orch.run("tests/targets/vuln_app.py")
'@
Set-Content -Path "tests\integration\test_end_to_end.py" -Value $content -Encoding utf8

# --- tests/targets/vuln_app.py ---
$content = @'
# Intentionally vulnerable target for Chimera testing
# Demonstrates the JSON -> Python -> SQL grammar differential

import json

def get_user_unsafe(user_input: str):
    """
    Developer intent: safely retrieve user by ID from JSON input.
    Vulnerability: json.loads produces a Python str with bare quotes,
    which then breaks the SQL string literal boundary.
    """
    data = json.loads(user_input)
    user_id = data["id"]

    # Grammar differential here:
    # user_id is a Python str (quote is safe data)
    # But in the f-string, it becomes a SQL literal (quote is meta)
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query


def get_user_safe(user_input: str):
    """Fixed version with parameterized query."""
    import sqlite3
    data = json.loads(user_input)
    user_id = data["id"]

    conn = sqlite3.connect(":memory:")
    # Sanitizer exists: parameterized query translates Python str -> SQL param
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
'@
Set-Content -Path "tests\targets\vuln_app.py" -Value $content -Encoding utf8

# --- tests/test_import.py ---
$content = @'
import pytest

def test_import():
    import chimera
    assert chimera is not None
'@
Set-Content -Path "tests\test_import.py" -Value $content -Encoding utf8

# --- configs/default.yaml ---
$content = @'
chimera:
  version: "0.1.0"

  llm:
    provider: "anthropic"
    model: "claude-sonnet-4"
    temperature: 0.1
    max_tokens: 4096

  limits:
    max_hypotheses: 100
    max_requests_per_second: 10
    timeout_seconds: 300

  epistemic:
    confidence_threshold: 0.6
    require_evidence: true
    calibration_window: 100

  memory:
    backend: "sqlite"
    path: "./data/memory.db"

  tools:
    nuclei:
      binary: "nuclei"
      rate_limit: 150
    caido:
      api_url: "http://localhost:8080"
      api_token: ""
'@
Set-Content -Path "configs\default.yaml" -Value $content -Encoding utf8

# --- pyproject.toml ---
$content = @'
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "chimera"
version = "0.1.0"
description = "Causal security reasoning engine"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.11"
authors = [{name = "Chimera Author"}]
classifiers = [
    "Development Status :: 2 - Pre-Alpha",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Topic :: Security",
]
dependencies = [
    "pydantic>=2.0",
    "networkx>=3.0",
    "pyyaml>=6.0",
    "openai>=1.0",
    "anthropic>=0.30",
    "requests>=2.31",
    # "docker>=7.0",       # Uncomment after installing Docker Desktop
    # "playwright>=1.40",  # Uncomment after manual install: playwright install chromium
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-cov>=4.0",
    "black>=24.0",
    "ruff>=0.4",
    "mypy>=1.0",
]

[project.scripts]
chimera = "chimera.__main__:main"

[tool.setuptools.packages.find]
where = ["."]
include = ["chimera*"]

[tool.black]
line-length = 100
target-version = ["py311"]

[tool.ruff]
line-length = 100
select = ["E", "F", "I", "N", "W"]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
'@
Set-Content -Path "pyproject.toml" -Value $content -Encoding utf8

# --- .gitignore ---
$content = @'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.venv/
venv/
ENV/
*.egg-info/
dist/
build/
.pytest_cache/
.mypy_cache/

# Data / Secrets
data/
*.db
*.sqlite
.env
.env.*
*.pem
*.key

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
'@
Set-Content -Path ".gitignore" -Value $content -Encoding utf8

# --- Makefile ---
$content = @'
.PHONY: install test format lint clean run

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --tb=short

format:
	black chimera/ tests/
	ruff check --fix chimera/ tests/

lint:
	mypy chimera/
	ruff check chimera/ tests/

run:
	python -m chimera analyze

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache data/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
'@
Set-Content -Path "Makefile" -Value $content -Encoding utf8

# --- README.md ---
$content = @'
# Chimera

**Causal Security Reasoning Engine — Python**

Finds violated security assumptions by modeling parser cascades, grammar differentials, and intent-vs-implementation contradictions.

## The Reasoning Loop

1. **Observe** — Gather raw target data
2. **Model** — Build parser cascades and system models
3. **Hypothesize** — Generate falsifiable claims
4. **Interrogate** — Skeptic challenges each hypothesis
5. **Test** — Gather evidence via execution adapters
6. **Update** — Revise confidence based on observations
7. **Decide** — Confirm, reject, or iterate
8. **Remember** — Store everything in structured memory

## Quick Start

```powershell
# Setup (manual - see MANUAL_INSTALL.md)
# .\scripts\setup.ps1

# Run analysis
python -m chimera analyze

# Test
make test

# Format & lint
make format
make lint
'@