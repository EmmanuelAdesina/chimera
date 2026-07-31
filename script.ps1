# CHIMERA ARCHITECTURE UPDATE
# Centers the system on Hypothesis, dual memory, capability-based execution, and the reasoning loop
# Run this INSIDE your chimera repo root

$owner = "emmanueladesina"  # <-- CHANGE THIS

if (-not (Test-Path ".git")) {
    Write-Host "[ERROR] Not a git repo. cd into chimera first." -ForegroundColor Red
    exit 1
}

Write-Host "[*] Updating Chimera architecture..." -ForegroundColor Cyan

# =============================================================================
# 1. MODELS — Hypothesis is the center of the universe
# =============================================================================

# chimera/models/evidence.py
@"
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime

class Evidence(BaseModel):
    '''A single piece of evidence supporting or refuting a hypothesis.'''
n    source: str = Field(description='Where this evidence came from: code, runtime, tool, llm')\n    data: Any = Field(description='The actual evidence payload')\n    confidence: float = Field(ge=0.0, le=1.0, default=1.0, description='How much we trust this evidence')\n    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())\n    metadata: Dict[str, Any] = Field(default_factory=dict, description='Line numbers, file paths, request IDs, etc.')
"@ | Set-Content "chimera\models\evidence.py" -Encoding utf8

# chimera/models/hypothesis.py
@"
from pydantic import BaseModel, Field
from typing import List, Literal, Optional
from datetime import datetime

from chimera.models.evidence import Evidence

HypothesisStatus = Literal['proposed', 'testing', 'confirmed', 'rejected']

class Hypothesis(BaseModel):
    '''\n    The central object of Chimera.\n    \n    Everything revolves around generating, testing, and validating hypotheses.\n    A hypothesis is not a finding — it is a falsifiable claim about the target.\n    '''\n    id: str = Field(description='Unique hypothesis identifier')\n    claim: str = Field(description='The falsifiable claim, e.g. \"The application is vulnerable to SQL injection\"')\n    \n    required_conditions: List[str] = Field(\n        default_factory=list,\n        description='What must be true for this claim to hold'\n    )\n    \n    evidence: List[Evidence] = Field(\n        default_factory=list,\n        description='Observations that support the claim'\n    )\n    \n    missing_information: List[str] = Field(\n        default_factory=list,\n        description='What we still need to know to decide'\n    )\n    \n    falsifiers: List[str] = Field(\n        default_factory=list,\n        description='What observations would prove this claim false'\n    )\n    \n    confidence: float = Field(\n        ge=0.0, le=1.0, default=0.0,\n        description='Current belief strength based on evidence and gaps'\n    )\n    \n    status: HypothesisStatus = Field(default='proposed')\n    \n    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())\n    updated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())\n    \n    def add_evidence(self, evidence: Evidence) -> 'Hypothesis':\n        self.evidence.append(evidence)\n        self.updated_at = datetime.utcnow().isoformat()\n        return self\n    \n    def check_completeness(self) -> float:\n        '''\n        How complete is our evidence relative to required conditions?\n        1.0 = all required conditions have evidence\n        0.0 = no required conditions have evidence\n        '''\n        if not self.required_conditions:\n            return 0.0\n        # Simple heuristic: count evidence sources matching conditions\n        # TODO: make this semantic\n        return min(1.0, len(self.evidence) / max(1, len(self.required_conditions)))\n    \n    def is_falsified(self) -> bool:\n        '''Check if any evidence directly contradicts the claim.'''\n        # TODO: implement contradiction detection\n        return False
"@ | Set-Content "chimera\models\hypothesis.py" -Encoding utf8

# Update chimera/models/__init__.py
@"
from chimera.models.evidence import Evidence
from chimera.models.hypothesis import Hypothesis, HypothesisStatus
from chimera.models.causal import (
    GrammarModel, ParserLayerModel, DifferentialReport, CascadeAnalysis, BeliefModel
)

__all__ = [
    'Evidence',\n    'Hypothesis',\n    'HypothesisStatus',\n    'GrammarModel',\n    'ParserLayerModel',\n    'DifferentialReport',\n    'CascadeAnalysis',\n    'BeliefModel',\n]
"@ | Set-Content "chimera\models\__init__.py" -Encoding utf8

# =============================================================================
# 2. MEMORY PLANE — Structured (source of truth) + Semantic (retrieval)
# =============================================================================

# chimera/core/memory.py — complete rewrite
@"
from typing import List, Dict, Optional, Any
import sqlite3
import json
from datetime import datetime

from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


class StructuredMemory:
n    '''\n    SQLite-backed source of truth for all Chimera reasoning artifacts.\n    \n    Stores:\n    - Findings (confirmed hypotheses)\n    - Hypotheses (all stages)\n    - Evidence (observations)\n    - Decisions (why we did what we did)\n    - Failures (what went wrong and why)\n    \n    This is the source of truth. Everything else is derived.\n    '''\n\n    def __init__(self, db_path: str = './data/memory.db'):\n        self.db_path = db_path\n        self._init_db()\n    \n    def _init_db(self):\n        import os\n        os.makedirs('data', exist_ok=True)\n        conn = sqlite3.connect(self.db_path)\n        c = conn.cursor()\n        \n        c.execute('''\n            CREATE TABLE IF NOT EXISTS hypotheses (\n                id TEXT PRIMARY KEY,\n                claim TEXT NOT NULL,\n                required_conditions TEXT,  -- JSON list\n                evidence TEXT,             -- JSON list of Evidence\n                missing_information TEXT,  -- JSON list\n                falsifiers TEXT,           -- JSON list\n                confidence REAL,\n                status TEXT,\n                created_at TEXT,\n                updated_at TEXT\n            )\n        ''')\n        \n        c.execute('''\n            CREATE TABLE IF NOT EXISTS findings (\n                id INTEGER PRIMARY KEY,\n                hypothesis_id TEXT,\n                target TEXT,\n                severity TEXT,\n                description TEXT,\n                proof TEXT,\n                timestamp TEXT,\n                FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id)\n            )\n        ''')\n        \n        c.execute('''\n            CREATE TABLE IF NOT EXISTS decisions (\n                id INTEGER PRIMARY KEY,\n                context TEXT,\n                action TEXT,\n                reasoning TEXT,\n                outcome TEXT,\n                timestamp TEXT\n            )\n        ''')\n        \n        c.execute('''\n            CREATE TABLE IF NOT EXISTS failures (\n                id INTEGER PRIMARY KEY,\n                hypothesis_id TEXT,\n                failure_type TEXT,\n                root_cause TEXT,\n                correction TEXT,\n                timestamp TEXT,\n                FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id)\n            )\n        ''')\n        \n        conn.commit()\n        conn.close()\n    \n    def store_hypothesis(self, hypothesis: Hypothesis):\n        conn = sqlite3.connect(self.db_path)\n        c = conn.cursor()\n        c.execute('''\n            INSERT OR REPLACE INTO hypotheses\n            (id, claim, required_conditions, evidence, missing_information,\n             falsifiers, confidence, status, created_at, updated_at)\n            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)\n        ''', (\n            hypothesis.id,\n            hypothesis.claim,\n            json.dumps(hypothesis.required_conditions),\n            json.dumps([e.model_dump() for e in hypothesis.evidence]),\n            json.dumps(hypothesis.missing_information),\n            json.dumps(hypothesis.falsifiers),\n            hypothesis.confidence,\n            hypothesis.status,\n            hypothesis.created_at,\n            hypothesis.updated_at\n        ))\n        conn.commit()\n        conn.close()\n    \n    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:\n        conn = sqlite3.connect(self.db_path)\n        c = conn.cursor()\n        c.execute('SELECT * FROM hypotheses WHERE id = ?', (hypothesis_id,))\n        row = c.fetchone()\n        conn.close()\n        \n        if not row:\n            return None\n        \n        return Hypothesis(\n            id=row[0],\n            claim=row[1],\n            required_conditions=json.loads(row[2]),\n            evidence=[Evidence(**e) for e in json.loads(row[3])],\n            missing_information=json.loads(row[4]),\n            falsifiers=json.loads(row[5]),\n            confidence=row[6],\n            status=row[7],\n            created_at=row[8],\n            updated_at=row[9]\n        )\n    \n    def store_failure(self, hypothesis_id: str, failure_type: str, \n                      root_cause: str, correction: str):\n        conn = sqlite3.connect(self.db_path)\n        c = conn.cursor()\n        c.execute('''\n            INSERT INTO failures\n            (hypothesis_id, failure_type, root_cause, correction, timestamp)\n            VALUES (?, ?, ?, ?, ?)\n        ''', (hypothesis_id, failure_type, root_cause, correction, \n              datetime.utcnow().isoformat()))\n        conn.commit()\n        conn.close()\n    \n    def get_failure_patterns(self, limit: int = 50) -> List[Dict]:\n        '''Extract patterns from failures for the epistemic engine.'''\n        conn = sqlite3.connect(self.db_path)\n        c = conn.cursor()\n        c.execute('''\n            SELECT failure_type, root_cause, COUNT(*) as count\n            FROM failures\n            GROUP BY failure_type, root_cause\n            ORDER BY count DESC\n            LIMIT ?\n        ''', (limit,))\n        rows = c.fetchall()\n        conn.close()\n        return [\n            {'type': r[0], 'cause': r[1], 'count': r[2]}\n            for r in rows\n        ]\n\n\nclass SemanticMemory:\n    '''\n    Vector-backed retrieval memory for similar patterns, code, and reasoning chains.\n    \n    This is NOT the source of truth. It helps retrieve relevant context\n    from the structured memory and external corpora.\n    \n    Use cases:\n    - \"Have we seen a parser cascade like this before?\"\n    - \"What hypotheses worked on similar code patterns?\"\n    - \"Retrieve previous reasoning chains for this vulnerability class\"\n    '''\n\n    def __init__(self, backend: str = 'sqlite_vec'):\n        self.backend = backend\n        # TODO: integrate chromadb or sqlite-vec for embeddings\n        # For now, this is a stub that the epistemic engine can query\n        self._embeddings: Dict[str, List[float]] = {}\n    \n    def index_hypothesis(self, hypothesis: Hypothesis):\n        '''Compute embedding for hypothesis claim and store.'''\n        # TODO: use sentence-transformers or OpenAI embeddings\n        pass\n    \n    def query_similar(self, text: str, k: int = 5) -> List[str]:\n        '''Return IDs of similar past hypotheses/findings.'''\n        # TODO: implement similarity search\n        return []\n    \n    def index_code_pattern(self, pattern_id: str, code_snippet: str, \n                           metadata: Dict[str, Any]):\n        '''Index a code pattern for retrieval.'''\n        pass\n\n\nclass ChimeraMemory:\n    '''Unified interface: structured is truth, semantic is retrieval.'''\n    \n    def __init__(self, db_path: str = './data/memory.db'):\n        self.structured = StructuredMemory(db_path)\n        self.semantic = SemanticMemory()\n"@ | Set-Content "chimera\core\memory.py" -Encoding utf8

# =============================================================================
# 3. EXECUTION PLANE — Capabilities, not products
# =============================================================================

# Remove old bridges, create capability-based adapters
Remove-Item "chimera\tools\nuclei_bridge.py" -ErrorAction SilentlyContinue
Remove-Item "chimera\tools\caido_bridge.py" -ErrorAction SilentlyContinue

# chimera/execution/__init__.py
New-Item -ItemType File -Path "chimera\execution\__init__.py" -Force | Out-Null

# chimera/execution/base.py
@"
from abc import ABC, abstractmethod
from typing import Any, Dict, List

class ExecutionAdapter(ABC):
n    '''\n    Abstract base for all execution capabilities.\n    \n    Adapters translate Chimera's intent into specific tool actions.\n    The capability (what we want to do) is stable.\n    The adapter (which tool does it) is replaceable.\n    '''\n\n    @property\n    @abstractmethod\n    def capability(self) -> str:\n        '''What capability this adapter provides.'''\n        raise NotImplementedError\n\n    @abstractmethod\n    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:\n        '''Execute the intent and return observations.'''\n        raise NotImplementedError\n\n    @abstractmethod\n    def health_check(self) -> bool:\n        '''Is this adapter available and functional?'''\n        raise NotImplementedError
"@ | Set-Content "chimera\execution\base.py" -Encoding utf8

# chimera/execution/observation.py
@"
from chimera.execution.base import ExecutionAdapter
from typing import Any, Dict
import subprocess
import json

class NucleiObservationAdapter(ExecutionAdapter):
n    '''\n    Capability: Observation\n    Adapter: Nuclei\n    \n    Observes target surface: technologies, known CVEs, exposed endpoints.\n    '''\n\n    @property\n    def capability(self) -> str:\n        return 'observation'\n\n    def __init__(self, binary: str = 'nuclei', rate_limit: int = 150):\n        self.binary = binary\n        self.rate_limit = rate_limit\n\n    def health_check(self) -> bool:\n        try:\n            subprocess.run([self.binary, '-version'], \n                         capture_output=True, check=True)\n            return True\n        except (subprocess.CalledProcessError, FileNotFoundError):\n            return False\n\n    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:\n        target = intent.get('target')\n        if not target:\n            return {'error': 'No target provided'}\n        \n        cmd = [\n            self.binary, '-u', target,\n            '-rate-limit', str(self.rate_limit),\n            '-jsonl', '-o', '/tmp/nuclei_chimera.jsonl'\n        ]\n        subprocess.run(cmd, capture_output=True)\n        \n        findings = []\n        try:\n            with open('/tmp/nuclei_chimera.jsonl') as f:\n                for line in f:\n                    if not line.strip():\n                        continue\n                    data = json.loads(line)\n                    findings.append({\n                        'template_id': data.get('template-id'),\n                        'severity': data.get('info', {}).get('severity'),\n                        'matched_at': data.get('matched-at'),\n                        'description': data.get('info', {}).get('description')\n                    })\n        except FileNotFoundError:\n            pass\n        \n        return {\n            'capability': 'observation',\n            'adapter': 'nuclei',\n            'findings': findings,\n            'count': len(findings)\n        }
"@ | Set-Content "chimera\execution\observation.py" -Encoding utf8

# chimera/execution/controlled_testing.py
@"
from chimera.execution.base import ExecutionAdapter
from typing import Any, Dict
import requests

class CaidoTestingAdapter(ExecutionAdapter):
n    '''\n    Capability: Controlled Testing\n    Adapter: Caido\n    \n    Sends crafted requests, observes responses, detects anomalies.\n    '''\n\n    @property\n    def capability(self) -> str:\n        return 'controlled_testing'\n\n    def __init__(self, api_url: str = 'http://localhost:8080', token: str = ''):\n        self.api_url = api_url\n        self.headers = {'Authorization': f'Bearer {token}'}\n        self._baseline_cache: Dict[str, Dict] = {}\n\n    def health_check(self) -> bool:\n        try:\n            r = requests.get(f'{self.api_url}/graphql', \n                           headers=self.headers, timeout=2)\n            return r.status_code < 500\n        except requests.RequestException:\n            return False\n\n    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:\n        action = intent.get('action')\n        \n        if action == 'capture_baseline':\n            return self._capture_baseline(intent.get('request_spec', {}))\n        elif action == 'send_test':\n            return self._send_test(\n                intent.get('request_spec', {}),\n                intent.get('payload', '')\n            )\n        return {'error': f'Unknown action: {action}'}\n\n    def _capture_baseline(self, spec: Dict) -> Dict:\n        # TODO: integrate Caido GraphQL API\n        path = spec.get('path', '/')\n        self._baseline_cache[path] = {'status': 200, 'length': 0}\n        return {'capability': 'controlled_testing', 'action': 'baseline', 'path': path}\n\n    def _send_test(self, spec: Dict, payload: str) -> Dict:\n        path = spec.get('path', '/')\n        baseline = self._baseline_cache.get(path)\n        \n        # TODO: actual Caido integration\n        anomalies = []\n        if baseline and len(payload) > 100:\n            anomalies.append('payload_size_anomaly')\n        \n        return {\n            'capability': 'controlled_testing',\n            'adapter': 'caido',\n            'path': path,\n            'anomalies': anomalies,\n            'response_status': 200\n        }
"@ | Set-Content "chimera\execution\controlled_testing.py" -Encoding utf8

# chimera/execution/environment_interaction.py
@"
from chimera.execution.base import ExecutionAdapter
from typing import Any, Dict

class BrowserInteractionAdapter(ExecutionAdapter):
n    '''\n    Capability: Environment Interaction\n    Adapter: Playwright / Browser\n    \n    Interacts with web applications as a user would.\n    '''\n\n    @property\n    def capability(self) -> str:\n        return 'environment_interaction'\n\n    def health_check(self) -> bool:\n        # TODO: check if playwright is installed\n        return False\n\n    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:\n        return {'capability': 'environment_interaction', 'status': 'not_implemented'}

class TerminalAdapter(ExecutionAdapter):
n    '''\n    Capability: Environment Interaction\n    Adapter: Local/Remote Shell\n    \n    Executes commands in target environment (post-exploitation, container exec).\n    '''\n\n    @property\n    def capability(self) -> str:\n        return 'environment_interaction'\n\n    def health_check(self) -> bool:\n        return True  # Always available locally\n\n    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:\n        import subprocess\n        command = intent.get('command')\n        if not command:\n            return {'error': 'No command provided'}\n        \n        result = subprocess.run(command, shell=True, capture_output=True, text=True)\n        return {\n            'capability': 'environment_interaction',\n            'adapter': 'terminal',\n            'returncode': result.returncode,\n            'stdout': result.stdout,\n            'stderr': result.stderr\n        }
"@ | Set-Content "chimera\execution\environment_interaction.py" -Encoding utf8

# chimera/execution/runtime_verification.py
@"
from chimera.execution.base import ExecutionAdapter
from typing import Any, Dict

class RuntimeVerificationAdapter(ExecutionAdapter):
n    '''\n    Capability: Runtime Verification\n    Adapter: Custom instrumentation\n    \n    Verifies whether a hypothesized vulnerability is actually exploitable\n    at runtime without causing damage.\n    '''\n\n    @property\n    def capability(self) -> str:\n        return 'runtime_verification'\n\n    def health_check(self) -> bool:\n        return True\n\n    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:\n        verification_type = intent.get('type')\n        \n        if verification_type == 'time_based':\n            return self._verify_time_based(intent)\n        elif verification_type == 'error_based':\n            return self._verify_error_based(intent)\n        elif verification_type == 'out_of_band':\n            return self._verify_oob(intent)\n        \n        return {'error': f'Unknown verification type: {verification_type}'}\n\n    def _verify_time_based(self, intent: Dict) -> Dict:\n        # Verify SQLi via time delay without destructive queries\n        return {'verified': False, 'method': 'time_based', 'details': 'Not implemented'}\n\n    def _verify_error_based(self, intent: Dict) -> Dict:\n        # Verify via error message analysis\n        return {'verified': False, 'method': 'error_based', 'details': 'Not implemented'}\n\n    def _verify_oob(self, intent: Dict) -> Dict:\n        # Verify via out-of-band interaction (DNS, HTTP callback)\n        return {'verified': False, 'method': 'out_of_band', 'details': 'Not implemented'}
"@ | Set-Content "chimera\execution\runtime_verification.py" -Encoding utf8

# chimera/execution/registry.py
@"
from typing import Dict, List, Type
from chimera.execution.base import ExecutionAdapter

class ExecutionRegistry:
n    '''\n    Central registry for execution capabilities.\n    \n    Usage:\n        registry = ExecutionRegistry()\n        registry.register(NucleiObservationAdapter())\n        \n        obs = registry.get_capability('observation')\n        result = obs.execute({'target': 'http://example.com'})\n    '''\n\n    def __init__(self):\n        self._adapters: Dict[str, ExecutionAdapter] = {}\n        self._capabilities: Dict[str, List[str]] = {}\n\n    def register(self, adapter: ExecutionAdapter):\n        name = adapter.__class__.__name__\n        self._adapters[name] = adapter\n        \n        cap = adapter.capability\n        if cap not in self._capabilities:\n            self._capabilities[cap] = []\n        self._capabilities[cap].append(name)\n\n    def get_capability(self, capability: str) -> ExecutionAdapter:\n        '''Get the first healthy adapter for a capability.'''\n        names = self._capabilities.get(capability, [])\n        for name in names:\n            adapter = self._adapters[name]\n            if adapter.health_check():\n                return adapter\n        raise RuntimeError(f'No healthy adapter for capability: {capability}')\n\n    def list_capabilities(self) -> Dict[str, List[str]]:\n        return {\n            cap: [n for n in names if self._adapters[n].health_check()]\n            for cap, names in self._capabilities.items()\n        }
"@ | Set-Content "chimera\execution\registry.py" -Encoding utf8

# =============================================================================
# 4. CORE — Update Causal Engine to produce Hypotheses
# =============================================================================

# chimera/core/causal_engine.py
@"
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
n    '''\n    Analyzes parser cascades for grammar differentials.\n    Produces Hypothesis objects, not just reports.\n    '''\n\n    def __init__(self):\n        self.differentials: List[DifferentialReport] = []\n\n    def analyze_cascade(self, layers: List[ParserLayer], target: str = '') -> List[Hypothesis]:\n        '''\n        Analyze parser cascade and return Hypothesis objects for each differential.\n        '''\n        hypotheses = []\n        \n        for i in range(len(layers) - 1):\n            current = layers[i]\n            next_layer = layers[i + 1]\n            \n            unescaped_meta = current.grammar.safe_chars & next_layer.grammar.meta_chars\n            \n            if unescaped_meta and not current.sanitizer:\n                diff = DifferentialReport(\n                    boundary=f'{current.name} → {next_layer.name}',\n                    dangerous_chars=unescaped_meta,\n                    developer_assumption=f'{current.name} output is safe for {next_layer.name}',\n                    actual_risk=f'Characters {unescaped_meta} are meta in {next_layer.name}',\n                    fix_recommendation=f'Insert sanitizer at boundary: escape {unescaped_meta} for {next_layer.name} grammar',\n                    confidence=0.95,\n                    evidence=[f'No sanitizer between {current.name} and {next_layer.name}']\n                )\n                \n                # Convert differential to hypothesis\n                hypothesis = self._differential_to_hypothesis(diff, target, layers)\n                hypotheses.append(hypothesis)\n        \n        return hypotheses\n\n    def _differential_to_hypothesis(self, diff: DifferentialReport, target: str, \n                                      layers: List[ParserLayer]) -> Hypothesis:\n        '''Transform a grammar differential into a falsifiable hypothesis.'''\n        \n        # Extract the dangerous character(s)\n        chars = ', '.join(diff.dangerous_chars)\n        \n        claim = (\n            f'Grammar differential at {diff.boundary}: '\n            f'character(s) [{chars}] are data in the upstream layer '\n            f'but meta-characters in the downstream layer, '\n            f'and no sanitizer translates between grammars.'\n        )\n        \n        return Hypothesis(\n            id=f'HYP-{hash(diff.boundary) % 10000:04d}',\n            claim=claim,\n            required_conditions=[\n                f'Data flows from {diff.boundary.split(\" → \")[0]} to {diff.boundary.split(\" → \")[1]}',\n                f'Character(s) {diff.dangerous_chars} appear in attacker-controlled input',\n                f'No sanitizer exists at the boundary',\n                f'Downstream layer interprets {diff.dangerous_chars} as control characters'\n            ],\n            evidence=[\n                Evidence(\n                    source='causal_engine',\n                    data=diff.model_dump(),\n                    confidence=diff.confidence,\n                    metadata={'boundary': diff.boundary, 'target': target}\n                )\n            ],\n            missing_information=[\n                'Attacker-controlled input path to the boundary',\n                'Runtime execution confirmation',\n                'WAF or defense layer interference'\n            ],\n            falsifiers=[\n                f'Input never contains {diff.dangerous_chars}',\n                'A sanitizer exists but was not detected',\n                'Downstream layer is not actually reached by user input',\n                'The application uses parameterized queries at a higher layer'\n            ],\n            confidence=diff.confidence * 0.7,  # Penalty for missing runtime evidence\n            status='proposed'\n        )
"@ | Set-Content "chimera\core\causal_engine.py" -Encoding utf8

# =============================================================================
# 5. CORE — Update Epistemic Engine to interrogate Hypotheses
# =============================================================================

# chimera/core/epistemic_engine.py
@"
from typing import List, Dict, Optional
from datetime import datetime

from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


class EpistemicMonitor:
n    '''\n    Interrogates Hypotheses before they become beliefs.\n    \n    Every hypothesis must survive:\n    - \"What evidence supports this?\"\n    - \"What would prove this false?\"\n    - \"What are we assuming that we haven't verified?\"\n    '''\n\n    def __init__(self, confidence_threshold: float = 0.6):\n        self.confidence_threshold = confidence_threshold\n        self.known_biases: Dict[str, float] = {}\n        self.interrogation_history: List[Dict] = []\n\n    def interrogate(self, hypothesis: Hypothesis) -> bool:\n        '''\n        The Skeptic interrogates a hypothesis.\n        Returns True if hypothesis survives, False if rejected.\n        '''\n        failures = []\n        \n        # Check 1: Confidence too low\n        if hypothesis.confidence < self.confidence_threshold:\n            failures.append(f'Confidence {hypothesis.confidence} below threshold {self.confidence_threshold}')\n        \n        # Check 2: No evidence\n        if not hypothesis.evidence:\n            failures.append('Zero evidence provided')\n        \n        # Check 3: All required conditions have evidence?\n        evidence_coverage = hypothesis.check_completeness()\n        if evidence_coverage < 0.5:\n            failures.append(f'Evidence coverage only {evidence_coverage:.2f}')\n        \n        # Check 4: Known biases\n        for bias, failure_rate in self.known_biases.items():\n            if bias.lower() in hypothesis.claim.lower():\n                adjusted = hypothesis.confidence * (1 - failure_rate)\n                if adjusted < self.confidence_threshold:\n                    failures.append(f'Known bias \"{bias}\" reduces effective confidence to {adjusted:.2f}')\n        \n        # Check 5: Missing critical information\n        critical_missing = [m for m in hypothesis.missing_information \n                           if 'runtime' in m.lower() or 'execution' in m.lower()]\n        if len(critical_missing) > 2:\n            failures.append(f'Too much missing runtime information: {len(critical_missing)} items')\n        \n        result = len(failures) == 0\n        \n        self.interrogation_history.append({\n            'hypothesis_id': hypothesis.id,\n            'timestamp': datetime.utcnow().isoformat(),\n            'survived': result,\n            'failures': failures,\n            'original_confidence': hypothesis.confidence\n        })\n        \n        return result\n\n    def calibrate(self, hypothesis: Hypothesis, actual_outcome: str):\n        '''\n        After testing, record whether the hypothesis was correct.\n        Used to update known biases.\n        '''\n        was_correct = actual_outcome == 'confirmed'\n        \n        # Find patterns in incorrect hypotheses\n        if not was_correct:\n            for condition in hypothesis.required_conditions:\n                # Track which conditions keep failing\n                pass  # TODO: implement bias learning\n\n    def register_bias(self, assumption_pattern: str, historical_failure_rate: float):\n        self.known_biases[assumption_pattern] = historical_failure_rate\n\n    def calibration_report(self) -> Dict:\n        if not self.interrogation_history:\n            return {'status': 'no_interrogations'}\n        \n        total = len(self.interrogation_history)\n        passed = sum(1 for h in self.interrogation_history if h['survived'])\n        \n        return {\n            'total_interrogated': total,\n            'survived': passed,\n            'rejected': total - passed,\n            'survival_rate': passed / total if total > 0 else 0,\n            'known_biases': len(self.known_biases)\n        }
"@ | Set-Content "chimera\core\epistemic_engine.py" -Encoding utf8

# =============================================================================
# 6. CORE — Update Orchestrator with the Reasoning Loop
# =============================================================================

# chimera/core/orchestrator.py
@"
from typing import List
from pathlib import Path

from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.core.memory import ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.causal import GrammarModel


class ChimeraOrchestrator:
n    '''\n    The Reasoning Loop:\n    \n    1. OBSERVE        — Gather raw data about the target\n    2. MODEL          — Build parser cascades and system models\n    3. HYPOTHESIZE    — Generate falsifiable claims\n    4. INTERROGATE    — Skeptic challenges each hypothesis\n    5. TEST           — Gather evidence via execution adapters\n    6. UPDATE         — Revise confidence based on observations\n    7. DECIDE         — Confirm, reject, or iterate\n    8. REMEMBER       — Store everything in structured memory\n    '''\n\n    def __init__(self, config_path: str = 'configs/default.yaml'):\n        self.causal = CausalEngine()\n        self.epistemic = EpistemicMonitor(confidence_threshold=0.6)\n        self.memory = ChimeraMemory()\n        self.config_path = config_path\n        self.hypotheses: List[Hypothesis] = []\n    \n    def run(self, target: str):\n        print(f'[CHIMERA] Starting Reasoning Loop on: {target}')\n        print('=' * 60)\n        \n        # === 1. OBSERVE ===\n        print('[1] OBSERVE: Gathering target surface...')\n        observations = self._observe(target)\n        print(f'    → {len(observations)} raw observations')\n        \n        # === 2. MODEL ===\n        print('[2] MODEL: Building parser cascades...')\n        cascades = self._build_cascades(target, observations)\n        print(f'    → {len(cascades)} parser cascades modeled')\n        \n        # === 3. HYPOTHESIZE ===\n        print('[3] HYPOTHESIZE: Generating falsifiable claims...')\n        for cascade in cascades:\n            hyps = self.causal.analyze_cascade(cascade, target=target)\n            self.hypotheses.extend(hyps)\n        print(f'    → {len(self.hypotheses)} hypotheses generated')\n        \n        # === 4. INTERROGATE ===\n        print('[4] INTERROGATE: Skeptic challenges hypotheses...')\n        survivors = []\n        for hyp in self.hypotheses:\n            if self.epistemic.interrogate(hyp):\n                hyp.status = 'testing'\n                survivors.append(hyp)\n                print(f'    ✓ {hyp.id}: {hyp.claim[:60]}...')\n            else:\n                hyp.status = 'rejected'\n                print(f'    ✗ {hyp.id}: REJECTED')\n        print(f'    → {len(survivors)} survived interrogation')\n        \n        # === 5. TEST ===\n        print('[5] TEST: Gathering runtime evidence...')\n        for hyp in survivors:\n            self._test_hypothesis(hyp, target)\n        \n        # === 6. UPDATE ===\n        print('[6] UPDATE: Revising confidence...')\n        for hyp in survivors:\n            self._update_confidence(hyp)\n        \n        # === 7. DECIDE ===\n        print('[7] DECIDE: Final classification...')\n        confirmed = []\n        for hyp in survivors:\n            if hyp.confidence > 0.85 and hyp.check_completeness() > 0.8:\n                hyp.status = 'confirmed'\n                confirmed.append(hyp)\n            elif hyp.confidence < 0.3:\n                hyp.status = 'rejected'\n        print(f'    → {len(confirmed)} CONFIRMED')\n        \n        # === 8. REMEMBER ===\n        print('[8] REMEMBER: Storing in structured memory...')\n        for hyp in self.hypotheses:\n            self.memory.structured.store_hypothesis(hyp)\n        print('    → All hypotheses stored')\n        \n        self._print_report(confirmed)\n    \n    def _observe(self, target: str) -> List[dict]:\n        '''Phase 1: Raw observation.'''\n        # TODO: integrate execution adapters\n        return [{'source': 'static', 'type': 'file', 'path': target}]\n    \n    def _build_cascades(self, target: str, observations: List[dict]) -> List[List[ParserLayer]]:\n        '''Phase 2: Build parser cascades from observations.'''\n        # For now, return the canonical JSON->Python->SQL cascade\n        return [[\n            ParserLayer(\n                name='JSON',\n                grammar=GrammarModel(\n                    safe_chars={'a','b',' ','\\'', '\\\\'},\n                    meta_chars={'\\\\', '\"'},\n                    escape_rules={'\\\\': '\\\\\\\\', '\"': '\\\\\"'}\n                ),\n                sanitizer='JSON RFC 8259 escape'\n            ),\n            ParserLayer(\n                name='Python_str',\n                grammar=GrammarModel(\n                    safe_chars={'a','b',' ','\\''},\n                    meta_chars=set()\n                ),\n                sanitizer=None\n            ),\n            ParserLayer(\n                name='SQL_literal',\n                grammar=GrammarModel(\n                    safe_chars={'a','b',' '},\n                    meta_chars={'\\''}\n                ),\n                sanitizer=None\n            ),\n        ]]\n    \n    def _test_hypothesis(self, hyp: Hypothesis, target: str):\n        '''Phase 5: Gather runtime evidence.'''\n        # TODO: use execution adapters to test\n        # For now, simulate evidence gathering\n        from chimera.models.evidence import Evidence\n        hyp.add_evidence(Evidence(\n            source='static_analysis',\n            data={'finding': 'f-string query construction detected'},\n            confidence=0.8,\n            metadata={'file': target}\n        ))\n    \n    def _update_confidence(self, hyp: Hypothesis):\n        '''Phase 6: Bayesian-ish confidence update.'''\n        if not hyp.evidence:\n            return\n        \n        # Simple model: average evidence confidence weighted by source reliability\n        total_conf = sum(e.confidence for e in hyp.evidence)\n        avg_conf = total_conf / len(hyp.evidence)\n        \n        # Penalize missing information\n        missing_penalty = 0.1 * len(hyp.missing_information)\n        \n        hyp.confidence = max(0.0, min(1.0, avg_conf - missing_penalty))\n    \n    def _print_report(self, confirmed: List[Hypothesis]):\n        print('\\n' + '=' * 60)\n        print('CHIMERA REASONING LOOP REPORT')\n        print('=' * 60)\n        print(f'Total hypotheses generated: {len(self.hypotheses)}')\n        print(f'Confirmed: {len(confirmed)}')\n        print(f'Rejected: {sum(1 for h in self.hypotheses if h.status == \"rejected\")}')\n        print(f'In testing: {sum(1 for h in self.hypotheses if h.status == \"testing\")}')\n        \n        if confirmed:\n            print('\\n--- CONFIRMED FINDINGS ---')\n            for hyp in confirmed:\n                print(f'\\n[{hyp.id}] {hyp.claim[:80]}')\n                print(f'    Confidence: {hyp.confidence:.2f}')\n                print(f'    Evidence: {len(hyp.evidence)} items')\n                print(f'    Missing: {len(hyp.missing_information)} items')\n        print('=' * 60)
"@ | Set-Content "chimera\core\orchestrator.py" -Encoding utf8

# =============================================================================
# 7. TESTS — Update to match new architecture
# =============================================================================

# tests/unit/core/test_causal_engine.py
@"
import pytest
from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.models.causal import GrammarModel

class TestCausalEngine:
n    def test_json_python_sql_differential(self):\n        layers = [\n            ParserLayer(\n                name='JSON',\n                grammar=GrammarModel(\n                    safe_chars={'a', 'b', \"'\", '\\\\', ' '},\n                    meta_chars={'\\\\', '\"'},\n                    escape_rules={'\\\\': '\\\\\\\\', '\"': '\\\\\"'}\n                ),\n                sanitizer='JSON RFC 8259 escape'\n            ),\n            ParserLayer(\n                name='Python_str',\n                grammar=GrammarModel(\n                    safe_chars={'a', 'b', \"'\", ' '},\n                    meta_chars=set()\n                ),\n                sanitizer=None\n            ),\n            ParserLayer(\n                name='SQL_literal',\n                grammar=GrammarModel(\n                    safe_chars={'a', 'b', ' '},\n                    meta_chars={\"'\"}\n                ),\n                sanitizer=None\n            ),\n        ]\n        \n        engine = CausalEngine()\n        hyps = engine.analyze_cascade(layers, target='test')\n        \n        assert len(hyps) == 1\n        hyp = hyps[0]\n        assert hyp.status == 'proposed'\n        assert \"'\" in hyp.claim\n        assert len(hyp.required_conditions) == 4\n        assert len(hyp.falsifiers) == 4\n        assert hyp.confidence > 0.0\n\n    def test_no_differential_with_sanitizer(self):\n        layers = [\n            ParserLayer(\n                name='Input',\n                grammar=GrammarModel(safe_chars={\"'\"}, meta_chars=set()),\n                sanitizer='parameterized_query'\n            ),\n            ParserLayer(\n                name='SQL',\n                grammar=GrammarModel(safe_chars=set(), meta_chars={\"'\"}),\n                sanitizer=None\n            ),\n        ]\n        \n        engine = CausalEngine()\n        hyps = engine.analyze_cascade(layers)\n        assert len(hyps) == 0\n\n    def test_hypothesis_has_falsifiers(self):\n        layers = [\n            ParserLayer(name='A', grammar=GrammarModel(safe_chars={';'}, meta_chars=set()), sanitizer=None),\n            ParserLayer(name='B', grammar=GrammarModel(safe_chars=set(), meta_chars={';'}), sanitizer=None),\n        ]\n        engine = CausalEngine()\n        hyps = engine.analyze_cascade(layers)\n        assert len(hyps) == 1\n        assert len(hyps[0].falsifiers) > 0
"@ | Set-Content "tests\unit\core\test_causal_engine.py" -Encoding utf8

# tests/unit/core/test_epistemic_engine.py
@"
import pytest
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

class TestEpistemicMonitor:
n    def test_interrogation_rejects_low_confidence(self):\n        mon = EpistemicMonitor(confidence_threshold=0.6)\n        hyp = Hypothesis(\n            id='HYP-001',\n            claim='Test claim',\n            confidence=0.3\n        )\n        assert mon.interrogate(hyp) == False\n\n    def test_interrogation_accepts_strong_hypothesis(self):\n        mon = EpistemicMonitor(confidence_threshold=0.6)\n        hyp = Hypothesis(\n            id='HYP-002',\n            claim='Strong claim',\n            confidence=0.9,\n            required_conditions=['cond1'],\n            evidence=[Evidence(source='test', data='x', confidence=0.9)]\n        )\n        assert mon.interrogate(hyp) == True\n\n    def test_known_bias_reduces_effective_confidence(self):\n        mon = EpistemicMonitor(confidence_threshold=0.6)\n        mon.register_bias('SQL injection', 0.5)\n        \n        hyp = Hypothesis(\n            id='HYP-003',\n            claim='SQL injection possible',\n            confidence=0.9,\n            required_conditions=['cond1'],\n            evidence=[Evidence(source='test', data='x', confidence=0.9)]\n        )\n        # 0.9 * (1 - 0.5) = 0.45 < 0.6 threshold\n        assert mon.interrogate(hyp) == False
"@ | Set-Content "tests\unit\core\test_epistemic_engine.py" -Encoding utf8

# tests/unit/core/test_memory.py
@"
from chimera.core.memory import StructuredMemory, SemanticMemory, ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

def test_structured_memory_roundtrip(tmp_path):\n    db = tmp_path / 'test.db'\n    mem = StructuredMemory(db_path=str(db))\n    \n    hyp = Hypothesis(\n        id='HYP-TEST-001',\n        claim='Test claim',\n        confidence=0.8,\n        evidence=[Evidence(source='test', data='x')]\n    )\n    \n    mem.store_hypothesis(hyp)\n    retrieved = mem.get_hypothesis('HYP-TEST-001')\n    \n    assert retrieved is not None\n    assert retrieved.claim == 'Test claim'\n    assert retrieved.confidence == 0.8\n    assert len(retrieved.evidence) == 1\n\ndef test_chimera_memory_has_both_planes():\n    mem = ChimeraMemory(db_path=':memory:')\n    assert mem.structured is not None\n    assert mem.semantic is not None
"@ | Set-Content "tests\unit\core\test_memory.py" -Encoding utf8

# tests/integration/test_end_to_end.py
@"
from chimera.core.orchestrator import ChimeraOrchestrator

def test_reasoning_loop_runs_without_crash():\n    orch = ChimeraOrchestrator()\n    orch.run('tests/targets/vuln_app.py')
n    # If we get here without exception, the loop is wired correctly
"@ | Set-Content "tests\integration\test_end_to_end.py" -Encoding utf8

# =============================================================================
# 8. ARCHITECTURE DOCS — Reasoning Loop + Updated Planes
# =============================================================================

# docs/architecture/ARCHITECTURE.md
@"
# Chimera Architecture

## The Reasoning Loop

Chimera is not a scanner. It is a reasoning engine. Everything flows through this loop:

```\n1. OBSERVE\n      |\n      v\n2. MODEL (Build parser cascades, system models)\n      |\n      v\n3. HYPOTHESIZE (Generate falsifiable claims)\n      |\n      v\n4. INTERROGATE (Skeptic challenges each hypothesis)\n      |\n      v\n5. TEST (Gather evidence via execution adapters)\n      |\n      v\n6. UPDATE (Revise confidence based on observations)\n      |\n      v\n7. DECIDE (Confirm, reject, or iterate)\n      |\n      v\n8. REMEMBER (Store in structured memory)\n      |\n      +---> Back to 1 (with what we learned)\n```

This separates Chimera from every scanner on the market. Scanners skip steps 2, 3, 4, and 6. They observe, then report. Chimera observes, models, claims, challenges, tests, revises, decides, and remembers.

## The Central Object: Hypothesis

Everything revolves around `Hypothesis`:

| Field | Purpose |
|-------|---------|
| `claim` | The falsifiable statement |
| `required_conditions` | What must be true for the claim to hold |
| `evidence` | Observations that support the claim |
| `missing_information` | What we still need to know |
| `falsifiers` | What would prove this claim false |
| `confidence` | Current belief strength |
| `status` | proposed → testing → confirmed / rejected |

A finding is not a finding until it is a `Hypothesis` that has survived interrogation and testing.

## The Four Planes

### Causal Plane
- `CausalEngine`: Analyzes parser cascades for grammar differentials
- `ParserLayer`: Represents one layer in the cascade
- `GrammarDifferential`: Proof that a trust boundary is violated
- **Output**: `Hypothesis` objects with required conditions and falsifiers

### Epistemic Plane
- `EpistemicMonitor`: Interrogates hypotheses before they become beliefs
- Questions every hypothesis: \"What would prove you wrong?\"
- Tracks known biases and calibration history
- **Output**: Surviving hypotheses promoted to `testing` status

### Memory Plane
Two systems, distinct purposes:

**Structured Memory (SQLite) — Source of Truth**
- `hypotheses`: All hypotheses with full provenance
- `findings`: Confirmed hypotheses with proof
- `decisions`: Why we took each action
- `failures`: What went wrong and why

**Semantic Memory (Vector DB) — Retrieval Aid**
- Similar code patterns
- Similar vulnerability classes
- Previous reasoning chains
- **Never** the source of truth. Always derived from structured memory.

### Execution Plane
Capabilities, not products:

| Capability | Purpose | Current Adapters |
|------------|---------|------------------|
| **Observation** | Map target surface | Nuclei |
| **Controlled Testing** | Send crafted inputs, observe responses | Caido |
| **Environment Interaction** | Act like a user or system | Browser, Terminal |
| **Runtime Verification** | Confirm exploitability without damage | Custom instrumentation |

Adapters are replaceable. The capability is stable.

## Solo Developer Rules
- One `make test` runs everything in < 10 seconds
- Pydantic models enforce contracts across modules
- Every module has a `Base*` ABC for extension
- Hypothesis is the center of gravity — everything produces, consumes, or validates it
"@ | Set-Content "docs\architecture\ARCHITECTURE.md" -Encoding utf8

# =============================================================================
# 9. CLEANUP & FINALIZE
# =============================================================================

# Remove old tools directory if empty
if ((Get-ChildItem "chimera\tools" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
    Remove-Item "chimera\tools" -Recurse -Force
}

# Update Makefile to remove Go references
@"
.PHONY: install test format lint clean run

install:
\tpip install -e \".[dev]\"

test:
\tpytest tests/ -v --tb=short

format:
\tblack chimera/ tests/
\truff check --fix chimera/ tests/

lint:
\tmypy chimera/
\truff check chimera/ tests/

run:
\tpython -m chimera analyze

clean:
\trm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache data/
\tfind . -type d -name __pycache__ -exec rm -rf {} +
\tfind . -type f -name '*.pyc' -delete
"@ | Set-Content "Makefile" -Encoding utf8

# Update README
@"
# Chimera

**Causal Security Reasoning Engine**

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

```powershell\n.\\scripts\\setup.ps1\nmake test\npython -m chimera analyze\n```

## Structure

| Path | Purpose |
|------|---------|
| `chimera/core/` | Causal engine, epistemic monitor, memory, orchestrator |
| `chimera/models/` | Pydantic models: Hypothesis, Evidence, Grammar |
| `chimera/parsers/` | Parser cascade builders |
| `chimera/execution/` | Capability-based execution adapters |
| `chimera/plugins/` | Drop-in extensions |
| `tests/` | Unit + integration tests |

## The Core Insight

> The developer thinks there is one language. The machine is actually processing several languages in sequence.

Chimera models each boundary, computes grammar differentials, and proves where trust assumptions break.

## License\nMIT
"@ | Set-Content "README.md" -Encoding utf8

# =============================================================================
# 10. COMMIT & PUSH
# =============================================================================

Write-Host "[*] Committing architecture update..." -ForegroundColor Cyan

git add -A
git commit -m "refactor: center architecture on Hypothesis, dual memory, reasoning loop

- Add Hypothesis as central object with claim, evidence, required_conditions,
  missing_information, falsifiers, confidence, status
- Add Evidence model for structured provenance
- Rewrite CausalEngine to produce Hypothesis objects instead of raw reports
- Rewrite EpistemicMonitor to interrogate Hypothesis objects with bias tracking
- Split Memory Plane: StructuredMemory (SQLite, source of truth) and
  SemanticMemory (vector retrieval, derived)
- Restructure Execution Plane around capabilities, not products:
  Observation, Controlled Testing, Environment Interaction, Runtime Verification
- Add ExecutionAdapter ABC with NucleiObservationAdapter and CaidoTestingAdapter
- Add ExecutionRegistry for capability-based adapter selection
- Document Reasoning Loop: Observe → Model → Hypothesize → Interrogate →
  Test → Update → Decide → Remember
- Update all tests to validate Hypothesis-centric flow
- Remove Go artifacts, pure Python execution"

git push origin main

Write-Host "`n[OK] Architecture updated." -ForegroundColor Green
Write-Host "https://github.com/$owner/chimera" -ForegroundColor Cyan
Write-Host "`nNext:" -ForegroundColor Cyan
Write-Host "  make test" -ForegroundColor White
Write-Host "  python -m chimera analyze" -ForegroundColor White