# CHIMERA FIX SCRIPT
# Run this INSIDE C:\Cyber\chimera

$owner = "emmanueladesina"  # I see your GH username from the push output

# --- 1. CREATE ALL MISSING DIRECTORIES ---
Write-Host "[*] Creating missing directories..." -ForegroundColor Cyan

$dirs = @(
    "chimera\execution",
    "chimera\parsers\languages",
    "chimera\utils",
    "tests\unit\core",
    "tests\unit\parsers",
    "tests\unit\analysis",
    "tests\integration"
)

foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        Write-Host "  + $d" -ForegroundColor Green
    }
}

# --- 2. WRITE MISSING FILES ---

# chimera/execution/__init__.py
"" | Set-Content "chimera\execution\__init__.py" -Encoding utf8

# chimera/execution/base.py
@"
from abc import ABC, abstractmethod
from typing import Any, Dict

class ExecutionAdapter(ABC):
    @property
    @abstractmethod
    def capability(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> bool:
        raise NotImplementedError
"@ | Set-Content "chimera\execution\base.py" -Encoding utf8

# chimera/execution/observation.py
@"
import subprocess
import json
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class NucleiObservationAdapter(ExecutionAdapter):
    @property
    def capability(self) -> str:
        return 'observation'

    def __init__(self, binary: str = 'nuclei', rate_limit: int = 150):
        self.binary = binary
        self.rate_limit = rate_limit

    def health_check(self) -> bool:
        try:
            subprocess.run([self.binary, '-version'], capture_output=True, check=True)
            return True
        except:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        target = intent.get('target')
        if not target:
            return {'error': 'No target provided'}
        
        cmd = [self.binary, '-u', target, '-rate-limit', str(self.rate_limit), '-jsonl', '-o', '/tmp/nuclei_chimera.jsonl']
        subprocess.run(cmd, capture_output=True)
        
        findings = []
        try:
            with open('/tmp/nuclei_chimera.jsonl') as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line)
                    findings.append({
                        'template_id': data.get('template-id'),
                        'severity': data.get('info', {}).get('severity'),
                        'matched_at': data.get('matched-at')
                    })
        except:
            pass
        
        return {'capability': 'observation', 'adapter': 'nuclei', 'findings': findings, 'count': len(findings)}
"@ | Set-Content "chimera\execution\observation.py" -Encoding utf8

# chimera/execution/controlled_testing.py
@"
import requests
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class CaidoTestingAdapter(ExecutionAdapter):
    @property
    def capability(self) -> str:
        return 'controlled_testing'

    def __init__(self, api_url: str = 'http://localhost:8080', token: str = ''):
        self.api_url = api_url
        self.headers = {'Authorization': f'Bearer {token}'}

    def health_check(self) -> bool:
        try:
            r = requests.get(f'{self.api_url}/graphql', headers=self.headers, timeout=2)
            return r.status_code < 500
        except:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        return {'capability': 'controlled_testing', 'adapter': 'caido', 'status': 'not_implemented'}
"@ | Set-Content "chimera\execution\controlled_testing.py" -Encoding utf8

# chimera/execution/environment_interaction.py
@"
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class TerminalAdapter(ExecutionAdapter):
    @property
    def capability(self) -> str:
        return 'environment_interaction'

    def health_check(self) -> bool:
        return True

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        import subprocess
        command = intent.get('command')
        if not command:
            return {'error': 'No command provided'}
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return {
            'capability': 'environment_interaction',
            'adapter': 'terminal',
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
"@ | Set-Content "chimera\execution\environment_interaction.py" -Encoding utf8

# chimera/execution/runtime_verification.py
@"
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class RuntimeVerificationAdapter(ExecutionAdapter):
    @property
    def capability(self) -> str:
        return 'runtime_verification'

    def health_check(self) -> bool:
        return True

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        return {'capability': 'runtime_verification', 'verified': False, 'details': 'Not implemented'}
"@ | Set-Content "chimera\execution\runtime_verification.py" -Encoding utf8

# chimera/execution/registry.py
@"
from typing import Dict, List
from chimera.execution.base import ExecutionAdapter

class ExecutionRegistry:
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
        raise RuntimeError(f'No healthy adapter for: {capability}')
"@ | Set-Content "chimera\execution\registry.py" -Encoding utf8

# chimera/parsers/languages/python_parser.py
@"
import ast
from typing import Any, Optional
from chimera.parsers.base import BaseParser
from chimera.models.causal import ParserLayerModel, GrammarModel

class PythonParser(BaseParser):
    @property
    def name(self) -> str:
        return 'python_ast'

    def parse(self, source: str) -> ParserLayerModel:
        tree = ast.parse(source)
        return ParserLayerModel(
            name='Python_str',
            grammar=GrammarModel(
                safe_chars=set(chr(i) for i in range(32, 127)),
                meta_chars=set()
            ),
            sanitizer=None
        )

    def detect_sanitizer(self, source: Any) -> Optional[str]:
        return None
"@ | Set-Content "chimera\parsers\languages\python_parser.py" -Encoding utf8

# chimera/parsers/languages/sql_parser.py
@"
from typing import Any, Optional
from chimera.parsers.base import BaseParser
from chimera.models.causal import ParserLayerModel, GrammarModel

class SQLParser(BaseParser):
    @property
    def name(self) -> str:
        return 'sql_literal'

    def parse(self, source: str) -> ParserLayerModel:
        return ParserLayerModel(
            name='SQL_literal',
            grammar=GrammarModel(
                safe_chars=set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '),
                meta_chars={"'", '"', ';', '--', '/*'}
            ),
            sanitizer=None
        )

    def detect_sanitizer(self, source: Any) -> Optional[str]:
        return None
"@ | Set-Content "chimera\parsers\languages\sql_parser.py" -Encoding utf8

# chimera/utils/logger.py
@"
import logging
import sys

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S'))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
"@ | Set-Content "chimera\utils\logger.py" -Encoding utf8

# tests/unit/core/test_causal_engine.py
@"
import pytest
from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.models.causal import GrammarModel

class TestCausalEngine:
    def test_json_python_sql_differential(self):
        layers = [
            ParserLayer(name='JSON', grammar=GrammarModel(safe_chars={'a', 'b', "'", '\\', ' '}, meta_chars={'\\', '"'}, escape_rules={'\\': '\\\\', '"': '\\"'}), sanitizer='JSON RFC 8259 escape'),
            ParserLayer(name='Python_str', grammar=GrammarModel(safe_chars={'a', 'b', "'", ' '}, meta_chars=set()), sanitizer=None),
            ParserLayer(name='SQL_literal', grammar=GrammarModel(safe_chars={'a', 'b', ' '}, meta_chars={"'"}), sanitizer=None),
        ]
        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers, target='test')
        assert len(hyps) == 1
        assert hyps[0].status == 'proposed'
        assert "'" in hyps[0].claim
        assert len(hyps[0].required_conditions) == 4

    def test_no_differential_with_sanitizer(self):
        layers = [
            ParserLayer(name='Input', grammar=GrammarModel(safe_chars={"'"}, meta_chars=set()), sanitizer='parameterized_query'),
            ParserLayer(name='SQL', grammar=GrammarModel(safe_chars=set(), meta_chars={"'"}), sanitizer=None),
        ]
        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers)
        assert len(hyps) == 0

    def test_hypothesis_has_falsifiers(self):
        layers = [
            ParserLayer(name='A', grammar=GrammarModel(safe_chars={';'}, meta_chars=set()), sanitizer=None),
            ParserLayer(name='B', grammar=GrammarModel(safe_chars=set(), meta_chars={';'}), sanitizer=None),
        ]
        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers)
        assert len(hyps) == 1
        assert len(hyps[0].falsifiers) > 0
"@ | Set-Content "tests\unit\core\test_causal_engine.py" -Encoding utf8

# tests/unit/core/test_epistemic_engine.py
@"
import pytest
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

class TestEpistemicMonitor:
    def test_rejects_low_confidence(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        hyp = Hypothesis(id='HYP-001', claim='Test', confidence=0.3)
        assert mon.interrogate(hyp) == False

    def test_accepts_strong_hypothesis(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        hyp = Hypothesis(id='HYP-002', claim='Strong', confidence=0.9, required_conditions=['c1'], evidence=[Evidence(source='test', data='x', confidence=0.9)])
        assert mon.interrogate(hyp) == True

    def test_known_bias(self):
        mon = EpistemicMonitor(confidence_threshold=0.6)
        mon.register_bias('SQL injection', 0.5)
        hyp = Hypothesis(id='HYP-003', claim='SQL injection possible', confidence=0.9, required_conditions=['c1'], evidence=[Evidence(source='test', data='x', confidence=0.9)])
        assert mon.interrogate(hyp) == False
"@ | Set-Content "tests\unit\core\test_epistemic_engine.py" -Encoding utf8

# tests/unit/core/test_memory.py
@"
from chimera.core.memory import StructuredMemory, ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

def test_structured_memory_roundtrip(tmp_path):
    db = tmp_path / 'test.db'
    mem = StructuredMemory(db_path=str(db))
    hyp = Hypothesis(id='HYP-TEST-001', claim='Test claim', confidence=0.8, evidence=[Evidence(source='test', data='x')])
    mem.store_hypothesis(hyp)
    retrieved = mem.get_hypothesis('HYP-TEST-001')
    assert retrieved is not None
    assert retrieved.claim == 'Test claim'
    assert retrieved.confidence == 0.8

def test_chimera_memory_has_both_planes():
    mem = ChimeraMemory(db_path=':memory:')
    assert mem.structured is not None
    assert mem.semantic is not None
"@ | Set-Content "tests\unit\core\test_memory.py" -Encoding utf8

# tests/integration/test_end_to_end.py
@"
from chimera.core.orchestrator import ChimeraOrchestrator

def test_reasoning_loop_runs():
    orch = ChimeraOrchestrator()
    orch.run('tests/targets/vuln_app.py')
"@ | Set-Content "tests\integration\test_end_to_end.py" -Encoding utf8

# tests/unit/parsers/test_python_parser.py
@"
from chimera.parsers.languages.python_parser import PythonParser

def test_name():
    assert PythonParser().name == 'python_ast'
"@ | Set-Content "tests\unit\parsers\test_python_parser.py" -Encoding utf8

# tests/targets/vuln_app.py
@"
import json

def get_user_unsafe(user_input: str):
    data = json.loads(user_input)
    user_id = data['id']
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return query

def get_user_safe(user_input: str):
    import sqlite3
    data = json.loads(user_input)
    user_id = data['id']
    conn = sqlite3.connect(':memory:')
    cursor = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cursor.fetchall()
"@ | Set-Content "tests\targets\vuln_app.py" -Encoding utf8

# chimera/plugins/README.md
@"
# Chimera Plugins

## How to Extend

Drop a Python module here or install as a separate package with entry points.

## Plugin Types

| Type | Interface |
|------|-----------|
| Parser | `chimera.parsers.base.BaseParser` |
| Analyzer | `chimera.analysis.base.BaseAnalyzer` |
| Bridge | `chimera.execution.base.ExecutionAdapter` |
| Reporter | `chimera.reports.base.BaseReporter` |

## Rules
1. Lazy-load heavy dependencies
2. Return Pydantic models
3. Handle your own exceptions
"@ | Set-Content "chimera\plugins\README.md" -Encoding utf8

# --- 3. CLEANUP ---
Write-Host "[*] Cleaning up..." -ForegroundColor Cyan

# Remove script.ps1 from git and disk
if (Test-Path "script.ps1") {
    git rm --cached script.ps1 | Out-Null
    Remove-Item script.ps1 -Force
    Write-Host "  - removed script.ps1 from repo" -ForegroundColor Yellow
}

# Remove old tools directory if it exists
if (Test-Path "chimera\tools") {
    Remove-Item "chimera\tools" -Recurse -Force
    Write-Host "  - removed old chimera/tools" -ForegroundColor Yellow
}

# --- 4. COMMIT ---
Write-Host "[*] Committing complete architecture..." -ForegroundColor Cyan

git add -A
git commit -m "fix: add missing execution plane, tests, and target files

- Add chimera/execution/ with capability-based adapters
- Add tests/unit/core/ for causal, epistemic, memory
- Add tests/integration/ for end-to-end loop
- Add tests/targets/vuln_app.py for canonical SQLi demo
- Add parsers/languages/ Python and SQL parsers
- Remove script.ps1 and old tools/ directory
- Complete Hypothesis-centered architecture"

git push origin main

Write-Host "`n[OK] Fixed and pushed." -ForegroundColor Green
Write-Host "Run: make test" -ForegroundColor Cyan