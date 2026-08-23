# apply_chimera_swarm.ps1
# Chimera Swarm Architecture Update for Windows PowerShell
# Run from repository root.
#
# Compatibility notes (kept in sync with the committed repository state):
# - TerminalLayer allowlist also includes python3/python3.exe for Linux/macOS hosts.
# - GraphQLCausalParser.field_pattern uses the fixed directive-capture regex
#   (non-greedy return type + optional trailing comment) so @auth/@rateLimit
#   directives are actually captured.
# - AsyncJavaScriptAnalyzer keeps a backward-compatible analyze_race_conditions()
#   shim required by chimera/core/asi_runtime_patch.py.

$ErrorActionPreference = "Stop"

function Write-File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $Dir = Split-Path $Path -Parent
    if ($Dir -and !(Test-Path $Dir)) {
        New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    }

    if (Test-Path $Path) {
        Copy-Item $Path "$Path.bak" -Force
        Write-Host "Backed up existing $Path to $Path.bak"
    }

    Set-Content -Path $Path -Value $Content -Encoding UTF8
    Write-Host "Wrote $Path"
}

Write-Host "Applying Chimera autonomous swarm architecture update..."

Write-File "chimera/execution/__init__.py" @'
"""Execution-plane primitives for Chimera."""
'@

Write-File "chimera/layers/__init__.py" @'
"""Tool execution layers for Chimera."""
'@

Write-File "chimera/memory/__init__.py" @'
"""Memory extensions for Chimera."""
'@

Write-File "chimera/execution/swarm_coordinator.py" @'
"""
Chimera Swarm Coordinator.

This module turns the existing v2 reasoning loop into a strategic planner that
can dispatch tactical work to bounded, asynchronous worker capabilities.

Design goals:
- capability-based dispatch, not tool-specific orchestration
- bounded concurrency and backpressure
- structured Evidence output
- strict authorization/scope hooks
- no implicit exploit execution
"""

from __future__ import annotations

import asyncio
import inspect
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class SwarmTask:
    """
    A bounded tactical unit of work.

    capability:
        Symbolic capability name, e.g.:
        - terminal.execute
        - browser.navigate
        - caido.execute
        - parser.graphql
        - parser.javascript

    payload:
        Capability-specific arguments.

    scope:
        Optional authorization metadata. Execution layers should refuse work
        outside explicitly authorized scope.
    """
    capability: str
    payload: Dict[str, Any]
    id: str = field(default_factory=lambda: f"task-{uuid.uuid4().hex[:12]}")
    hypothesis_id: str = ""
    priority: int = 100
    scope: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class SwarmResult:
    task_id: str
    capability: str
    status: TaskStatus
    evidence: List[Evidence] = field(default_factory=list)
    error: str = ""
    started_at: str = ""
    finished_at: str = ""


Capability = Callable[[Dict[str, Any]], Awaitable[Any]]


class SwarmCoordinator:
    """
    Bounded asynchronous dispatcher.

    This deliberately supports thousands of local concurrent tasks but is also
    architected so the queue can later be replaced by Redis Streams, Kafka, NATS,
    Ray, Celery, or another distributed substrate.
    """

    def __init__(
        self,
        max_concurrency: int = 256,
        queue_size: int = 10000,
        default_scope: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.max_concurrency = max_concurrency
        self.default_scope = default_scope or {}
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._queue: asyncio.PriorityQueue[tuple[int, str, SwarmTask]] = asyncio.PriorityQueue(maxsize=queue_size)
        self._results: asyncio.Queue[SwarmResult] = asyncio.Queue()
        self._capabilities: Dict[str, Capability] = {}
        self._workers: List[asyncio.Task[None]] = []
        self._running = False

    def register_agent_capability(self, name: str, executor: Callable[[Dict[str, Any]], Any]) -> None:
        """
        Register a tactical capability.

        The callable may be sync or async. It may return:
        - Evidence
        - list[Evidence]
        - dict/str/None, which will be wrapped into Evidence
        """
        async def wrapper(payload: Dict[str, Any]) -> Any:
            result = executor(payload)
            if inspect.isawaitable(result):
                return await result
            return result

        self._capabilities[name] = wrapper

    async def submit(self, task: SwarmTask) -> None:
        await self._queue.put((task.priority, task.id, task))

    async def submit_many(self, tasks: Iterable[SwarmTask]) -> None:
        for task in tasks:
            await self.submit(task)

    async def start(self, worker_count: Optional[int] = None) -> None:
        if self._running:
            return
        self._running = True
        count = worker_count or self.max_concurrency
        self._workers = [asyncio.create_task(self._worker_loop(i)) for i in range(count)]

    async def stop(self) -> None:
        self._running = False
        for worker in self._workers:
            worker.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def dispatch_swarm(self, tasks: Sequence[SwarmTask]) -> List[SwarmResult]:
        """
        Convenience method for finite batches.
        """
        await self.start()
        await self.submit_many(tasks)

        results: List[SwarmResult] = []
        for _ in range(len(tasks)):
            results.append(await self._results.get())

        return results

    async def harvest_evidence(self, result_count: int) -> List[Evidence]:
        evidences: List[Evidence] = []
        for _ in range(result_count):
            result = await self._results.get()
            evidences.extend(result.evidence)
        return evidences

    async def _worker_loop(self, worker_id: int) -> None:
        while self._running:
            try:
                _, _, task = await self._queue.get()
                result = await self._execute_task(task)
                await self._results.put(result)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._results.put(SwarmResult(
                    task_id="unknown",
                    capability="unknown",
                    status=TaskStatus.FAILED,
                    error=f"worker-{worker_id}: {exc}",
                    finished_at=datetime.utcnow().isoformat(),
                ))

    async def _execute_task(self, task: SwarmTask) -> SwarmResult:
        started = datetime.utcnow().isoformat()
        executor = self._capabilities.get(task.capability)

        if executor is None:
            return SwarmResult(
                task_id=task.id,
                capability=task.capability,
                status=TaskStatus.SKIPPED,
                error=f"Capability not registered: {task.capability}",
                started_at=started,
                finished_at=datetime.utcnow().isoformat(),
            )

        async with self._semaphore:
            try:
                raw = await executor({**task.payload, "_scope": task.scope or self.default_scope})
                evidence = self._normalize_evidence(task, raw)
                return SwarmResult(
                    task_id=task.id,
                    capability=task.capability,
                    status=TaskStatus.SUCCESS,
                    evidence=evidence,
                    started_at=started,
                    finished_at=datetime.utcnow().isoformat(),
                )
            except Exception as exc:
                return SwarmResult(
                    task_id=task.id,
                    capability=task.capability,
                    status=TaskStatus.FAILED,
                    error=str(exc),
                    started_at=started,
                    finished_at=datetime.utcnow().isoformat(),
                )

    def _normalize_evidence(self, task: SwarmTask, raw: Any) -> List[Evidence]:
        if raw is None:
            return []

        if isinstance(raw, Evidence):
            return [raw]

        if isinstance(raw, list):
            out: List[Evidence] = []
            for item in raw:
                if isinstance(item, Evidence):
                    out.append(item)
                else:
                    out.append(self._wrap_evidence(task, item))
            return out

        return [self._wrap_evidence(task, raw)]

    def _wrap_evidence(self, task: SwarmTask, raw: Any) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="SwarmCoordinator",
            action=task.capability,
            input_ref=task.id,
            output_ref=ev_id,
            parameters={"hypothesis_id": task.hypothesis_id},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.EXPERIMENT_RESULT,
            data={"raw_result": raw, "task": task.__dict__},
            chain_of_custody=chain,
            confidence=0.7,
            description=f"Swarm task {task.capability} produced a result",
            metadata={"task_id": task.id, "capability": task.capability},
        )
'@

Write-File "chimera/layers/terminal_layer.py" @'
"""
Sandbox-aware terminal execution layer.

This is intentionally conservative:
- no shell=True
- allowlisted executables
- optional workspace boundary
- timeout enforcement
- structured Evidence output

For stronger isolation in production, run this layer inside a container,
Windows Sandbox, Hyper-V VM, Firecracker/gVisor equivalent, or ephemeral CI job.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


@dataclass
class CommandPolicy:
    allowed_executables: set[str] = field(default_factory=lambda: {
        "python", "python.exe", "py",
        "python3", "python3.exe",
        "node", "node.exe",
        "npm", "npm.cmd",
        "npx", "npx.cmd",
        "git", "git.exe",
        "pytest", "pytest.exe",
        "ruff", "ruff.exe",
        "mypy", "mypy.exe",
        "bandit", "bandit.exe",
    })
    workspace_root: Optional[str] = None
    timeout_seconds: int = 30
    max_output_chars: int = 200_000


class TerminalLayer:
    def __init__(self, policy: Optional[CommandPolicy] = None) -> None:
        self.policy = policy or CommandPolicy()
        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    async def execute(self, payload: Dict[str, Any]) -> Evidence:
        argv = payload.get("argv")
        cwd = payload.get("cwd")
        env = payload.get("env")

        if not isinstance(argv, list) or not argv:
            raise ValueError("terminal.execute requires payload['argv'] as a non-empty list")

        result = await self.run(argv=argv, cwd=cwd, env=env)
        return self._evidence(argv, cwd, result)

    async def run(
        self,
        argv: Sequence[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        executable = Path(str(argv[0])).name
        if executable not in self.policy.allowed_executables:
            raise PermissionError(f"Executable not allowed by policy: {executable}")

        safe_cwd = self._validate_cwd(cwd)

        proc = await asyncio.create_subprocess_exec(
            *[str(x) for x in argv],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=safe_cwd,
            env=self._safe_env(env),
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.policy.timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Execution timed out after {self.policy.timeout_seconds}s",
                "timed_out": True,
            }

        out = self._clean(stdout)
        err = self._clean(stderr)

        return {
            "exit_code": proc.returncode,
            "stdout": out[: self.policy.max_output_chars],
            "stderr": err[: self.policy.max_output_chars],
            "timed_out": False,
        }

    def _validate_cwd(self, cwd: Optional[str]) -> Optional[str]:
        if cwd is None:
            return None

        resolved = Path(cwd).resolve()

        if self.policy.workspace_root:
            root = Path(self.policy.workspace_root).resolve()
            if root not in resolved.parents and resolved != root:
                raise PermissionError(f"cwd is outside workspace_root: {resolved}")

        return str(resolved)

    def _safe_env(self, env: Optional[Dict[str, str]]) -> Dict[str, str]:
        base = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
            "PYTHONIOENCODING": "utf-8",
        }
        if env:
            for key, value in env.items():
                if key.upper() in {"PATH", "SYSTEMROOT", "TEMP", "TMP", "PYTHONIOENCODING"}:
                    base[key] = value
        return base

    def _clean(self, data: bytes) -> str:
        text = data.decode("utf-8", errors="ignore")
        return self.ansi_escape.sub("", text).strip()

    def _evidence(self, argv: Sequence[str], cwd: Optional[str], result: Dict[str, Any]) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="TerminalLayer",
            action="execute",
            input_ref=" ".join(argv),
            output_ref=ev_id,
            parameters={"cwd": cwd, "exit_code": result.get("exit_code")},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.EXPERIMENT_RESULT,
            data={"argv": list(argv), "cwd": cwd, "result": result},
            chain_of_custody=chain,
            confidence=1.0 if result.get("exit_code") == 0 else 0.75,
            description=f"Terminal execution: {' '.join(argv)}",
            metadata={"layer": "terminal"},
        )
'@

Write-File "chimera/layers/browser_layer.py" @'
"""
Headless browser execution layer.

This layer is intended for authorized dynamic application observation:
- navigation
- DOM/title/status capture
- optional scoped host enforcement

It deliberately avoids anti-detection bypass behavior.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


class BrowserLayer:
    def __init__(
        self,
        allowed_hosts: Optional[List[str]] = None,
        headless: bool = True,
        timeout_ms: int = 30000,
    ) -> None:
        self.allowed_hosts = set(allowed_hosts or [])
        self.headless = headless
        self.timeout_ms = timeout_ms
        self._playwright = None
        self._browser = None

    async def initialize(self) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed. Run: pip install playwright && playwright install chromium") from exc

        if self._playwright is None:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(headless=self.headless)

    async def cleanup(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def execute_navigation(self, payload: Dict[str, Any]) -> Evidence:
        url = payload.get("url")
        if not url:
            raise ValueError("browser.navigate requires payload['url']")

        self._enforce_scope(url, payload.get("_scope", {}))
        await self.initialize()

        context = await self._browser.new_context()
        page = await context.new_page()

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)
            title = await page.title()
            html = await page.content()
            status = response.status if response else 0

            return self._evidence(url, title, status, len(html))
        finally:
            await context.close()

    def _enforce_scope(self, url: str, runtime_scope: Dict[str, Any]) -> None:
        host = urlparse(url).hostname or ""
        allowed = set(self.allowed_hosts)
        allowed.update(runtime_scope.get("allowed_hosts", []) or [])

        if allowed and host not in allowed:
            raise PermissionError(f"Host is outside authorized browser scope: {host}")

    def _evidence(self, url: str, title: str, status: int, html_length: int) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="BrowserLayer",
            action="navigate",
            input_ref=url,
            output_ref=ev_id,
            parameters={"status": status},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.HTTP_RESPONSE,
            data={
                "request": {"method": "GET", "url": url},
                "response": {
                    "status": status,
                    "title": title,
                    "html_length": html_length,
                },
            },
            chain_of_custody=chain,
            confidence=1.0 if status else 0.5,
            description=f"Browser observed {url} with status {status}",
            metadata={"layer": "browser"},
        )
'@

Write-File "chimera/plugins/base_plugin.py" @'
"""
Base plugin contract for Chimera epistemic tool integrations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class ToolPlugin(ABC):
    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.name = self.__class__.__name__

    @abstractmethod
    async def initialize(self) -> None:
        pass

    @abstractmethod
    async def execute(self, payload: Dict[str, Any]) -> Any:
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        pass
'@

Write-File "chimera/plugins/caido_bridge.py" @'
"""
Caido Bridge.

Persistent GraphQL bridge for using Caido as an epistemic HTTP sensor.

This bridge intentionally does not assume undocumented schema names. You can:
- run arbitrary configured GraphQL queries/mutations against your local Caido
- optionally enable active scan actions if your Caido schema supports them
- enforce target host scope before sending traffic-oriented requests
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody
from chimera.plugins.base_plugin import ToolPlugin


class CaidoBridge(ToolPlugin):
    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self.api_url = self.config.get("caido_url", "http://127.0.0.1:8080/graphql")
        self.token = self.config.get("token")
        self.allowed_hosts = set(self.config.get("allowed_hosts", []) or [])
        self.enable_active_scan = bool(self.config.get("enable_active_scan", False))
        self.session = None

    async def initialize(self) -> None:
        try:
            import aiohttp
        except ImportError as exc:
            raise RuntimeError("aiohttp is not installed. Run: pip install aiohttp") from exc

        if self.session is None:
            headers = {}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self.session = aiohttp.ClientSession(headers=headers)

        # Soft health-check. Some Caido builds may not expose introspection.
        try:
            await self.graphql("query { __typename }")
        except Exception:
            pass

    async def cleanup(self) -> None:
        if self.session is not None:
            await self.session.close()
            self.session = None

    async def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        await self.initialize()
        payload: Dict[str, Any] = {"query": query}
        if variables is not None:
            payload["variables"] = variables

        async with self.session.post(self.api_url, json=payload) as response:
            text = await response.text()
            if response.status >= 400:
                raise RuntimeError(f"Caido GraphQL HTTP {response.status}: {text[:500]}")
            try:
                data = await response.json()
            except Exception as exc:
                raise RuntimeError(f"Caido GraphQL returned non-JSON response: {text[:500]}") from exc

        if "errors" in data:
            raise RuntimeError(f"Caido GraphQL errors: {data['errors']}")
        return data

    async def execute(self, payload: Dict[str, Any]) -> Evidence:
        action = payload.get("action", "graphql")

        if action == "graphql":
            query = payload.get("query")
            variables = payload.get("variables")
            if not query:
                raise ValueError("caido.execute action=graphql requires payload['query']")
            result = await self.graphql(query, variables)
            return self._evidence("graphql", {"result": result})

        if action == "replay_http":
            return await self._replay_http(payload)

        if action == "active_scan":
            if not self.enable_active_scan:
                raise PermissionError("Caido active_scan disabled. Set enable_active_scan=true in config.")
            return await self._active_scan(payload)

        raise ValueError(f"Unsupported Caido action: {action}")

    async def _replay_http(self, payload: Dict[str, Any]) -> Evidence:
        target_url = payload.get("target_url")
        raw_http_request = payload.get("raw_http_request")

        if not target_url or not raw_http_request:
            raise ValueError("replay_http requires target_url and raw_http_request")

        self._enforce_scope(target_url, payload.get("_scope", {}))

        mutation = self.config.get("replay_mutation")
        if not mutation:
            raise RuntimeError(
                "No Caido replay_mutation configured. Provide schema-specific GraphQL mutation in config."
            )

        variables = {
            "input": {
                "url": target_url,
                "raw": raw_http_request,
            }
        }

        result = await self.graphql(mutation, variables)
        return self._evidence("replay_http", {"target_url": target_url, "result": result})

    async def _active_scan(self, payload: Dict[str, Any]) -> Evidence:
        target_url = payload.get("target_url")
        request_id = payload.get("request_id")

        if target_url:
            self._enforce_scope(target_url, payload.get("_scope", {}))

        mutation = self.config.get("active_scan_mutation")
        if not mutation:
            raise RuntimeError(
                "No Caido active_scan_mutation configured. Provide schema-specific GraphQL mutation in config."
            )

        result = await self.graphql(mutation, {"requestId": request_id})
        return self._evidence("active_scan", {"target_url": target_url, "request_id": request_id, "result": result})

    def _enforce_scope(self, url: str, runtime_scope: Dict[str, Any]) -> None:
        host = urlparse(url).hostname or ""
        allowed = set(self.allowed_hosts)
        allowed.update(runtime_scope.get("allowed_hosts", []) or [])

        if allowed and host not in allowed:
            raise PermissionError(f"Host is outside authorized Caido scope: {host}")

    def _evidence(self, action: str, data: Dict[str, Any]) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="CaidoBridge",
            action=action,
            input_ref=self.api_url,
            output_ref=ev_id,
            parameters={"action": action},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.EXPERIMENT_RESULT,
            data=data,
            chain_of_custody=chain,
            confidence=0.9,
            description=f"Caido bridge executed action: {action}",
            metadata={"plugin": "caido", "action": action},
        )
'@

Write-File "chimera/plugins/caido_testing_adapter.py" @'
"""
Compatibility adapter that exposes CaidoBridge as a testing adapter.

If the existing codebase expects a CaidoTestingAdapter, this class can be
registered in the execution registry while delegating persistent GraphQL work
to CaidoBridge.
"""

from __future__ import annotations

from typing import Any, Dict

from chimera.plugins.caido_bridge import CaidoBridge


class CaidoTestingAdapter:
    capability = "controlled_testing.http.caido"

    def __init__(self, config: Dict[str, Any] | None = None) -> None:
        self.bridge = CaidoBridge(config)

    async def initialize(self) -> None:
        await self.bridge.initialize()

    async def execute(self, payload: Dict[str, Any]) -> Any:
        return await self.bridge.execute(payload)

    async def cleanup(self) -> None:
        await self.bridge.cleanup()
'@

Write-File "chimera/parsers/graphql_parser.py" @'
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
'@

Write-File "chimera/parsers/javascript_parser.py" @'
"""
JavaScript/TypeScript async-state parser.

Uses conservative static analysis to identify async boundaries that deserve
controlled testing:
- state mutation before await
- Promise.all with shared-looking identifiers
- async function bodies with mixed mutation and awaits

Tree-sitter is optional. If unavailable, a regex fallback is used.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


@dataclass
class JSAsyncFinding:
    kind: str
    description: str
    line: int = 0
    confidence: float = 0.6
    metadata: Dict[str, Any] = field(default_factory=dict)


class AsyncJavaScriptAnalyzer:
    assignment_pattern = re.compile(r"(?P<lhs>(?:this\.)?[A-Za-z_$][\w$\.]*)\s*(?:=|\+=|-=|\*=|/=)")
    await_pattern = re.compile(r"\bawait\b")
    async_fn_pattern = re.compile(
        r"async\s+function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}",
        re.DOTALL,
    )
    async_arrow_pattern = re.compile(
        r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*async\s*\([^)]*\)\s*=>\s*\{(?P<body>.*?)\n\}",
        re.DOTALL,
    )

    def analyze_source(self, source: str, file_path: str = "") -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []
        findings.extend(self._analyze_async_functions(source, file_path))
        findings.extend(self._analyze_promise_all(source, file_path))
        findings.extend(self._analyze_unawaited_promises(source, file_path))
        return findings

    def analyze_to_evidence(self, source: str, file_path: str = "") -> List[Evidence]:
        return [self._evidence(finding, file_path) for finding in self.analyze_source(source, file_path)]

    def analyze_race_conditions(self, code_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Backward-compatible entry point used by chimera.core.asi_runtime_patch.

        Accepts raw source bytes, runs the source analysis, and maps
        ASYNC_STATE_MUTATION_BEFORE_AWAIT findings onto the legacy
        ``ASYNC_TOCTOU`` vector dictionaries.
        """
        if isinstance(code_bytes, (bytes, bytearray)):
            source = code_bytes.decode("utf-8", errors="ignore")
        else:
            source = str(code_bytes)

        vectors: List[Dict[str, Any]] = []
        for finding in self.analyze_source(source):
            if finding.kind != "ASYNC_STATE_MUTATION_BEFORE_AWAIT":
                continue
            vectors.append({
                "vector": "ASYNC_TOCTOU",
                "location": (finding.line - 1, 0),
                "description": finding.description,
            })
        return vectors

    def _analyze_async_functions(self, source: str, file_path: str) -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []
        matches = list(self.async_fn_pattern.finditer(source)) + list(self.async_arrow_pattern.finditer(source))

        for match in matches:
            name = match.group("name")
            body = match.group("body")
            start_line = source[: match.start()].count("\n") + 1

            await_match = self.await_pattern.search(body)
            if not await_match:
                continue

            first_await_pos = await_match.start()
            before_await = body[:first_await_pos]
            mutation_match = self.assignment_pattern.search(before_await)

            if mutation_match:
                findings.append(JSAsyncFinding(
                    kind="ASYNC_STATE_MUTATION_BEFORE_AWAIT",
                    description=(
                        f"Async function {name} mutates {mutation_match.group('lhs')} before an await boundary. "
                        "This may represent a TOCTOU-sensitive state transition and should be tested dynamically."
                    ),
                    line=start_line + before_await[: mutation_match.start()].count("\n"),
                    confidence=0.72,
                    metadata={"function": name, "lhs": mutation_match.group("lhs"), "file_path": file_path},
                ))

        return findings

    def _analyze_promise_all(self, source: str, file_path: str) -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []

        for match in re.finditer(r"Promise\.all\s*\((?P<body>.*?)\)", source, re.DOTALL):
            body = match.group("body")
            line = source[: match.start()].count("\n") + 1

            if self.assignment_pattern.search(body):
                findings.append(JSAsyncFinding(
                    kind="PROMISE_ALL_SHARED_STATE",
                    description="Promise.all block contains state mutation candidates; verify shared-state race behavior.",
                    line=line,
                    confidence=0.65,
                    metadata={"file_path": file_path},
                ))

        return findings

    def _analyze_unawaited_promises(self, source: str, file_path: str) -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []
        promise_call = re.compile(r"(?<!await\s)(?P<call>[A-Za-z_$][\w$]*\([^;\n]*\))\s*;")

        for match in promise_call.finditer(source):
            call = match.group("call")
            if any(term in call.lower() for term in ["fetch", "axios", "request", "query", "save", "update"]):
                findings.append(JSAsyncFinding(
                    kind="POTENTIALLY_UNAWAITED_ASYNC_CALL",
                    description=f"Potentially unawaited async call: {call}",
                    line=source[: match.start()].count("\n") + 1,
                    confidence=0.55,
                    metadata={"call": call, "file_path": file_path},
                ))

        return findings

    def _evidence(self, finding: JSAsyncFinding, file_path: str) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="AsyncJavaScriptAnalyzer",
            action=finding.kind,
            input_ref=f"{file_path}:{finding.line}",
            output_ref=ev_id,
            parameters=finding.metadata,
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.STATIC_ANALYSIS,
            evidence_type=EvidenceType.CODE_SNIPPET,
            data={"finding": finding.__dict__},
            chain_of_custody=chain,
            file_path=file_path,
            line_range=(finding.line, finding.line),
            confidence=finding.confidence,
            description=finding.description,
            metadata={"parser": "javascript", "kind": finding.kind},
        )


# Backward-compatible alias.
AsyncPromiseAnalyzer = AsyncJavaScriptAnalyzer
'@

Write-File "chimera/memory/hybrid_epistemic_memory.py" @'
"""
Hybrid epistemic memory.

Combines:
- dense semantic retrieval from Chimera core SemanticMemory
- sparse lexical retrieval inspired by BM25
- temporal decay to reduce stale-memory dominance during long autonomous runs

This class wraps chimera.core.memory.SemanticMemory without requiring changes to
the existing memory.py file.
"""

from __future__ import annotations

import math
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from chimera.core.memory import SemanticMemory


def _tokens(text: str) -> List[str]:
    return re.findall(r"[A-Za-z0-9_.$:/-]+", text.lower())


@dataclass
class HybridMemoryDocument:
    id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_epoch: float = field(default_factory=time.time)


class HybridEpistemicMemory:
    def __init__(
        self,
        semantic_memory: Optional[SemanticMemory] = None,
        decay_lambda: float = 0.015,
        dense_weight: float = 0.65,
        sparse_weight: float = 0.35,
    ) -> None:
        self.semantic = semantic_memory or SemanticMemory()
        self.decay_lambda = decay_lambda
        self.dense_weight = dense_weight
        self.sparse_weight = sparse_weight
        self.documents: Dict[str, HybridMemoryDocument] = {}

    def store(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
    ) -> str:
        metadata = dict(metadata or {})
        doc_id = doc_id or f"hyb-{uuid.uuid4().hex[:12]}"
        created_epoch = float(metadata.get("created_epoch", time.time()))
        metadata.setdefault("created_epoch", created_epoch)
        metadata.setdefault("created_at", datetime.utcfromtimestamp(created_epoch).isoformat())

        self.documents[doc_id] = HybridMemoryDocument(
            id=doc_id,
            text=text,
            metadata=metadata,
            created_epoch=created_epoch,
        )

        self.semantic.store(text, metadata=metadata, doc_id=doc_id)
        return doc_id

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_dict: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        dense = self.semantic.search(query, n_results=max(n_results * 4, 10), filter_dict=filter_dict)
        dense_by_id = {item["id"]: item for item in dense}

        sparse = self._sparse_search(query, filter_dict)
        sparse_by_id = {item["id"]: item for item in sparse}

        all_ids = set(dense_by_id) | set(sparse_by_id)
        fused: List[Dict[str, Any]] = []

        for doc_id in all_ids:
            dense_score = float(dense_by_id.get(doc_id, {}).get("score", 0.0))
            sparse_score = float(sparse_by_id.get(doc_id, {}).get("score", 0.0))
            doc = self.documents.get(doc_id)

            metadata = {}
            text = ""
            created_epoch = time.time()

            if doc is not None:
                metadata = doc.metadata
                text = doc.text
                created_epoch = doc.created_epoch
            elif doc_id in dense_by_id:
                metadata = dense_by_id[doc_id].get("metadata", {})
                text = dense_by_id[doc_id].get("text", "")
                created_epoch = float(metadata.get("created_epoch", time.time()))

            fused_score = (self.dense_weight * dense_score) + (self.sparse_weight * sparse_score)
            fused_score = self._apply_decay(fused_score, created_epoch)

            fused.append({
                "id": doc_id,
                "text": text,
                "metadata": metadata,
                "score": fused_score,
                "dense_score": dense_score,
                "sparse_score": sparse_score,
            })

        fused.sort(key=lambda item: item["score"], reverse=True)
        return fused[:n_results]

    def _sparse_search(
        self,
        query: str,
        filter_dict: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        query_tokens = _tokens(query)
        if not query_tokens:
            return []

        query_set = set(query_tokens)
        results: List[Dict[str, Any]] = []

        for doc in self.documents.values():
            if filter_dict and not all(doc.metadata.get(k) == v for k, v in filter_dict.items()):
                continue

            doc_tokens = _tokens(doc.text)
            if not doc_tokens:
                continue

            doc_set = set(doc_tokens)
            overlap = len(query_set & doc_set)
            if overlap == 0:
                continue

            # Lightweight BM25-like scoring without mandatory external deps.
            score = overlap / math.sqrt(len(doc_set) * len(query_set))
            results.append({
                "id": doc.id,
                "text": doc.text,
                "metadata": doc.metadata,
                "score": score,
            })

        results.sort(key=lambda item: item["score"], reverse=True)
        return results

    def _apply_decay(self, score: float, created_epoch: float) -> float:
        age_hours = max(0.0, (time.time() - created_epoch) / 3600.0)
        return score * math.exp(-self.decay_lambda * age_hours)

    def store_hypothesis(self, hypothesis: Any) -> str:
        text = getattr(hypothesis, "claim", str(hypothesis))
        vuln_class = getattr(getattr(hypothesis, "vulnerability_class", None), "value", "unknown")
        status = getattr(getattr(hypothesis, "status", None), "value", "unknown")
        confidence = getattr(hypothesis, "confidence", 0.0)
        file_path = getattr(hypothesis, "file_path", "")

        return self.store(
            text,
            metadata={
                "vulnerability_class": vuln_class,
                "status": status,
                "confidence": confidence,
                "file_path": file_path,
            },
            doc_id=f"hyp-{getattr(hypothesis, 'id', uuid.uuid4().hex[:12])}",
        )
'@

Write-File "chimera/execution/swarm_bootstrap.py" @'
"""
Swarm bootstrap helpers.

Use this from an application entrypoint or from the existing orchestrator:

    from chimera.execution.swarm_bootstrap import build_default_swarm

    swarm = await build_default_swarm(
        workspace_root=".",
        allowed_hosts=["localhost", "127.0.0.1", "example.test"],
        caido_config={"caido_url": "http://127.0.0.1:8080/graphql"}
    )

The existing v2 orchestrator should remain the strategic planner. It can turn
hypotheses into SwarmTask objects and let the swarm handle tactical execution.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from chimera.execution.swarm_coordinator import SwarmCoordinator
from chimera.layers.terminal_layer import CommandPolicy, TerminalLayer
from chimera.layers.browser_layer import BrowserLayer
from chimera.plugins.caido_bridge import CaidoBridge


async def build_default_swarm(
    workspace_root: Optional[str] = None,
    allowed_hosts: Optional[List[str]] = None,
    caido_config: Optional[Dict[str, Any]] = None,
    max_concurrency: int = 128,
) -> SwarmCoordinator:
    swarm = SwarmCoordinator(
        max_concurrency=max_concurrency,
        default_scope={"allowed_hosts": allowed_hosts or []},
    )

    terminal = TerminalLayer(CommandPolicy(workspace_root=workspace_root))
    browser = BrowserLayer(allowed_hosts=allowed_hosts or [])
    caido = CaidoBridge(caido_config or {"allowed_hosts": allowed_hosts or []})

    swarm.register_agent_capability("terminal.execute", terminal.execute)
    swarm.register_agent_capability("browser.navigate", browser.execute_navigation)
    swarm.register_agent_capability("caido.execute", caido.execute)

    return swarm
'@

Write-Host ""
Write-Host "Chimera swarm architecture files written successfully."
Write-Host ""
Write-Host "Recommended dependencies:"
Write-Host "  pip install aiohttp playwright"
Write-Host "  playwright install chromium"
Write-Host ""
Write-Host "Optional validation:"
Write-Host "  python -m compileall chimera"
Write-Host ""
Write-Host "Backups were created as *.bak for overwritten files."
