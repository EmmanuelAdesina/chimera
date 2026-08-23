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
        Dispatch a finite batch and return results in SUBMISSION order.

        Workers complete tasks out of order; results are re-keyed by task id
        so ``results[i]`` always corresponds to ``tasks[i]``. Callers mapping
        results back to inputs must never see silent misattribution.
        """
        await self.start()
        await self.submit_many(tasks)

        by_id: Dict[str, SwarmResult] = {}
        for _ in range(len(tasks)):
            result = await self._results.get()
            by_id[result.task_id] = result

        results: List[SwarmResult] = []
        for task in tasks:
            result = by_id.get(task.id)
            if result is None:
                result = SwarmResult(
                    task_id=task.id,
                    capability=task.capability,
                    status=TaskStatus.FAILED,
                    error="result lost in dispatch",
                    finished_at=datetime.utcnow().isoformat(),
                )
            results.append(result)
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
