"""Unit tests for the SwarmCoordinator."""

from __future__ import annotations

import asyncio

import pytest

from chimera.execution.swarm_coordinator import (
    SwarmCoordinator,
    SwarmTask,
    TaskStatus,
)


@pytest.fixture
def coordinator():
    coord = SwarmCoordinator(max_concurrency=32)

    async def echo(payload):
        await asyncio.sleep(0.001)
        return {"echo": payload.get("n")}

    async def boom(payload):
        raise RuntimeError("simulated failure")

    async def slow_then_fast(payload):
        # Invert completion order: n=0 sleeps longest
        await asyncio.sleep(0.02 if payload.get("n") == 0 else 0.001)
        return {"n": payload.get("n")}

    coord.register_agent_capability("test.echo", echo)
    coord.register_agent_capability("test.boom", boom)
    coord.register_agent_capability("test.slow", slow_then_fast)
    yield coord


@pytest.mark.asyncio
async def test_results_match_submission_order(coordinator):
    """results[i] must correspond to tasks[i] — never completion order."""
    tasks = [
        SwarmTask(capability="test.slow", payload={"n": 0}),
        SwarmTask(capability="test.slow", payload={"n": 1}),
        SwarmTask(capability="test.slow", payload={"n": 2}),
    ]
    results = await coordinator.dispatch_swarm(tasks)
    await coordinator.stop()
    assert [r.task_id for r in results] == [t.id for t in tasks]
    ns = []
    for r in results:
        data = r.evidence[0].data["raw_result"]
        ns.append(data["n"])
    assert ns == [0, 1, 2]


@pytest.mark.asyncio
async def test_failure_isolated(coordinator):
    tasks = [
        SwarmTask(capability="test.echo", payload={"n": 1}),
        SwarmTask(capability="test.boom", payload={}),
        SwarmTask(capability="test.echo", payload={"n": 3}),
    ]
    results = await coordinator.dispatch_swarm(tasks)
    await coordinator.stop()
    assert results[0].status == TaskStatus.SUCCESS
    assert results[1].status == TaskStatus.FAILED
    assert "simulated failure" in results[1].error
    assert results[2].status == TaskStatus.SUCCESS


@pytest.mark.asyncio
async def test_unknown_capability_skipped(coordinator):
    tasks = [SwarmTask(capability="nonexistent.cap", payload={})]
    results = await coordinator.dispatch_swarm(tasks)
    await coordinator.stop()
    assert results[0].status == TaskStatus.SKIPPED
    assert "not registered" in results[0].error


@pytest.mark.asyncio
async def test_concurrency_throughput(coordinator):
    """200 x 5ms tasks must complete well below the serial 1s."""
    tasks = [
        SwarmTask(capability="test.echo", payload={"n": i}) for i in range(200)
    ]
    loop = asyncio.get_event_loop()
    start = loop.time()
    results = await coordinator.dispatch_swarm(tasks)
    elapsed = loop.time() - start
    await coordinator.stop()
    assert all(r.status == TaskStatus.SUCCESS for r in results)
    assert elapsed < 0.8  # serial would be ~1.0s
