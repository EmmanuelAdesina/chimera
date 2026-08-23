"""Minimal Chimera swarm usage example.

Run from the repository root:

    python scripts/swarm_demo.py

Dispatches a terminal task and a browser navigation task through the
SwarmCoordinator and prints each result's status, error, and evidence.
"""
import asyncio

from chimera.execution.swarm_bootstrap import build_default_swarm
from chimera.execution.swarm_coordinator import SwarmTask

async def main():
    swarm = await build_default_swarm(
        workspace_root=".",
        allowed_hosts=["localhost", "127.0.0.1"],
        max_concurrency=32,
    )

    tasks = [
        SwarmTask(
            capability="terminal.execute",
            payload={"argv": ["python", "--version"], "cwd": "."},
        ),
        SwarmTask(
            capability="browser.navigate",
            payload={"url": "http://localhost:8000"},
            scope={"allowed_hosts": ["localhost"]},
        ),
    ]

    results = await swarm.dispatch_swarm(tasks)

    for result in results:
        print(result.status, result.error)
        for ev in result.evidence:
            print(ev.description)

    await swarm.stop()

asyncio.run(main())
