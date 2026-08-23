"""Swarm tool-execution test battery."""
import asyncio
import logging
import sys

logging.basicConfig(level=logging.WARNING)

from chimera.execution.swarm_bootstrap import build_default_swarm
from chimera.execution.swarm_coordinator import SwarmTask

async def main():
    swarm = await build_default_swarm(
        workspace_root="/home/user/chimera",
        allowed_hosts=["localhost", "127.0.0.1"],
        max_concurrency=32,
    )

    cases = [
        ("1-happy: python --version",
         SwarmTask(capability="terminal.execute",
                   payload={"argv": ["python", "--version"], "cwd": "."})),
        ("2-policy: disallowed executable (nmap)",
         SwarmTask(capability="terminal.execute",
                   payload={"argv": ["nmap", "-sS", "10.0.0.1"], "cwd": "."})),
        ("3-escape: cwd outside workspace (/tmp)",
         SwarmTask(capability="terminal.execute",
                   payload={"argv": ["python", "--version"], "cwd": "/tmp"})),
        ("4-traversal: cwd ../../",
         SwarmTask(capability="terminal.execute",
                   payload={"argv": ["python", "--version"], "cwd": "../../"})),
        ("5-arg-injection: python -c writes outside workspace",
         SwarmTask(capability="terminal.execute",
                   payload={"argv": ["python", "-c", "open('/tmp/pwned.txt','w').write('x')"], "cwd": "."})),
        ("6-unknown capability",
         SwarmTask(capability="kernel.pwn", payload={})),
        ("7-browser: playwright missing",
         SwarmTask(capability="browser.navigate",
                   payload={"url": "http://localhost:9999"},
                   scope={"allowed_hosts": ["localhost"]})),
        ("8-caido: no caido server",
         SwarmTask(capability="caido.execute",
                   payload={"query": "query { me { id } }"})),
    ]

    results = await swarm.dispatch_swarm([t for _, t in cases])
    by_id = {r.task_id: r for r in results}
    results = [by_id[t.id] for t in (t for _, t in cases)]
    print("\n=== SINGLE-TASK RESULTS (mapped by task_id) ===")
    for case, task in cases:
        r = by_id[task.id]
        print(f"\n{case}")
        print(f"  status={r.status}  error={str(r.error)[:140]}")
        for ev in r.evidence[:1]:
            print(f"  evidence: type={ev.evidence_type} desc={ev.description[:120]}")
            coc = getattr(ev, "chain_of_custody", None)
            if coc:
                print(f"  custody: sha256={str(getattr(coc, 'content_hash', ''))[:16]}… entries={len(getattr(coc, 'entries', [])) or 'n/a'}")

    # Concurrency burst: 32 simultaneous sleep tasks
    burst = [SwarmTask(capability="terminal.execute",
                       payload={"argv": ["python", "-c", "import time; time.sleep(0.5)"], "cwd": "."})
             for _ in range(32)]
    import time
    t0 = time.monotonic()
    bresults = await swarm.dispatch_swarm(burst)
    wall = time.monotonic() - t0
    ok = sum(1 for r in bresults if r.status.value == "success" or r.status == "success")
    print(f"\n=== BURST: 32 x 0.5s tasks ===")
    print(f"  wall={wall:.2f}s (serial would be ~16s)  ok={ok}/32")

    await swarm.stop()

asyncio.run(main())
