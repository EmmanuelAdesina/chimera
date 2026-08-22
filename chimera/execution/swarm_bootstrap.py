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
