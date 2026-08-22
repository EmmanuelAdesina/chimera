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
