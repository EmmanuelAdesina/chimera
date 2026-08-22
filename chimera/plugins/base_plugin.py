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
