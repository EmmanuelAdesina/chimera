"""
Chimera v4 ASI Module: Abstract Base Class for Epistemic Tool Plugins.
Standardizes the lifecycle of all external tool integrations (Caido, Burp, Nmap, etc.).
"""
from abc import ABC, abstractmethod
from typing import Dict, Any

class ToolPlugin(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.name = self.__class__.__name__

    @abstractmethod
    async def initialize(self):
        """Setup connections, start headless services, or verify API keys."""
        pass

    @abstractmethod
    async def execute(self, payload: Dict[str, Any]) -> Any:
        """Execute the tool-specific logic and return structured Evidence."""
        pass

    @abstractmethod
    async def cleanup(self):
        """Tear down connections and release resources."""
        pass
