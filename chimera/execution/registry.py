from typing import Dict, List
from chimera.execution.base import ExecutionAdapter

class ExecutionRegistry:
    """
    Central registry for execution capabilities.
    """

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
        raise RuntimeError(f"No healthy adapter for capability: {capability}")

    def list_capabilities(self) -> Dict[str, List[str]]:
        return {
            cap: [n for n in names if self._adapters[n].health_check()]
            for cap, names in self._capabilities.items()
        }
