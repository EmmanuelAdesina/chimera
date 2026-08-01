from abc import ABC, abstractmethod
from typing import Any, Dict

class ExecutionAdapter(ABC):
    """
    Abstract base for all execution capabilities.
    Adapters translate Chimera's intent into specific tool actions.
    The capability (what we want to do) is stable.
    The adapter (which tool does it) is replaceable.
    """

    @property
    @abstractmethod
    def capability(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the intent and return observations."""
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> bool:
        """Is this adapter available and functional?"""
        raise NotImplementedError
