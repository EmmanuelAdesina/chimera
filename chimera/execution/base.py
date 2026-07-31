from abc import ABC, abstractmethod
from typing import Any, Dict

class ExecutionAdapter(ABC):
    @property
    @abstractmethod
    def capability(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> bool:
        raise NotImplementedError
