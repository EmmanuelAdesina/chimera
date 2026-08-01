from abc import ABC, abstractmethod
from typing import Any, Optional
from chimera.models.causal import ParserLayerModel

class BaseParser(ABC):
    """
    Abstract base for all parser cascade builders.
    To extend: subclass, implement parse() and detect_sanitizer().
    """

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def parse(self, source: Any) -> ParserLayerModel:
        """Extract grammar and sanitizer info from source code."""
        raise NotImplementedError

    @abstractmethod
    def detect_sanitizer(self, source: Any) -> Optional[str]:
        """Identify if/where a sanitizer exists between layers."""
        raise NotImplementedError
