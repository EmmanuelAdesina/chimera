"""Optional runtime hooks for ASI extensions.

The hook is intentionally idempotent and only patches APIs that exist.  This
keeps the extension compatible with Chimera's evolving core instead of making
startup depend on a particular Debunker implementation.
"""
from __future__ import annotations

from typing import Any

from chimera.core import debunker
from chimera.parsers.javascript_parser import AsyncPromiseAnalyzer

_INITIALIZED = False
_ORIGINAL_EXECUTE_VECTOR: Any = None


def inject_debunker_vectors() -> bool:
    """Add ASYNC_TOCTOU support when the core exposes an execution hook."""
    global _ORIGINAL_EXECUTE_VECTOR
    execute = getattr(debunker.Debunker, "execute_vector", None)
    if not callable(execute):
        return False
    if _ORIGINAL_EXECUTE_VECTOR is not None:
        return True
    _ORIGINAL_EXECUTE_VECTOR = execute

    def extended_execute(self: Any, hypothesis: Any) -> Any:
        if getattr(hypothesis, "vector", None) == "ASYNC_TOCTOU":
            code = getattr(hypothesis, "code_bytes", b"")
            return AsyncPromiseAnalyzer().analyze_race_conditions(code)
        return _ORIGINAL_EXECUTE_VECTOR(self, hypothesis)

    debunker.Debunker.execute_vector = extended_execute
    return True


def inject_async_state_mapping() -> None:
    """Reserved extension point for broker state edges (Kafka, Redis, RabbitMQ)."""


def initialize_asi_extensions() -> bool:
    """Initialize extensions once; return whether initialization completed."""
    global _INITIALIZED
    if not _INITIALIZED:
        inject_debunker_vectors()
        inject_async_state_mapping()
        _INITIALIZED = True
    return _INITIALIZED
