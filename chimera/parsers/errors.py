"""Chimera parser errors — structured, contextual parse failure types."""

from __future__ import annotations

from typing import Optional


class ParseError(Exception):
    """
    Raised when a source file cannot be parsed.

    Carries file path, line number, and a source snippet so failures are
    diagnosable without re-running the parser under a debugger.
    """

    def __init__(
        self,
        message: str,
        file_path: str = "",
        line: Optional[int] = None,
        snippet: str = "",
        parser: str = "",
    ) -> None:
        self.file_path = file_path
        self.line = line
        self.snippet = snippet
        self.parser = parser
        location = f"{file_path}:{line}" if line else file_path
        prefix = f"[{parser}] " if parser else ""
        full = f"{prefix}{message}"
        if location:
            full = f"{full} ({location})"
        super().__init__(full)

    @classmethod
    def from_syntax_error(
        cls, exc: SyntaxError, file_path: str, source: str, parser: str = ""
    ) -> "ParseError":
        """Build a ParseError from an ``ast``/compile SyntaxError with context."""
        line = exc.lineno or 0
        snippet = ""
        if 0 < line <= len(source.splitlines()):
            snippet = source.splitlines()[line - 1].strip()
        message = exc.msg or "invalid syntax"
        if snippet:
            message = f"{message} — near: {snippet[:120]!r}"
        return cls(
            message,
            file_path=file_path,
            line=line or None,
            snippet=snippet,
            parser=parser,
        )
