"""
JavaScript/TypeScript async-state parser.

Uses conservative static analysis to identify async boundaries that deserve
controlled testing:
- state mutation before await
- Promise.all with shared-looking identifiers
- async function bodies with mixed mutation and awaits

Tree-sitter is optional. If unavailable, a regex fallback is used.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


@dataclass
class JSAsyncFinding:
    kind: str
    description: str
    line: int = 0
    confidence: float = 0.6
    metadata: Dict[str, Any] = field(default_factory=dict)


class AsyncJavaScriptAnalyzer:
    assignment_pattern = re.compile(r"(?P<lhs>(?:this\.)?[A-Za-z_$][\w$\.]*)\s*(?:=|\+=|-=|\*=|/=)")
    await_pattern = re.compile(r"\bawait\b")
    async_fn_pattern = re.compile(
        r"async\s+function\s+(?P<name>[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}",
        re.DOTALL,
    )
    async_arrow_pattern = re.compile(
        r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*async\s*\([^)]*\)\s*=>\s*\{(?P<body>.*?)\n\}",
        re.DOTALL,
    )

    def analyze_source(self, source: str, file_path: str = "") -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []
        findings.extend(self._analyze_async_functions(source, file_path))
        findings.extend(self._analyze_promise_all(source, file_path))
        findings.extend(self._analyze_unawaited_promises(source, file_path))
        return findings

    def analyze_to_evidence(self, source: str, file_path: str = "") -> List[Evidence]:
        return [self._evidence(finding, file_path) for finding in self.analyze_source(source, file_path)]

    def analyze_race_conditions(self, code_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Backward-compatible entry point used by chimera.core.asi_runtime_patch.

        Accepts raw source bytes, runs the source analysis, and maps
        ASYNC_STATE_MUTATION_BEFORE_AWAIT findings onto the legacy
        ``ASYNC_TOCTOU`` vector dictionaries.
        """
        if isinstance(code_bytes, (bytes, bytearray)):
            source = code_bytes.decode("utf-8", errors="ignore")
        else:
            source = str(code_bytes)

        vectors: List[Dict[str, Any]] = []
        for finding in self.analyze_source(source):
            if finding.kind != "ASYNC_STATE_MUTATION_BEFORE_AWAIT":
                continue
            vectors.append({
                "vector": "ASYNC_TOCTOU",
                "location": (finding.line - 1, 0),
                "description": finding.description,
            })
        return vectors

    def _analyze_async_functions(self, source: str, file_path: str) -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []
        matches = list(self.async_fn_pattern.finditer(source)) + list(self.async_arrow_pattern.finditer(source))

        for match in matches:
            name = match.group("name")
            body = match.group("body")
            start_line = source[: match.start()].count("\n") + 1

            await_match = self.await_pattern.search(body)
            if not await_match:
                continue

            first_await_pos = await_match.start()
            before_await = body[:first_await_pos]
            mutation_match = self.assignment_pattern.search(before_await)

            if mutation_match:
                findings.append(JSAsyncFinding(
                    kind="ASYNC_STATE_MUTATION_BEFORE_AWAIT",
                    description=(
                        f"Async function {name} mutates {mutation_match.group('lhs')} before an await boundary. "
                        "This may represent a TOCTOU-sensitive state transition and should be tested dynamically."
                    ),
                    line=start_line + before_await[: mutation_match.start()].count("\n"),
                    confidence=0.72,
                    metadata={"function": name, "lhs": mutation_match.group("lhs"), "file_path": file_path},
                ))

        return findings

    def _analyze_promise_all(self, source: str, file_path: str) -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []

        for match in re.finditer(r"Promise\.all\s*\((?P<body>.*?)\)", source, re.DOTALL):
            body = match.group("body")
            line = source[: match.start()].count("\n") + 1

            if self.assignment_pattern.search(body):
                findings.append(JSAsyncFinding(
                    kind="PROMISE_ALL_SHARED_STATE",
                    description="Promise.all block contains state mutation candidates; verify shared-state race behavior.",
                    line=line,
                    confidence=0.65,
                    metadata={"file_path": file_path},
                ))

        return findings

    def _analyze_unawaited_promises(self, source: str, file_path: str) -> List[JSAsyncFinding]:
        findings: List[JSAsyncFinding] = []
        promise_call = re.compile(r"(?<!await\s)(?P<call>[A-Za-z_$][\w$]*\([^;\n]*\))\s*;")

        for match in promise_call.finditer(source):
            call = match.group("call")
            if any(term in call.lower() for term in ["fetch", "axios", "request", "query", "save", "update"]):
                findings.append(JSAsyncFinding(
                    kind="POTENTIALLY_UNAWAITED_ASYNC_CALL",
                    description=f"Potentially unawaited async call: {call}",
                    line=source[: match.start()].count("\n") + 1,
                    confidence=0.55,
                    metadata={"call": call, "file_path": file_path},
                ))

        return findings

    def _evidence(self, finding: JSAsyncFinding, file_path: str) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="AsyncJavaScriptAnalyzer",
            action=finding.kind,
            input_ref=f"{file_path}:{finding.line}",
            output_ref=ev_id,
            parameters=finding.metadata,
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.STATIC_ANALYSIS,
            evidence_type=EvidenceType.CODE_SNIPPET,
            data={"finding": finding.__dict__},
            chain_of_custody=chain,
            file_path=file_path,
            line_range=(finding.line, finding.line),
            confidence=finding.confidence,
            description=finding.description,
            metadata={"parser": "javascript", "kind": finding.kind},
        )


# Backward-compatible alias.
AsyncPromiseAnalyzer = AsyncJavaScriptAnalyzer
