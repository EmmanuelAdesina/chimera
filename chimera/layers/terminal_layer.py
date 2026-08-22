"""
Sandbox-aware terminal execution layer.

This is intentionally conservative:
- no shell=True
- allowlisted executables
- optional workspace boundary
- timeout enforcement
- structured Evidence output

For stronger isolation in production, run this layer inside a container,
Windows Sandbox, Hyper-V VM, Firecracker/gVisor equivalent, or ephemeral CI job.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from chimera.models.evidence import Evidence, EvidenceSource, EvidenceType, ChainOfCustody


@dataclass
class CommandPolicy:
    allowed_executables: set[str] = field(default_factory=lambda: {
        "python", "python.exe", "py",
        "python3", "python3.exe",
        "node", "node.exe",
        "npm", "npm.cmd",
        "npx", "npx.cmd",
        "git", "git.exe",
        "pytest", "pytest.exe",
        "ruff", "ruff.exe",
        "mypy", "mypy.exe",
        "bandit", "bandit.exe",
    })
    workspace_root: Optional[str] = None
    timeout_seconds: int = 30
    max_output_chars: int = 200_000


class TerminalLayer:
    def __init__(self, policy: Optional[CommandPolicy] = None) -> None:
        self.policy = policy or CommandPolicy()
        self.ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

    async def execute(self, payload: Dict[str, Any]) -> Evidence:
        argv = payload.get("argv")
        cwd = payload.get("cwd")
        env = payload.get("env")

        if not isinstance(argv, list) or not argv:
            raise ValueError("terminal.execute requires payload['argv'] as a non-empty list")

        result = await self.run(argv=argv, cwd=cwd, env=env)
        return self._evidence(argv, cwd, result)

    async def run(
        self,
        argv: Sequence[str],
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        executable = Path(str(argv[0])).name
        if executable not in self.policy.allowed_executables:
            raise PermissionError(f"Executable not allowed by policy: {executable}")

        safe_cwd = self._validate_cwd(cwd)

        proc = await asyncio.create_subprocess_exec(
            *[str(x) for x in argv],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=safe_cwd,
            env=self._safe_env(env),
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.policy.timeout_seconds,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Execution timed out after {self.policy.timeout_seconds}s",
                "timed_out": True,
            }

        out = self._clean(stdout)
        err = self._clean(stderr)

        return {
            "exit_code": proc.returncode,
            "stdout": out[: self.policy.max_output_chars],
            "stderr": err[: self.policy.max_output_chars],
            "timed_out": False,
        }

    def _validate_cwd(self, cwd: Optional[str]) -> Optional[str]:
        if cwd is None:
            return None

        resolved = Path(cwd).resolve()

        if self.policy.workspace_root:
            root = Path(self.policy.workspace_root).resolve()
            if root not in resolved.parents and resolved != root:
                raise PermissionError(f"cwd is outside workspace_root: {resolved}")

        return str(resolved)

    def _safe_env(self, env: Optional[Dict[str, str]]) -> Dict[str, str]:
        base = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
            "PYTHONIOENCODING": "utf-8",
        }
        if env:
            for key, value in env.items():
                if key.upper() in {"PATH", "SYSTEMROOT", "TEMP", "TMP", "PYTHONIOENCODING"}:
                    base[key] = value
        return base

    def _clean(self, data: bytes) -> str:
        text = data.decode("utf-8", errors="ignore")
        return self.ansi_escape.sub("", text).strip()

    def _evidence(self, argv: Sequence[str], cwd: Optional[str], result: Dict[str, Any]) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="TerminalLayer",
            action="execute",
            input_ref=" ".join(argv),
            output_ref=ev_id,
            parameters={"cwd": cwd, "exit_code": result.get("exit_code")},
        )
        chain.finalize()

        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.EXPERIMENT_RESULT,
            data={"argv": list(argv), "cwd": cwd, "result": result},
            chain_of_custody=chain,
            confidence=1.0 if result.get("exit_code") == 0 else 0.75,
            description=f"Terminal execution: {' '.join(argv)}",
            metadata={"layer": "terminal"},
        )
