"""Unit tests for the sandbox-aware terminal layer."""

from __future__ import annotations

import asyncio

import pytest

from chimera.layers.terminal_layer import CommandPolicy, TerminalLayer


def _run_sync(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestPolicy:
    def test_allowlisted_executable(self):
        layer = TerminalLayer()
        result = asyncio.run(layer.run(["python3", "--version"]))
        assert result["exit_code"] == 0
        assert "Python" in result["stdout"]

    def test_disallowed_executable(self):
        layer = TerminalLayer()
        with pytest.raises(PermissionError):
            asyncio.run(layer.run(["nmap", "-sS", "localhost"]))

    def test_inline_code_blocked_by_default(self):
        """python -c 'arbitrary code' must not pass the allowlist policy."""
        layer = TerminalLayer()
        with pytest.raises(PermissionError) as exc:
            asyncio.run(layer.run(["python3", "-c", "print('pwned')"]))
        assert "Inline code execution" in str(exc.value)

    def test_node_eval_blocked(self):
        layer = TerminalLayer()
        with pytest.raises(PermissionError):
            asyncio.run(layer.run(["node", "-e", "console.log(1)"]))

    def test_inline_code_opt_in(self, tmp_path):
        policy = CommandPolicy(allow_interpreter_code=True)
        layer = TerminalLayer(policy)
        result = asyncio.run(layer.run(["python3", "-c", "print('hi')"]))
        assert result["exit_code"] == 0
        assert result["stdout"] == "hi"

    def test_workspace_boundary(self, tmp_path):
        policy = CommandPolicy(workspace_root=str(tmp_path))
        layer = TerminalLayer(policy)
        with pytest.raises(PermissionError):
            asyncio.run(layer.run(["python3", "--version"], cwd="/tmp"))
        # Inside the workspace it works
        result = asyncio.run(layer.run(["python3", "--version"], cwd=str(tmp_path)))
        assert result["exit_code"] == 0

    def test_timeout(self):
        policy = CommandPolicy(timeout_seconds=1, allow_interpreter_code=True)
        layer = TerminalLayer(policy)
        result = asyncio.run(
            layer.run(["python3", "-c", "import time; time.sleep(5)"])
        )
        assert result["timed_out"] is True

    def test_evidence_chain_of_custody(self):
        layer = TerminalLayer()
        ev = asyncio.run(layer.execute({"argv": ["python3", "--version"], "cwd": "."}))
        assert ev.chain_of_custody.verify()
        assert ev.confidence == 1.0
