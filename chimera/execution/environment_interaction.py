import subprocess
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class TerminalAdapter(ExecutionAdapter):
    """
    Capability: Environment Interaction
    Adapter: Local/Remote Shell
    """

    @property
    def capability(self) -> str:
        return "environment_interaction"

    def health_check(self) -> bool:
        return True

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        action = intent.get("action", "oneshot")

        if action == "oneshot":
            return self._run_command(intent.get("command", ""))
        elif action == "interactive":
            return self._interactive_session(intent)
        elif action == "stream":
            return self._stream_command(intent.get("command", ""))
        return {"error": f"Unknown action: {action}"}

    def _run_command(self, command: str) -> Dict:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
        return {
            "capability": "environment_interaction",
            "adapter": "terminal",
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    def _interactive_session(self, intent: Dict) -> Dict:
        command = intent.get("command")
        inputs = intent.get("inputs", [])

        proc = subprocess.Popen(
            command,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        outputs = []
        import time
        for inp in inputs:
            proc.stdin.write(inp + "\n")
            proc.stdin.flush()
            time.sleep(0.5)
            if proc.stdout.readable():
                outputs.append(proc.stdout.read(4096))

        proc.stdin.close()
        proc.wait()

        return {
            "capability": "environment_interaction",
            "adapter": "terminal",
            "mode": "interactive",
            "outputs": outputs,
            "returncode": proc.returncode
        }

    def _stream_command(self, command: str) -> Dict:
        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        lines = []
        for line in proc.stdout:
            lines.append(line.rstrip())
            if len(lines) > 1000:
                break

        proc.wait()
        return {
            "capability": "environment_interaction",
            "adapter": "terminal",
            "mode": "stream",
            "lines": lines,
            "truncated": proc.poll() is None
        }
