from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class TerminalAdapter(ExecutionAdapter):
    @property
    def capability(self) -> str:
        return 'environment_interaction'

    def health_check(self) -> bool:
        return True

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        import subprocess
        command = intent.get('command')
        if not command:
            return {'error': 'No command provided'}
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return {
            'capability': 'environment_interaction',
            'adapter': 'terminal',
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
