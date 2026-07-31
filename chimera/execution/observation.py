import subprocess
import json
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class NucleiObservationAdapter(ExecutionAdapter):
    @property
    def capability(self) -> str:
        return 'observation'

    def __init__(self, binary: str = 'nuclei', rate_limit: int = 150):
        self.binary = binary
        self.rate_limit = rate_limit

    def health_check(self) -> bool:
        try:
            subprocess.run([self.binary, '-version'], capture_output=True, check=True)
            return True
        except:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        target = intent.get('target')
        if not target:
            return {'error': 'No target provided'}
        
        cmd = [self.binary, '-u', target, '-rate-limit', str(self.rate_limit), '-jsonl', '-o', '/tmp/nuclei_chimera.jsonl']
        subprocess.run(cmd, capture_output=True)
        
        findings = []
        try:
            with open('/tmp/nuclei_chimera.jsonl') as f:
                for line in f:
                    if not line.strip(): continue
                    data = json.loads(line)
                    findings.append({
                        'template_id': data.get('template-id'),
                        'severity': data.get('info', {}).get('severity'),
                        'matched_at': data.get('matched-at')
                    })
        except:
            pass
        
        return {'capability': 'observation', 'adapter': 'nuclei', 'findings': findings, 'count': len(findings)}
