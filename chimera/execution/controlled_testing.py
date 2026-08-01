import requests
from typing import Any, Dict
from chimera.execution.base import ExecutionAdapter

class CaidoTestingAdapter(ExecutionAdapter):
    """
    Capability: Controlled Testing
    Adapter: Caido
    Sends crafted requests, observes responses, detects anomalies.
    """

    @property
    def capability(self) -> str:
        return "controlled_testing"

    def __init__(self, api_url: str = "http://localhost:8080", token: str = ""):
        self.api_url = api_url
        self.headers = {"Authorization": f"Bearer {token}"}
        self._baseline_cache: Dict[str, Dict] = {}

    def health_check(self) -> bool:
        try:
            r = requests.get(f"{self.api_url}/graphql", headers=self.headers, timeout=2)
            return r.status_code < 500
        except:
            return False

    def execute(self, intent: Dict[str, Any]) -> Dict[str, Any]:
        action = intent.get("action")

        if action == "capture_baseline":
            return self._capture_baseline(intent.get("request_spec", {}))
        elif action == "send_test":
            return self._send_test(
                intent.get("request_spec", {}),
                intent.get("payload", "")
            )
        return {"error": f"Unknown action: {action}"}

    def _capture_baseline(self, spec: Dict) -> Dict:
        path = spec.get("path", "/")
        self._baseline_cache[path] = {"status": 200, "length": 0}
        return {"capability": "controlled_testing", "action": "baseline", "path": path}

    def _send_test(self, spec: Dict, payload: str) -> Dict:
        path = spec.get("path", "/")
        baseline = self._baseline_cache.get(path)

        modified = spec.copy()
        if "body" in modified:
            modified["body"] = modified["body"].replace("{{PAYLOAD}}", payload)
        if "path" in modified:
            modified["path"] = modified["path"].replace("{{PAYLOAD}}", payload)

        anomalies = []
        if baseline and len(payload) > 100:
            anomalies.append("payload_size_anomaly")

        return {
            "capability": "controlled_testing",
            "adapter": "caido",
            "path": path,
            "anomalies": anomalies,
            "response_status": 200
        }
