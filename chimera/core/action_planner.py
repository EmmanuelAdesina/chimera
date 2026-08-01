from typing import Dict
from chimera.models.hypothesis import Hypothesis

class ActionPlanner:
    """
    Maps a hypothesis to the best execution capability.
    """

    CAPABILITY_MAP = {
        "sql injection": "controlled_testing",
        "xss": "browser_automation",
        "idor": "browser_automation",
        "command injection": "environment_interaction",
        "ssrf": "controlled_testing",
        "recon": "observation",
        "endpoint discovery": "browser_automation",
        "authentication bypass": "browser_automation",
        "file inclusion": "controlled_testing",
        "information disclosure": "observation",
    }

    @classmethod
    def select_capability(cls, hypothesis: Hypothesis) -> str:
        claim_lower = hypothesis.claim.lower()
        for pattern, capability in cls.CAPABILITY_MAP.items():
            if pattern in claim_lower:
                return capability
        return "controlled_testing"

    @classmethod
    def build_intent(cls, hypothesis: Hypothesis, target: str) -> Dict:
        capability = cls.select_capability(hypothesis)

        if capability == "browser_automation":
            return {"action": "fetch", "url": target, "wait_for": "body"}
        elif capability == "environment_interaction":
            return {"action": "oneshot", "command": f"curl -I {target}"}
        elif capability == "controlled_testing":
            return {"action": "send_test", "request_spec": {"path": "/", "method": "GET"}, "payload": ""}
        elif capability == "observation":
            return {"target": target}

        return {}
