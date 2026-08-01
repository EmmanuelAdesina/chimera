"""
Tool Manager - Dynamic tool provisioning inside sandboxes.
NOTE: Requires SandboxManager to be functional.
"""

from typing import Dict, List


class ToolManager:
    """
    Manages security tools inside sandboxes.
    The AI requests tools by name; this handles installation.
    """

    TOOL_REGISTRY = {
        "nuclei": {
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
            "check": "which nuclei && nuclei -version",
            "binary": "nuclei",
            "type": "recon"
        },
        "ffuf": {
            "install": "go install -v github.com/ffuf/ffuf@latest",
            "check": "which ffuf",
            "binary": "ffuf",
            "type": "fuzzing"
        },
        "sqlmap": {
            "install": "pip install sqlmap",
            "check": "which sqlmap",
            "binary": "sqlmap",
            "type": "exploitation"
        },
        "gobuster": {
            "install": "go install -v github.com/OJ/gobuster/v3@latest",
            "check": "which gobuster",
            "binary": "gobuster",
            "type": "recon"
        },
        "nmap": {
            "install": "apt-get update && apt-get install -y nmap",
            "check": "which nmap",
            "binary": "nmap",
            "type": "recon"
        }
    }

    def __init__(self, sandbox_manager):
        self.sandbox = sandbox_manager
        self._installed_cache: Dict[str, List[str]] = {}

    def ensure_tool(self, box_id: str, tool_name: str) -> bool:
        raise NotImplementedError("Sandbox not available. Install docker>=7.0 first.")

    def run_tool(self, box_id: str, tool_name: str, arguments: str, timeout: int = 120) -> Dict:
        return {"error": "Sandbox not available"}

    def discover_tools(self, box_id: str) -> List[str]:
        return []
