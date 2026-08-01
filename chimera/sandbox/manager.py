"""
Sandbox Manager - Docker container lifecycle.
NOTE: Requires 'docker' Python package and Docker Desktop installed manually.
"""

from typing import Dict, Optional, List
from dataclasses import dataclass

# Placeholder imports - uncomment after installing docker package
# import docker
# import uuid
# import os


@dataclass
class SandboxConfig:
    image: str = "chimera-sandbox:latest"
    network_mode: str = "bridge"
    memory_limit: str = "2g"
    cpu_limit: float = 1.0
    timeout_seconds: int = 300
    persist: bool = False


class SandboxManager:
    """
    The AI's personal computer.
    Creates disposable environments, installs tools on demand, returns results.
    NOTE: Docker-dependent. Will raise if docker is not installed.
    """

    def __init__(self):
        self.active_boxes: Dict[str, any] = {}
        # TODO: self.client = docker.from_env() after installing docker package

    def spawn(self, name: Optional[str] = None, config: Optional[SandboxConfig] = None) -> str:
        raise NotImplementedError("Install docker>=7.0 and Docker Desktop to enable sandboxes")

    def execute(self, box_id: str, command: str, timeout: int = 60) -> Dict:
        raise NotImplementedError("Sandbox not available")

    def destroy(self, box_id: str):
        pass

    def destroy_all(self):
        pass

    def list_active(self) -> List[str]:
        return []
