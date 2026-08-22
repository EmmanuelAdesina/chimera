"""SARIF 2.1.0 export for Chimera evidence."""
from __future__ import annotations

import hashlib
import json
from typing import List

from chimera.models import Evidence


class SARIFExporter:
    schema = "https://json.schemastore.org/sarif-2.1.0.json"

    def export_chain(self, evidences: List[Evidence], target_system: str) -> str:
        results = []
        chain_hash = hashlib.sha256()
        for evidence in evidences:
            canonical = json.dumps(evidence.to_dict(), sort_keys=True, default=str).encode()
            chain_hash.update(canonical)
            results.append({
                "ruleId": evidence.evidence_type.value,
                "level": "error" if evidence.confidence >= 0.8 else "warning",
                "message": {"text": evidence.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": target_system}}}],
                "properties": {"confidence": evidence.confidence, "chain_hash": chain_hash.hexdigest()},
            })
        return json.dumps({"$schema": self.schema, "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "Chimera", "version": "0.1.0"}},
            "results": results,
        }]}, indent=2)
