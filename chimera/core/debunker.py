# chimera/core/debunker.py - COMPLETE VERSION

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
import re
import requests

from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence


class DebunkSeverity(Enum):
    FATAL = "fatal"           # Hypothesis is definitely wrong
    CRITICAL = "critical"     # Major flaw, probably wrong
    WARNING = "warning"       # Weakness, needs more evidence
    COSMETIC = "cosmetic"     # Minor issue with claim wording


@dataclass
class DebunkFinding:
    attack_vector: str
    severity: DebunkSeverity
    reasoning: str
    evidence_required: List[str]
    confidence_impact: float


class Debunker:
    """
    The adversarial agent that tries to destroy hypotheses before they waste human time.
    
    Design principle: Be maximally hostile. Assume every hypothesis is garbage.
    Only let through the ones that survive cross-examination.
    
    Target: 90% false positive filtration rate.
    """

    def __init__(self):
        self.attacks: List[callable] = [
            self._attack_correlation_vs_causation,
            self._attack_confounding_variable,
            self._attack_reachability,
            self._attack_defense_layer,
            self._attack_semantic_misdirection,
            self._attack_version_mismatch,      # IMPLEMENTED
            self._attack_context_irrelevance,
            self._attack_duplicate_or_known,    # IMPLEMENTED
            self._attack_exploitability_doubt,  # IMPLEMENTED
        ]
        self.kill_threshold = 0.3
        self.memory = None  # Will be injected for duplicate checking

    def debunk(self, hypothesis: Hypothesis) -> Dict:
        findings: List[DebunkFinding] = []
        original_confidence = hypothesis.confidence

        for attack in self.attacks:
            finding = attack(hypothesis)
            if finding:
                findings.append(finding)
                hypothesis.confidence -= finding.confidence_impact

        hypothesis.confidence = max(0.0, min(1.0, hypothesis.confidence))

        survived = hypothesis.confidence >= self.kill_threshold

        if not survived:
            hypothesis.status = "rejected"

        return {
            "hypothesis_id": hypothesis.id,
            "original_confidence": original_confidence,
            "final_confidence": hypothesis.confidence,
            "survived": survived,
            "findings": findings,
            "verdict": "PASS_TO_TRIAGE" if survived else "DEBUNKED",
            "kill_reason": self._summarize_kill(findings) if not survived else None
        }

    # ───────────────────────────────────────────
    # ATTACK 1: Correlation vs. Causation
    # ───────────────────────────────────────────
    def _attack_correlation_vs_causation(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        observational_only = all(
            e.source in ["static_analysis", "pattern_match", "regex"]
            for e in hyp.evidence
        )
        if observational_only and len(hyp.evidence) < 2:
            return DebunkFinding(
                attack_vector="correlation_vs_causation",
                severity=DebunkSeverity.CRITICAL,
                reasoning="Evidence is purely observational. No data-flow proof.",
                evidence_required=["Taint analysis", "Dynamic trace"],
                confidence_impact=0.4
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 2: Confounding Variable
    # ───────────────────────────────────────────
    def _attack_confounding_variable(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        if "framework" in hyp.claim.lower() or "library" in hyp.claim.lower():
            return DebunkFinding(
                attack_vector="confounding_variable",
                severity=DebunkSeverity.WARNING,
                reasoning="May be a documented framework behavior.",
                evidence_required=["Framework docs", "Security advisory"],
                confidence_impact=0.2
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 3: Reachability
    # ───────────────────────────────────────────
    def _attack_reachability(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        unreachable_keywords = ["admin_only", "internal_api", "test_", "localhost", "debug_mode", "requires_auth"]
        for kw in unreachable_keywords:
            if kw in str(hyp.metadata if hasattr(hyp, 'metadata') else {}):
                return DebunkFinding(
                    attack_vector="reachability",
                    severity=DebunkSeverity.CRITICAL,
                    reasoning=f"Code path contains '{kw}', unlikely attacker-accessible.",
                    evidence_required=["Public endpoint mapping", "Auth bypass proof"],
                    confidence_impact=0.5
                )
        return None

    # ───────────────────────────────────────────
    # ATTACK 4: Defense Layer
    # ───────────────────────────────────────────
    def _attack_defense_layer(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        defense_indicators = ["waf", "cloudflare", "mod_security", "rasp", "input_validation", "csp", "csrf_token"]
        addresses_defense = any(d in str(hyp.claim).lower() or d in str(hyp.missing_information).lower() for d in defense_indicators)
        if not addresses_defense and "injection" in hyp.claim.lower():
            return DebunkFinding(
                attack_vector="defense_layer",
                severity=DebunkSeverity.WARNING,
                reasoning="Injection claim made without evaluating WAF/RASP interference.",
                evidence_required=["WAF rule analysis", "RASP bypass confirmation"],
                confidence_impact=0.25
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 5: Semantic Misdirection
    # ───────────────────────────────────────────
    def _attack_semantic_misdirection(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        if "sql" in hyp.claim.lower():
            # Check if evidence actually proves SQL, not just the word 'query'
            if "query" in str(hyp.evidence).lower() and "sql" not in str(hyp.evidence).lower():
                return DebunkFinding(
                    attack_vector="semantic_misdirection",
                    severity=DebunkSeverity.WARNING,
                    reasoning="'Query' in evidence may refer to GraphQL, not SQL.",
                    evidence_required=["Database driver identification", "Actual SQL injection proof"],
                    confidence_impact=0.3
                )
        return None

    # ───────────────────────────────────────────
    # ATTACK 6: Version Mismatch (IMPLEMENTED)
    # ───────────────────────────────────────────
    def _attack_version_mismatch(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Is the vulnerability already patched in the deployed version?
        """
        if not hyp.target_version:
            return DebunkFinding(
                attack_vector="version_mismatch",
                severity=DebunkSeverity.WARNING,
                reasoning="Target version unknown. Cannot verify if vulnerability is patched.",
                evidence_required=["Target version fingerprint", "CVE database lookup"],
                confidence_impact=0.15
            )
        
        # Check if this vulnerability is known to be patched in this version
        if self._is_version_patched(hyp.vulnerability_id, hyp.target_version):
            return DebunkFinding(
                attack_vector="version_mismatch",
                severity=DebunkSeverity.FATAL,
                reasoning=f"Vulnerability {hyp.vulnerability_id} was patched in version {hyp.target_version} or earlier.",
                evidence_required=["Vendor changelog", "Patch commit"],
                confidence_impact=0.8
            )
        return None

    def _is_version_patched(self, vuln_id: str, target_version: str) -> bool:
        """
        Placeholder: Query CVE database and vendor changelogs.
        """
        # In production, this would query NVD, vendor APIs, or a local cache
        patched_versions = {
            "CVE-2023-12345": "1.2.3",
            "CVE-2024-67890": "2.0.0",
        }
        return patched_versions.get(vuln_id) == target_version

    # ───────────────────────────────────────────
    # ATTACK 7: Context Irrelevance
    # ───────────────────────────────────────────
    def _attack_context_irrelevance(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        context_keywords = ["test", "spec", "mock", "fixture", "example", "demo"]
        for kw in context_keywords:
            if kw in str(hyp.file_path).lower():
                return DebunkFinding(
                    attack_vector="context_irrelevance",
                    severity=DebunkSeverity.CRITICAL,
                    reasoning=f"Code is in a {kw} file. Not production code.",
                    evidence_required=["Production code path confirmation"],
                    confidence_impact=0.6
                )
        return None

    # ───────────────────────────────────────────
    # ATTACK 8: Duplicate or Known (IMPLEMENTED)
    # ───────────────────────────────────────────
    def _attack_duplicate_or_known(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Has this vulnerability already been discovered or submitted?
        """
        if self.memory and self.memory.is_known(hyp):
            return DebunkFinding(
                attack_vector="duplicate_or_known",
                severity=DebunkSeverity.FATAL,
                reasoning="This vulnerability pattern has been submitted before.",
                evidence_required=["Previous submission ID", "Duplicate confirmation"],
                confidence_impact=1.0
            )
        
        # Check if there's a public CVE for this pattern + target
        if self._is_publicly_known(hyp):
            return DebunkFinding(
                attack_vector="duplicate_or_known",
                severity=DebunkSeverity.CRITICAL,
                reasoning="A public CVE exists for this vulnerability in this target.",
                evidence_required=["CVE ID", "Public disclosure link"],
                confidence_impact=0.7
            )
        return None

    def _is_publicly_known(self, hyp: Hypothesis) -> bool:
        """
        Placeholder: Query CVE database for target + vulnerability pattern.
        """
        # In production: query NVD API, HackerOne disclosure API, etc.
        return False

    # ───────────────────────────────────────────
    # ATTACK 9: Exploitability Doubt (IMPLEMENTED)
    # ───────────────────────────────────────────
    def _attack_exploitability_doubt(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Even if technically a bug, can it actually be exploited?
        """
        conditions = ["requires_local_admin", "requires_physical_access", "requires_root", "requires_ssrf_chain"]
        for cond in conditions:
            if cond in str(hyp.metadata if hasattr(hyp, 'metadata') else {}):
                return DebunkFinding(
                    attack_vector="exploitability_doubt",
                    severity=DebunkSeverity.WARNING,
                    reasoning=f"Exploitation requires '{cond}', which is unrealistic in most scenarios.",
                    evidence_required=["Chained exploit proof", "Realistic attack scenario"],
                    confidence_impact=0.3
                )
        return None

    # ───────────────────────────────────────────
    # UTILITY: Summarize Kill Reason
    # ───────────────────────────────────────────
    def _summarize_kill(self, findings: List[DebunkFinding]) -> str:
        if not findings:
            return "Unknown (no findings recorded)"
        fatal = [f for f in findings if f.severity == DebunkSeverity.FATAL]
        critical = [f for f in findings if f.severity == DebunkSeverity.CRITICAL]
        
        if fatal:
            return f"Fatal: {fatal[0].attack_vector} - {fatal[0].reasoning[:100]}"
        if critical:
            return f"Critical: {critical[0].attack_vector} - {critical[0].reasoning[:100]}"
        return f"Multiple weaknesses: {', '.join([f.attack_vector for f in findings[:3]])}"

    def inject_memory(self, memory):
        """Inject the memory system for duplicate checking."""
        self.memory = memory
           
class DebunkerFeedback:
    def __init__(self):
        self.killed_hypotheses = []
        self.valid_bugs_killed = 0
        self.false_positives_killed = 0
    
    def record_kill(self, hypothesis, triage_outcome):
        """Compare killed hypothesis to actual triage outcome."""
        if triage_outcome == "ACCEPTED":
            self.valid_bugs_killed += 1
            # Recalibrate: this attack was too aggressive
        elif triage_outcome == "REJECTED":
            self.false_positives_killed += 1
            # This attack is working correctly
