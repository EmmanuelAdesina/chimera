# chimera/core/debunker.py

from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

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
    evidence_required: List[str]  # What would prove this attack wrong
    confidence_impact: float  # How much to reduce hypothesis confidence


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
            self._attack_version_mismatch,
            self._attack_context_irrelevance,
            self._attack_duplicate_or_known,
            self._attack_exploitability_doubt,
        ]
        self.kill_threshold = 0.3  # Confidence below this after debunking = dead

    def debunk(self, hypothesis: Hypothesis) -> Dict:
        """
        Run all attacks against a hypothesis.
        Return: survive (bool), findings (list), final_confidence (float)
        """
        findings: List[DebunkFinding] = []
        original_confidence = hypothesis.confidence
        
        for attack in self.attacks:
            finding = attack(hypothesis)
            if finding:
                findings.append(finding)
                hypothesis.confidence -= finding.confidence_impact
        
        # Clamp confidence
        hypothesis.confidence = max(0.0, min(1.0, hypothesis.confidence))
        
        # Determine verdict
        survived = hypothesis.confidence >= self.kill_threshold
        
        # If killed, record why for learning
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
        """
        The most common false positive: 'I saw X near Y, therefore X causes Y.'
        """
        # Check if evidence is purely observational (pattern match) vs. causal (data flow)
        observational_only = all(
            e.source in ["static_analysis", "pattern_match", "regex"]
            for e in hyp.evidence
        )
        
        if observational_only and len(hyp.evidence) < 2:
            return DebunkFinding(
                attack_vector="correlation_vs_causation",
                severity=DebunkSeverity.CRITICAL,
                reasoning=(
                    f"Evidence is purely observational ({[e.source for e in hyp.evidence]}). "
                    f"No data-flow proof that attacker input reaches the sink. "
                    f"The pattern 'f-string' correlates with SQLi but does not prove it."
                ),
                evidence_required=[
                    "Taint analysis showing user input -> sink path",
                    "Dynamic trace confirming execution path"
                ],
                confidence_impact=0.4
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 2: Confounding Variable
    # ───────────────────────────────────────────
    def _attack_confounding_variable(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Is there a third factor that explains both the evidence and the 'vulnerability'?
        """
        # Example: The 'vulnerability' is actually a framework feature
        if "framework" in hyp.claim.lower() or "library" in hyp.claim.lower():
            return DebunkFinding(
                attack_vector="confounding_variable",
                severity=DebunkSeverity.WARNING,
                reasoning=(
                    "The claimed vulnerability may be a documented framework behavior. "
                    "e.g., Django's raw() is intentionally dangerous and documented as such."
                ),
                evidence_required=[
                    "Framework documentation showing this is intentional",
                    "Security advisory confirming this is a bug, not a feature"
                ],
                confidence_impact=0.2
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 3: Reachability
    # ───────────────────────────────────────────
    def _attack_reachability(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Can an attacker actually reach this code path?
        """
        # Check if hypothesis mentions auth, admin, internal, or test
        unreachable_keywords = ["admin_only", "internal_api", "test_", "localhost", 
                               "debug_mode", "requires_auth"]
        
        for kw in unreachable_keywords:
            if kw in str(hyp.metadata if hasattr(hyp, 'metadata') else {}):
                return DebunkFinding(
                    attack_vector="reachability",
                    severity=DebunkSeverity.CRITICAL,
                    reasoning=(
                        f"Code path contains '{kw}', suggesting attacker cannot reach it "
                        f"without prior compromise or authentication."
                    ),
                    evidence_required=[
                        "Public endpoint mapping showing this route is exposed",
                        "Authentication bypass proof"
                    ],
                    confidence_impact=0.5
                )
        
        # Check missing_information for reachability gaps
        reachability_missing = any(
            "attacker" in m.lower() or "reach" in m.lower() or "auth" in m.lower()
            for m in hyp.missing_information
        )
        if reachability_missing and len(hyp.evidence) < 2:
            return DebunkFinding(
                attack_vector="reachability",
                severity=DebunkSeverity.FATAL,
                reasoning=(
                    "Hypothesis explicitly admits attacker reachability is unknown, "
                    "yet claims a vulnerability exists. Cannot prove a negative, "
                    "but cannot claim a positive either."
                ),
                evidence_required=[
                    "Proof that unauthenticated users can reach this endpoint"
                ],
                confidence_impact=0.6
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 4: Defense Layer
    # ───────────────────────────────────────────
    def _attack_defense_layer(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Would WAF, RASP, CSP, or framework protections block this?
        """
        defense_indicators = ["waf", "cloudflare", "mod_security", "rasp", 
                             "input_validation", "csp", "csrf_token"]
        
        # If the hypothesis doesn't address defenses at all, that's suspicious
        addresses_defense = any(
            d in str(hyp.claim).lower() or d in str(hyp.missing_information).lower()
            for d in defense_indicators
        )
        
        if not addresses_defense and "injection" in hyp.claim.lower():
            return DebunkFinding(
                attack_vector="defense_layer",
                severity=DebunkSeverity.WARNING,
                reasoning=(
                    "Injection claim made without evaluating WAF/RASP interference. "
                    "Modern deployments have multiple defense layers that static analysis cannot see."
                ),
                evidence_required=[
                    "WAF rule analysis showing payload would pass",
                    "RASP bypass confirmation"
                ],
                confidence_impact=0.25
            )
        return None

    # ───────────────────────────────────────────
    # ATTACK 5: Semantic Misdirection
    # ───────────────────────────────────────────
    def _attack_semantic_misdirection(self, hyp: Hypothesis) -> Optional[DebunkFinding]:
        """
        Variable names lie. 'query' might be a GraphQL query, not SQL.
        """
        if "sql" in hyp.claim.lower():
            # Check if evidence actually proves SQL, or just the word 'query'
           
