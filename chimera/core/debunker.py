"""Chimera Debunker — The Gatekeeper. Hostile adversarial review with 9 attack vectors.

The Debunker is the adversarial gatekeeper of Chimera. Every hypothesis MUST
survive all 9 attack vectors to proceed to experimentation. Target: 90% false-
positive kill rate.

The 9 Attack Vectors:
    1. Tautology Check — Is the claim trivially true/unfalsifiable?
    2. Assumption Audit — Does it rely on unstated assumptions?
    3. Counter-Example Search — Can we find a falsifying case?
    4. Causal Chain Break — Does the causal chain hold logically?
    5. Scope Creep — Is the claim broader than evidence supports?
    6. Confirmation Bias — Was evidence selectively gathered?
    7. Temporal Validity — Is this still valid given the code?
    8. Semantic Drift — Have terms shifted meaning?
    9. Attack Surface Mismatch — Does this actually affect security?
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from chimera.models.hypothesis import Hypothesis, HypothesisStatus, VulnerabilityClass
    from chimera.core.semantic_graph import SemanticGraph


@dataclass
class DebunkResult:
    """Result of a single attack vector on a hypothesis."""
    attack_name: str
    survived: bool
    score: float
    reasoning: str
    kill_reason: str = ""
    suggested_refinement: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_name": self.attack_name,
            "survived": self.survived,
            "score": self.score,
            "reasoning": self.reasoning,
            "kill_reason": self.kill_reason,
            "suggested_refinement": self.suggested_refinement,
        }


@dataclass
class DebunkReport:
    """Complete debunking report for a hypothesis."""
    hypothesis_id: str
    survived_all: bool
    attack_results: List[DebunkResult]
    overall_score: float
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "survived_all": self.survived_all,
            "attack_results": [r.to_dict() for r in self.attack_results],
            "overall_score": self.overall_score,
            "recommendation": self.recommendation,
        }


class Debunker:
    """
    Hostile adversarial reviewer. Attacks every hypothesis with 9 vectors.

    The Debunker does not care about being fair. It actively tries to
    destroy hypotheses. Only the strongest survive.
    """

    # Patterns that indicate tautological claims
    _TAUTOLOGY_PATTERNS = [
        "does not check", "lacks a check", "is missing",
        "no check found", "without checking", "fails to check",
    ]

    # Common unstated assumptions to audit
    _COMMON_ASSUMPTIONS = [
        "no middleware enforces authorization",
        "no framework-level protection exists",
        "no database-level row security",
        "no WAF rules block the attack",
        "no API gateway enforces policies",
        "no rate limiting prevents brute force",
        "the application is the only access point",
        "error messages do not leak information",
        "logs are not monitored for anomalies",
    ]

    # Confirmation bias indicators
    _BIAS_INDICATORS = [
        "only", "all", "every", "always", "never", "definitely",
        "clearly", "obviously", "certainly",
    ]

    def __init__(self) -> None:
        self.total_debunked = 0
        self.total_survived = 0
        self.attack_stats: Dict[str, Dict[str, int]] = {}

    def debunk(
        self,
        hypothesis: Hypothesis,
        graph: Optional[SemanticGraph] = None,
        memory: Optional[object] = None,
    ) -> DebunkReport:
        """Run all 9 attack vectors. Return a complete report."""
        attacks = [
            ("tautology_check", self.tautology_check),
            ("assumption_audit", self.assumption_audit),
            ("counter_example_search", self.counter_example_search),
            ("causal_chain_break", self.causal_chain_break),
            ("scope_creep", self.scope_creep),
            ("confirmation_bias", self.confirmation_bias),
            ("temporal_validity", self.temporal_validity),
            ("semantic_drift", self.semantic_drift),
            ("attack_surface_mismatch", self.attack_surface_mismatch),
        ]

        results: List[DebunkResult] = []
        for name, method in attacks:
            result = method(hypothesis, graph, memory)
            results.append(result)
            self._record_attack(name, result)
            if not result.survived:
                # Hypothesis killed — stop immediately
                hypothesis.debunker_notes[name] = result.to_dict()
                self._record_verdict(hypothesis, killed=True)
                self.total_debunked += 1
                return DebunkReport(
                    hypothesis_id=hypothesis.id,
                    survived_all=False,
                    attack_results=results,
                    overall_score=0.0,
                    recommendation="kill",
                )

        # All attacks survived
        scores = [r.score for r in results]
        overall = min(scores)
        if overall >= 0.6:
            rec = "proceed"
        elif overall >= 0.3:
            rec = "refine"
        else:
            rec = "kill"

        hypothesis.debunker_notes = {
            r.attack_name: {"score": r.score, "reasoning": r.reasoning}
            for r in results
        }
        # Record the overall score for the epistemic engine's
        # adversarial-survival signal.
        hypothesis.metadata["debunker_overall_score"] = overall

        if rec == "kill":
            # A sub-0.3 survivor is still killed — record the verdict so the
            # hypothesis status is consistent with the recommendation.
            self._record_verdict(hypothesis, killed=True)
            self.total_debunked += 1
            return DebunkReport(
                hypothesis_id=hypothesis.id,
                survived_all=False,
                attack_results=results,
                overall_score=overall,
                recommendation=rec,
            )

        self.total_survived += 1

        return DebunkReport(
            hypothesis_id=hypothesis.id,
            survived_all=True,
            attack_results=results,
            overall_score=overall,
            recommendation=rec,
        )

    @staticmethod
    def _record_verdict(hypothesis: "Hypothesis", killed: bool) -> None:
        """Record a debunk verdict on the hypothesis, respecting transitions."""
        from chimera.models.hypothesis import HypothesisStatus
        if not killed:
            return
        try:
            if hypothesis.status == HypothesisStatus.UNDER_REVIEW:
                hypothesis.transition_to(HypothesisStatus.DEBUNKED)
            elif hypothesis.status == HypothesisStatus.GENERATED:
                hypothesis.transition_to(HypothesisStatus.UNDER_REVIEW)
                hypothesis.transition_to(HypothesisStatus.DEBUNKED)
        except ValueError:
            # Status already terminal — leave as-is; verdict is in the report.
            pass

    # ==================================================================
    # ATTACK 1: Tautology Check
    # ==================================================================

    def tautology_check(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 1: Is the claim trivially true or unfalsifiable?

        A tautology restates the observation as the claim without adding
        inferential value. E.g., "code that doesn't check auth doesn't check auth"
        is technically true but useless as a vulnerability hypothesis.
        """
        claim_lower = h.claim.lower()

        # Check for tautological patterns
        tautology_score = 1.0
        tautology_issues = []

        for pattern in self._TAUTOLOGY_PATTERNS:
            if pattern in claim_lower:
                # The claim might be tautological — check if it adds inferential value
                if claim_lower.count(pattern) > 1 or                    self._is_near_tautology(claim_lower, pattern):
                    tautology_score -= 0.3
                    tautology_issues.append(
                        f"Claim contains tautological pattern: '{pattern}'. "
                        f"The assertion restates the observation without adding causal insight."
                    )

        # Check if the claim is unfalsifiable (no concrete conditions)
        if not h.falsifiers:
            tautology_score -= 0.4
            tautology_issues.append(
                "Hypothesis has no falsifiers. An unfalsifiable claim cannot be "
                "scientifically tested and is therefore useless."
            )

        # Check if claim and observation are too similar
        if h.implementation_model_ref and h.claim:
            obs_words = set(h.implementation_model_ref.lower().split())
            claim_words = set(h.claim.lower().split())
            if obs_words and claim_words:
                overlap = len(obs_words & claim_words) / len(claim_words)
                if overlap > 0.8:
                    tautology_score -= 0.2
                    tautology_issues.append(
                        f"Claim overlaps {overlap:.0%} with the observation. "
                        f"The claim adds minimal inferential value beyond restating what was observed."
                    )

        survived = tautology_score > 0.0
        kill_reason = " ; ".join(tautology_issues) if not survived else ""
        return DebunkResult(
            attack_name="tautology_check",
            survived=survived,
            score=max(0.0, tautology_score),
            reasoning=" ; ".join(tautology_issues) if tautology_issues else "Claim is specific and falsifiable with clear causal reasoning.",
            kill_reason=kill_reason,
            suggested_refinement="Add causal chain from root cause to impact, and include specific falsifiers." if not survived else "",
        )

    def _is_near_tautology(self, claim: str, pattern: str) -> bool:
        """Check if a claim is near-tautological."""
        # If the claim is essentially "X doesn't do Y" and the observation is also about X not doing Y
        impl = ""
        # We can't access h here, so this is a heuristic on the claim text alone
        if "however" in claim or "but" in claim:
            return False  # Has a contrast, not pure tautology
        if "because" in claim or "leads to" in claim or "allows" in claim:
            return False  # Has causal reasoning
        return True

    # ==================================================================
    # ATTACK 2: Assumption Audit
    # ==================================================================

    def assumption_audit(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 2: Does the hypothesis rely on unstated assumptions?

        Many vulnerability hypotheses assume the analyzed code is the ONLY
        defense layer. In reality, middleware, WAFs, API gateways, database
        policies, or framework-level protections may provide defense in depth.
        """
        score = 1.0
        issues = []

        # Check against common unstated assumptions
        claim_lower = h.claim.lower()

        for assumption in self._COMMON_ASSUMPTIONS:
            assumption_lower = assumption.lower()
            # Check if this assumption is implicitly relied upon
            negated = assumption_lower.replace("no ", "")
            if negated in claim_lower or assumption_lower in claim_lower:
                # The hypothesis seems to assume this — check if it's stated as a prerequisite
                is_prerequisite = any(
                    assumption_lower in prereq.lower() or negated in prereq.lower()
                    for prereq in h.prerequisite_conditions
                )
                if not is_prerequisite:
                    score -= 0.15
                    issues.append(
                        f"Hypothesis implicitly assumes '{assumption}' but does not "
                        f"state it as a prerequisite condition."
                    )

        # Check if graph shows middleware protections that the hypothesis ignores
        if graph:
            for entity_id in h.attack_surface:
                node = graph.get_node(entity_id)
                if node:
                    # Check for middleware edges
                    for edge in graph.get_incoming_edges(entity_id):
                        if hasattr(edge, 'edge_type') and edge.edge_type.value == "middleware":
                            score -= 0.25
                            issues.append(
                                f"Entity '{node.name}' has middleware protection via graph edge, "
                                f"but hypothesis does not account for it."
                            )

        # Check if falsifiers cover the assumption space
        if len(h.falsifiers) < 2:
            score -= 0.15
            issues.append(
                f"Only {len(h.falsifiers)} falsifier(s). At least 2-3 needed to cover "
                f"common defense-in-depth scenarios (middleware, framework, DB-level)."
            )

        survived = score > 0.0
        return DebunkResult(
            attack_name="assumption_audit",
            survived=survived,
            score=max(0.0, score),
            reasoning=" ; ".join(issues) if issues else "Key assumptions are explicitly stated as prerequisites.",
            kill_reason=" ; ".join(issues) if not survived else "",
            suggested_refinement=(
                "Add missing assumptions as prerequisite_conditions. "
                "Investigate middleware and framework-level protections."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 3: Counter-Example Search
    # ==================================================================

    def counter_example_search(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 3: Can we find a case where the claim would be false?

        This attack tries to construct counter-examples — specific scenarios
        where the vulnerability would NOT be exploitable despite the claim.
        """
        score = 0.8  # Start with benefit of the doubt
        counter_examples = []

        # Counter-example 1: Framework-level protection
        if h.vulnerability_class and h.vulnerability_class.value in {"idor", "privilege_escalation_horizontal"}:
            counter_examples.append(
                "Framework (Django/Flask) may enforce object-level permissions at the queryset level, "
                "making the endpoint-level check unnecessary."
            )
            score -= 0.2

        # Counter-example 2: Decorator not visible in AST but applied at runtime
        if "decorator" in h.claim.lower() or "no auth" in h.claim.lower():
            counter_examples.append(
                "Authorization may be applied via a base class decorator, mixin, "
                "or metaclass that is not visible in the function-level AST analysis."
            )
            score -= 0.15

        # Counter-example 3: The function may be internal-only.
        # Only genuinely-private helpers (leading underscore, no route, no
        # endpoint tag) earn this discount — business handlers ARE reachable
        # through framework routing the graph may not model.
        if h.attack_surface:
            for eid in h.attack_surface:
                if graph:
                    node = graph.get_node(eid)
                    if node:
                        has_route = node.properties.get("route", "")
                        is_endpoint = (
                            node.properties.get("is_endpoint", False)
                            or node.node_type.value == "endpoint"
                            or "endpoint" in node.semantic_tags
                        )
                        is_private = node.name.startswith("_")
                        if is_private and not has_route and not is_endpoint:
                            counter_examples.append(
                                f"Function '{node.name}' is a private helper not exposed as "
                                f"an HTTP endpoint. It may only be called internally with "
                                f"pre-validated inputs."
                            )
                            score -= 0.15
                            break
                        if not has_route and not is_endpoint and not is_private:
                            counter_examples.append(
                                f"Function '{node.name}' has no visible route binding in the "
                                f"graph; exposure depends on framework wiring."
                            )
                            score -= 0.05
                            break

        # Counter-example 4: Overgeneralization from one code pattern
        if h.evidence and len(h.evidence) == 1:
            counter_examples.append(
                "Hypothesis is based on a single piece of evidence. "
                "The pattern may not generalize — other code paths may have proper checks."
            )
            score -= 0.1

        # Check if hypothesis already has counter-hypotheses
        if h.counter_hypotheses:
            score += 0.1  # Self-awareness bonus

        survived = score > 0.0
        return DebunkResult(
            attack_name="counter_example_search",
            survived=survived,
            score=max(0.0, min(1.0, score)),
            reasoning=(
                "Counter-examples found: " + " ; ".join(counter_examples)
                if counter_examples else "No strong counter-examples found."
            ),
            kill_reason=" ; ".join(counter_examples) if not survived else "",
            suggested_refinement=(
                "Address counter-examples in the claim or add them as falsifiers. "
                "Investigate base class and mixin protection patterns."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 4: Causal Chain Break
    # ==================================================================

    def causal_chain_break(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 4: Does the causal chain actually hold logically?

        Checks each step in the causal chain for logical gaps, unsupported
        inferences, or broken reasoning.
        """
        score = 1.0
        breaks = []

        if not h.causal_chain:
            # No causal chain at all
            score -= 0.4
            breaks.append(
                "No causal chain provided. The claim jumps from observation to "
                "vulnerability without explaining the mechanism."
            )
        elif len(h.causal_chain) < 3:
            score -= 0.2
            breaks.append(
                f"Causal chain has only {len(h.causal_chain)} step(s). "
                f"A complete chain needs: root cause -> mechanism -> impact."
            )
        else:
            # Check each link in the chain
            for i, step in enumerate(h.causal_chain):
                step_lower = step.lower()
                # Check for vague connector words that mask broken logic
                vague_connectors = ["somehow", "might", "could possibly", "perhaps"]
                for vc in vague_connectors:
                    if vc in step_lower:
                        score -= 0.2
                        breaks.append(
                            f"Causal chain step {i+1} uses vague language ('{vc}'), "
                            f"indicating an unsupported inference."
                        )

                # Check for unexplained leaps
                if i > 0:
                    prev = h.causal_chain[i-1].lower()
                    # A leap exists if consecutive steps share no *content*
                    # concepts — stopwords and structural tokens don't count.
                    stopwords = {
                        "the", "a", "an", "in", "on", "of", "to", "and", "or",
                        "is", "are", "be", "by", "for", "with", "from", "at",
                        "this", "that", "it", "its", "can", "not", "no",
                        "root", "cause:", "mechanism:", "impact:", "—", "->", "-",
                        "via", "any", "all",
                    }
                    prev_words = {w.strip(",.;:()") for w in prev.split()} - stopwords
                    curr_words = {w.strip(",.;:()") for w in step_lower.split()} - stopwords
                    shared = prev_words & curr_words
                    if len(shared) == 0 and len(prev_words) > 3 and len(curr_words) > 3:
                        score -= 0.15
                        breaks.append(
                            f"Causal chain step {i+1} shares no concepts with step {i}. "
                            f"This suggests a logical leap."
                        )

        survived = score > 0.0
        return DebunkResult(
            attack_name="causal_chain_break",
            survived=survived,
            score=max(0.0, score),
            reasoning=" ; ".join(breaks) if breaks else "Causal chain is logically sound with clear step-by-step reasoning.",
            kill_reason=" ; ".join(breaks) if not survived else "",
            suggested_refinement=(
                "Strengthen the causal chain by filling logical gaps. "
                "Each step should logically follow from the previous one."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 5: Scope Creep
    # ==================================================================

    def scope_creep(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 5: Is the claim broader than the evidence supports?

        Checks if confidence exceeds what the evidence actually warrants.
        Also checks if the claim overgeneralizes from a specific instance.
        """
        score = 1.0
        issues = []

        # Evidence-count vs confidence check
        evidence_count = len(h.evidence)
        if evidence_count == 0 and h.confidence > 0.5:
            score -= 0.3
            issues.append(
                f"Confidence is {h.confidence:.2f} but no supporting evidence exists. "
                f"Confidence should be proportional to evidence strength."
            )
        elif evidence_count == 1 and h.confidence > 0.7:
            score -= 0.2
            issues.append(
                f"Confidence is {h.confidence:.2f} based on only 1 piece of evidence. "
                f"Single-source claims should have confidence <= 0.7."
            )

        # Check if claim uses universal quantifiers
        claim_lower = h.claim.lower()
        universal_terms = ["all ", "every ", "any ", "always ", "never "]
        for term in universal_terms:
            if term in claim_lower:
                score -= 0.15
                issues.append(
                    f"Claim uses universal quantifier '{term.strip()}' which overgeneralizes. "
                    f"Vulnerability claims should be specific about scope."
                )

        # Check if attack surface is too broad
        if len(h.attack_surface) > 5 and evidence_count < 3:
            score -= 0.15
            issues.append(
                f"Claim affects {len(h.attack_surface)} entities but has only "
                f"{evidence_count} piece(s) of evidence. Scope may be overstated."
            )

        # Differential score vs confidence consistency
        if h.differential_score > 0 and h.confidence > h.differential_score + 0.3:
            score -= 0.1
            issues.append(
                f"Confidence ({h.confidence:.2f}) significantly exceeds differential score "
                f"({h.differential_score:.2f}). The gap suggests overconfidence."
            )

        survived = score > 0.0
        return DebunkResult(
            attack_name="scope_creep",
            survived=survived,
            score=max(0.0, score),
            reasoning=" ; ".join(issues) if issues else "Claim scope is well-bounded by available evidence.",
            kill_reason=" ; ".join(issues) if not survived else "",
            suggested_refinement=(
                "Reduce confidence to match evidence strength. "
                "Narrow the claim scope to what is directly supported."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 6: Confirmation Bias
    # ==================================================================

    def confirmation_bias(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 6: Was the evidence selectively gathered?

        Checks if only confirming evidence was collected, ignoring
        disconfirming signals.
        """
        score = 1.0
        issues = []

        # Check evidence diversity
        if h.evidence:
            evidence_sources = set()
            evidence_types = set()
            for ev in h.evidence:
                evidence_sources.add(ev.source.value if hasattr(ev.source, 'value') else str(ev.source))
                evidence_types.add(ev.evidence_type.value if hasattr(ev.evidence_type, 'value') else str(ev.evidence_type))

            if len(evidence_sources) == 1:
                score -= 0.2
                issues.append(
                    f"All evidence comes from a single source: {evidence_sources}. "
                    f"This suggests selective gathering from one analysis angle."
                )

            if len(evidence_types) == 1:
                score -= 0.15
                issues.append(
                    f"All evidence is of one type: {evidence_types}. "
                    f"Multi-type evidence (AST + graph + differential) is stronger."
                )

        # Check if counter-hypotheses were generated
        if not h.counter_hypotheses:
            score -= 0.15
            issues.append(
                "No counter-hypotheses were generated. A thorough analysis should "
                "consider alternative explanations for the observed differential."
            )

        # Check for confirmation-biased language in the claim
        claim_lower = h.claim.lower()
        bias_count = sum(1 for indicator in self._BIAS_INDICATORS if indicator in claim_lower)
        if bias_count >= 2:
            score -= 0.15
            issues.append(
                f"Claim contains {bias_count} confirmation-bias indicators. "
                f"Neutral, specific language is more credible."
            )

        # Check if falsifiers were actively sought or just defaults
        if h.falsifiers and all("missed during" in f.lower() for f in h.falsifiers):
            score -= 0.1
            issues.append(
                "All falsifiers are about analysis limitations rather than "
                "genuine conditions that would disprove the claim."
            )

        survived = score > 0.0
        return DebunkResult(
            attack_name="confirmation_bias",
            survived=survived,
            score=max(0.0, score),
            reasoning=" ; ".join(issues) if issues else "Evidence gathering appears balanced with diverse sources.",
            kill_reason=" ; ".join(issues) if not survived else "",
            suggested_refinement=(
                "Gather evidence from multiple sources (AST, graph, differential). "
                "Generate counter-hypotheses and use specific, testable falsifiers."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 7: Temporal Validity
    # ==================================================================

    def temporal_validity(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 7: Is this still valid given the current code?

        Checks if the hypothesis references patterns that may have changed,
        or if the code has been modified since analysis.
        """
        score = 1.0
        issues = []

        # Check if target_version is specified
        if not h.target_version:
            score -= 0.1
            issues.append(
                "No target version specified. The hypothesis may not be valid "
                "against the current code version."
            )

        # Check if file_path exists and was recently parsed
        if h.file_path:
            import os
            if not os.path.exists(h.file_path):
                score -= 0.3
                issues.append(
                    f"Referenced file '{h.file_path}' does not exist. "
                    f"The vulnerability may have been moved or removed."
                )

        # Check if the hypothesis is based on patterns that are commonly refactored
        claim_lower = h.claim.lower()
        transient_patterns = ["todo", "fixme", "hack", "temporary", "workaround"]
        for pattern in transient_patterns:
            if pattern in claim_lower:
                score -= 0.2
                issues.append(
                    f"Claim references '{pattern}' pattern, which is likely "
                    f"to be refactored and may not represent a persistent vulnerability."
                )

        survived = score > 0.0
        return DebunkResult(
            attack_name="temporal_validity",
            survived=survived,
            score=max(0.0, score),
            reasoning=" ; ".join(issues) if issues else "Hypothesis references current, versioned code.",
            kill_reason=" ; ".join(issues) if not survived else "",
            suggested_refinement=(
                "Specify the target version. Verify the file still exists."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 8: Semantic Drift
    # ==================================================================

    def semantic_drift(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 8: Have the terms shifted meaning in the claim?

        Checks if key terms (auth, ownership, authorization, etc.) are used
        consistently between the claim, evidence, and causal chain.
        """
        score = 1.0
        issues = []

        # Define key security terms and their expected context
        term_contexts = {
            "authorization": ["role", "permission", "privilege", "access", "policy"],
            "authentication": ["identity", "login", "session", "token", "credential"],
            "ownership": ["belongs", "owner", "creator", "user_id", "created_by"],
            "guard": ["check", "validate", "verify", "precondition", "condition"],
        }

        claim_lower = h.claim.lower()
        for term, expected_context in term_contexts.items():
            if term not in claim_lower:
                continue

            # Check if the claim uses the term in a context consistent with its meaning
            context_matches = sum(1 for ctx in expected_context if ctx in claim_lower)
            if context_matches == 0:
                score -= 0.2
                issues.append(
                    f"Term '{term}' appears in the claim but without expected context "
                    f"words ({expected_context[:3]}). This may indicate semantic drift."
                )

        # Check consistency between claim and intent/implementation references
        if h.intent_model_ref and h.implementation_model_ref:
            intent_words = set(h.intent_model_ref.lower().split())
            impl_words = set(h.implementation_model_ref.lower().split())
            claim_words = set(claim_lower.split())

            # Key terms in claim should appear in either intent or impl refs
            key_terms = ["auth", "ownership", "check", "guard", "role", "permission"]
            for term in key_terms:
                if term in claim_lower:
                    if term not in intent_words and term not in impl_words:
                        score -= 0.1
                        issues.append(
                            f"Term '{term}' in claim but not in intent or implementation references. "
                            f"The claim may be introducing concepts not present in the analysis."
                        )

        survived = score > 0.0
        return DebunkResult(
            attack_name="semantic_drift",
            survived=survived,
            score=max(0.0, score),
            reasoning=" ; ".join(issues) if issues else "Terms are used consistently across claim, evidence, and causal chain.",
            kill_reason=" ; ".join(issues) if not survived else "",
            suggested_refinement=(
                "Ensure key security terms are used with their standard meaning. "
                "Align claim terminology with the underlying analysis."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # ATTACK 9: Attack Surface Mismatch
    # ==================================================================

    def attack_surface_mismatch(
        self, h: Hypothesis, graph: Optional[SemanticGraph] = None, memory: Optional[object] = None
    ) -> DebunkResult:
        """
        Attack 9: Does this actually affect security?

        The final gate. Even if all other attacks pass, this checks whether
        the differential actually leads to an exploitable vulnerability or
        is just a code quality issue.
        """
        score = 0.7  # Start skeptical
        issues = []

        # Must have a vulnerability class to be security-relevant
        if not h.vulnerability_class:
            score -= 0.4
            issues.append(
                "No vulnerability class assigned. Without a clear vulnerability "
                "classification, this may be a code quality issue, not a security issue."
            )
        else:
            # Check if the vulnerability class is in our target set
            target_classes = {"idor", "privilege_escalation_horizontal", "privilege_escalation_vertical",
                             "workflow_bypass", "race_condition", "state_machine_violation",
                             "injection"}
            if h.vulnerability_class.value not in target_classes:
                score -= 0.3
                issues.append(
                    f"Vulnerability class '{h.vulnerability_class.value}' is not in Chimera's target set. "
                    f"This may be outside the scope of business logic vulnerability analysis."
                )

        # Check if attack surface leads to an exploitable endpoint
        if not h.attack_surface:
            score -= 0.2
            issues.append(
                "No attack surface specified. The claim doesn't identify "
                "which endpoints or functions an attacker would target."
            )

        # Check if the causal chain reaches an exploitable impact
        if h.causal_chain:
            last_step = h.causal_chain[-1].lower()
            impact_words = ["impact", "attacker can", "allows", "enables", "leads to"]
            if not any(iw in last_step for iw in impact_words):
                score -= 0.15
                issues.append(
                    "Causal chain does not clearly articulate the exploitable impact. "
                    "The final step should describe what an attacker can achieve."
                )

        # Check severity assessment
        if h.severity:
            sev = h.severity.value if hasattr(h.severity, 'value') else str(h.severity)
            if sev in {"info", "low"}:
                score -= 0.1
                issues.append(
                    f"Severity assessed as '{sev}'. Low-severity findings may not be "
                    f"worth the experimentation budget."
                )

        # Bonus: if the hypothesis has clear prerequisite conditions, it's more credible
        if len(h.prerequisite_conditions) >= 2:
            score += 0.1
        else:
            issues.append(
                "Fewer than 2 prerequisite conditions. Exploitability is unclear."
            )

        survived = score > 0.0
        return DebunkResult(
            attack_name="attack_surface_mismatch",
            survived=survived,
            score=max(0.0, min(1.0, score)),
            reasoning=" ; ".join(issues) if issues else "Differential clearly leads to an exploitable security impact.",
            kill_reason=" ; ".join(issues) if not survived else "",
            suggested_refinement=(
                "Clearly identify the attack surface and exploitable impact. "
                "Ensure the vulnerability class is in the target set."
            ) if score < 0.6 else "",
        )

    # ==================================================================
    # Utilities
    # ==================================================================

    def _record_attack(self, name: str, result: DebunkResult) -> None:
        """Record statistics for this attack."""
        if name not in self.attack_stats:
            self.attack_stats[name] = {"survived": 0, "killed": 0}
        if result.survived:
            self.attack_stats[name]["survived"] += 1
        else:
            self.attack_stats[name]["killed"] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get debunking statistics."""
        total = self.total_debunked + self.total_survived
        return {
            "total_debunked": self.total_debunked,
            "total_survived": self.total_survived,
            "kill_rate": (self.total_debunked / total * 100) if total > 0 else 0,
            "attack_stats": self.attack_stats,
        }
