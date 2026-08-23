"""Chimera Epistemic Engine — Confidence calibration and counter-hypothesis generation.

The EpistemicEngine is the rationality layer of Chimera. It ensures that
hypothesis confidence scores are well-calibrated — not overconfident, not
underconfident — by combining multiple orthogonal signals (evidence strength,
differential magnitude, novelty, prior calibration performance) into a single
precision-weighted score.

It also enforces epistemic humility by generating counter-hypotheses:
alternative explanations that must be explicitly falsified before the primary
hypothesis can be promoted to CONFIRMED.

Calibration model:
    calibrated_confidence = base * w_evidence + differential * w_diff +
                           novelty_penalty * w_novel + prior_bias

Where prior_bias is learned from historical calibration accuracy using an
exponential moving average of (predicted confidence - actual outcome).
"""

from __future__ import annotations

import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from chimera.models.hypothesis import (
    Hypothesis,
    HypothesisStatus,
    VulnerabilityClass,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Calibration record
# ---------------------------------------------------------------------------


@dataclass
class CalibrationRecord:
    """Tracks a single calibration prediction and its actual outcome."""

    hypothesis_id: str
    predicted_confidence: float
    actual_outcome: float  # 1.0 = confirmed, 0.0 = rejected
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: float = 0.0

    def __post_init__(self) -> None:
        self.error = self.predicted_confidence - self.actual_outcome


# ---------------------------------------------------------------------------
# Counter-hypothesis templates per vulnerability class
# ---------------------------------------------------------------------------

_COUNTER_HYPOTHESIS_TEMPLATES: Dict[VulnerabilityClass, List[Dict[str, str]]] = {
    VulnerabilityClass.IDOR: [
        {
            "claim_pattern": (
                "The endpoint at {file_path} does NOT lack ownership validation. "
                "The apparent gap is caused by indirect authorization enforced through "
                "a middleware, decorator, or base class method not visible in the local "
                "function scope."
            ),
            "falsifier_pattern": (
                "A direct HTTP request to the endpoint with another user's resource ID "
                "is rejected with 403 or 404, proving authorization is enforced at runtime."
            ),
        },
        {
            "claim_pattern": (
                "The access control at {file_path} is intentionally permissive for this "
                "endpoint as part of a public/shared resource design, not a vulnerability. "
                "The IntentModel mischaracterized the access policy."
            ),
            "falsifier_pattern": (
                "Documentation, comments, or test fixtures in {file_path} confirm the "
                "resource is supposed to be access-controlled, contradicting the "
                "public-resource interpretation."
            ),
        },
        {
            "claim_pattern": (
                "The object reference in {file_path} is not user-controllable at runtime. "
                "Although the AST shows no ownership check, the value may be derived "
                "from a session-scoped lookup rather than a user-supplied parameter."
            ),
            "falsifier_pattern": (
                "A crafted HTTP request supplying a different object ID in the query "
                "or body parameter successfully returns the other user's resource."
            ),
        },
    ],
    VulnerabilityClass.PRIVILEGE_ESCALATION_HORIZONTAL: [
        {
            "claim_pattern": (
                "The role check in {file_path} is not missing; it is performed in "
                "a separate authorization service or API gateway that intercepts the "
                "request before it reaches this handler."
            ),
            "falsifier_pattern": (
                "Direct access to the endpoint bypassing the gateway returns data "
                "belonging to another user in the same privilege tier."
            ),
        },
        {
            "claim_pattern": (
                "The data returned by {file_path} is legitimately accessible to all "
                "users in the same role tier due to collaborative access requirements."
            ),
            "falsifier_pattern": (
                "The data exposed includes personally identifiable information or "
                "financial records that violate the application's own access policy."
            ),
        },
    ],
    VulnerabilityClass.PRIVILEGE_ESCALATION_VERTICAL: [
        {
            "claim_pattern": (
                "The endpoint in {file_path} includes a role check that is conditional "
                "on a feature flag or configuration. The flag is enabled in production, "
                "so the check IS enforced at runtime despite being unreachable in the "
                "analyzed code path."
            ),
            "falsifier_pattern": (
                "A request from a low-privilege user to the endpoint succeeds in "
                "performing a high-privilege action, confirming the check is inactive."
            ),
        },
        {
            "claim_pattern": (
                "The endpoint in {file_path} is only callable by internal services "
                "with service-to-service authentication. The lack of a user-level role "
                "check is intentional because the network boundary provides the control."
            ),
            "falsifier_pattern": (
                "A direct HTTP request from an unauthenticated external client to the "
                "endpoint succeeds, proving no network-level restriction exists."
            ),
        },
    ],
    VulnerabilityClass.WORKFLOW_BYPASS: [
        {
            "claim_pattern": (
                "The workflow step in {file_path} is not skippable. The code path that "
                "appears to skip it is actually a fallback or error-handling branch that "
                "is never reached under normal operation."
            ),
            "falsifier_pattern": (
                "An HTTP request that deliberately omits the required prior step succeeds, "
                "demonstrating the step can be bypassed."
            ),
        },
        {
            "claim_pattern": (
                "The state transition in {file_path} is guarded by a frontend-only "
                "check, but the backend correctly validates the state machine for all "
                "API callers, making the frontend gap cosmetic only."
            ),
            "falsifier_pattern": (
                "A direct API call to the transition endpoint from the wrong state "
                "succeeds, showing the backend does not enforce the state machine."
            ),
        },
    ],
    VulnerabilityClass.RACE_CONDITION: [
        {
            "claim_pattern": (
                "The race condition in {file_path} is theoretical only. The operation "
                "is protected by database-level locking (SELECT FOR UPDATE, optimistic "
                "locking, or serializable isolation) that prevents concurrent exploitation."
            ),
            "falsifier_pattern": (
                "Concurrent HTTP requests demonstrate the race condition is exploitable: "
                "two requests both succeed in performing the action when only one should."
            ),
        },
        {
            "claim_pattern": (
                "The concurrency window in {file_path} is too small for practical "
                "exploitation. Network latency and request processing time make it "
                "infeasible to win the race without local network access."
            ),
            "falsifier_pattern": (
                "Automated concurrent requests from a single external client reliably "
                "trigger the race condition within 10 attempts."
            ),
        },
    ],
    VulnerabilityClass.STATE_MACHINE_VIOLATION: [
        {
            "claim_pattern": (
                "The state machine in {file_path} is not violated. The apparently "
                "invalid transition is actually a valid recovery or administrative path "
                "that was not captured in the IntentModel."
            ),
            "falsifier_pattern": (
                "An API request performing the invalid transition from the wrong state "
                "succeeds, and the resulting state is inconsistent with business rules."
            ),
        },
        {
            "claim_pattern": (
                "The state guard in {file_path} is enforced through a database "
                "constraint (CHECK, trigger, or enum column) that will reject the "
                "invalid transition at the persistence layer."
            ),
            "falsifier_pattern": (
                "An API request that attempts the invalid transition succeeds and "
                "persists the invalid state to the database."
            ),
        },
    ],
    VulnerabilityClass.INJECTION: [
        {
            "claim_pattern": (
                "The string-built query in {file_path} is not exploitable. The "
                "interpolated values are validated or escaped before reaching this "
                "function, so the grammar boundary is never crossed by hostile input."
            ),
            "falsifier_pattern": (
                "A request supplying a quote/escape payload in the interpolated "
                "parameter alters the executed statement (error-based or union-based "
                "response confirms grammar crossover)."
            ),
        },
        {
            "claim_pattern": (
                "The statement in {file_path} is never executed — it is built for "
                "logging or display only, so the constructed SQL is inert."
            ),
            "falsifier_pattern": (
                "A runtime trace shows the constructed string reaching an "
                "execute()/query() call on a live connection."
            ),
        },
    ],
}

# Fallback templates when the vulnerability class is unknown or not in the map
_FALLBACK_TEMPLATES: List[Dict[str, str]] = [
    {
        "claim_pattern": (
            "The observed behavior at {file_path} is not a vulnerability but a "
            "deliberate design choice. The IntentModel's expectation does not reflect "
            "the actual security requirements of the system."
        ),
        "falsifier_pattern": (
            "An experiment demonstrates the behavior can be exploited to violate "
            "a stated security requirement or cause unauthorized access."
        ),
    },
    {
        "claim_pattern": (
            "The vulnerability in {file_path} is mitigated by a runtime control "
            "not visible in static analysis — such as a WAF rule, CSP header, "
            "or infrastructure-level policy."
        ),
        "falsifier_pattern": (
            "A direct request to {file_path} that triggers the vulnerability "
            "succeeds, showing no runtime mitigation is in place."
        ),
    },
    {
        "claim_pattern": (
            "The code path in {file_path} that exhibits the vulnerability is "
            "unreachable. Dead code analysis would show this branch is never "
            "executed in any deployed configuration."
        ),
        "falsifier_pattern": (
            "A runtime trace or coverage report shows the vulnerable code path "
            "is executed during normal application operation."
        ),
    },
]


# ---------------------------------------------------------------------------
# EpistemicEngine
# ---------------------------------------------------------------------------


class EpistemicEngine:
    """Calibrates hypothesis confidence and generates counter-hypotheses.

    The engine maintains an internal calibration model that learns from past
    prediction errors. Over time it corrects for systematic over- or
    under-confidence, producing better-calibrated scores.

    Attributes:
        evidence_weight: How strongly evidence count/strength affects calibration.
        differential_weight: How strongly the differential score affects calibration.
        novelty_weight: Penalty weight for novel (unseen-in-memory) hypotheses.
        learning_rate: EMA decay factor for calibration bias updates.
        calibration_records: History of past calibration predictions vs. outcomes.
        calibration_bias: Running estimate of systematic prediction error.
    """

    def __init__(
        self,
        evidence_weight: float = 0.35,
        differential_weight: float = 0.25,
        novelty_weight: float = 0.10,
        adversarial_weight: float = 0.30,
        learning_rate: float = 0.15,
        min_confidence: float = 0.05,
        max_confidence: float = 0.95,
    ) -> None:
        """Initialize the EpistemicEngine.

        Args:
            evidence_weight: Weight for the evidence strength signal (0-1).
            differential_weight: Weight for the differential score signal (0-1).
            novelty_weight: Weight for the novelty penalty (0-1).
            adversarial_weight: Weight for the Debunker-survival signal (0-1).
                Surviving the hostile 9-vector review is genuine Bayesian
                evidence; hypotheses reviewed before calibration score higher
                than unreviewed ones.
            learning_rate: EMA alpha for updating calibration bias (0-1).
            min_confidence: Floor for calibrated confidence output.
            max_confidence: Ceiling for calibrated confidence output.

        Raises:
            ValueError: If weights are negative, learning rate is out of range,
                or min/max confidence are inconsistent.
        """
        if evidence_weight < 0 or differential_weight < 0 or novelty_weight < 0 or adversarial_weight < 0:
            raise ValueError("All signal weights must be non-negative.")
        if not (0.0 < learning_rate <= 1.0):
            raise ValueError("learning_rate must be in (0.0, 1.0].")
        if min_confidence < 0.0 or max_confidence > 1.0 or min_confidence >= max_confidence:
            raise ValueError(
                f"Invalid confidence bounds: [{min_confidence}, {max_confidence}]. "
                f"Must satisfy 0 <= min < max <= 1."
            )

        self.evidence_weight: float = evidence_weight
        self.differential_weight: float = differential_weight
        self.novelty_weight: float = novelty_weight
        self.adversarial_weight: float = adversarial_weight
        self.learning_rate: float = learning_rate
        self.min_confidence: float = min_confidence
        self.max_confidence: float = max_confidence

        self.calibration_records: List[CalibrationRecord] = []
        self.calibration_bias: float = 0.0

        logger.debug(
            "EpistemicEngine initialized: evidence=%.2f, differential=%.2f, "
            "novelty=%.2f, lr=%.2f",
            evidence_weight,
            differential_weight,
            novelty_weight,
            learning_rate,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calibrate(self, hypothesis: Hypothesis) -> float:
        """Calibrate the confidence of a hypothesis and return the score.

        The calibration combines three signals:

        1. **Evidence strength** — the weighted average confidence of attached
           evidence pieces, boosted by the number of pieces (diminishing returns
           via log).
        2. **Differential score** — the magnitude of the semantic differential
           that spawned the hypothesis. Higher differentials indicate stronger
           contradictions.
        3. **Novelty penalty** — novel hypotheses (not found in memory) receive
           a small confidence penalty because they lack historical validation.

        A learned calibration bias is subtracted to correct for systematic
        over- or under-confidence observed in past predictions.

        Args:
            hypothesis: The hypothesis to calibrate.

        Returns:
            A calibrated confidence score in [min_confidence, max_confidence].

        Raises:
            TypeError: If hypothesis is not a Hypothesis instance.
        """
        if not isinstance(hypothesis, Hypothesis):
            raise TypeError(
                f"Expected Hypothesis, got {type(hypothesis).__name__}"
            )

        # --- Signal 1: Evidence strength ---
        evidence_signal = self._compute_evidence_signal(hypothesis)

        # --- Signal 2: Differential score ---
        differential_signal = max(0.0, min(1.0, hypothesis.differential_score))

        # --- Signal 3: Novelty penalty ---
        novelty_penalty = 0.1 if hypothesis.is_novel else 0.0

        # --- Signal 4: Adversarial survival ---
        # Surviving the Debunker's hostile review is real Bayesian evidence.
        # If the hypothesis was reviewed, its overall debunk score feeds in;
        # unreviewed hypotheses get 0 (neutral, keeps them conservative).
        adversarial_signal = self._compute_adversarial_signal(hypothesis)

        # --- Weighted combination over ACTIVE signal families ---
        # Weights renormalize across the signals actually present so that
        # confidence is a proper weighted mean — not a sum that is
        # mathematically capped below 1.0 when a signal family is silent.
        weighted_sum = evidence_signal * self.evidence_weight
        weight_total = self.evidence_weight

        weighted_sum += differential_signal * self.differential_weight
        weight_total += self.differential_weight

        if adversarial_signal is not None:
            weighted_sum += adversarial_signal * self.adversarial_weight
            weight_total += self.adversarial_weight

        raw_confidence = (weighted_sum / weight_total) if weight_total > 0 else 0.0
        raw_confidence -= novelty_penalty * self.novelty_weight

        # --- Apply learned calibration bias ---
        adjusted = raw_confidence - self.calibration_bias

        # --- Clamp to valid range ---
        calibrated = max(self.min_confidence, min(self.max_confidence, adjusted))

        logger.debug(
            "Calibrated %s: evidence=%.3f, differential=%.3f, novelty=%.3f, "
            "adversarial=%s, bias=%.3f => %.3f",
            hypothesis.id,
            evidence_signal,
            differential_signal,
            novelty_penalty,
            f"{adversarial_signal:.3f}" if adversarial_signal is not None else "n/a",
            self.calibration_bias,
            calibrated,
        )

        return calibrated

    def generate_counter_hypotheses(self, hypothesis: Hypothesis) -> List[Hypothesis]:
        """Generate alternative explanations for the given hypothesis.

        Counter-hypotheses represent plausible non-vulnerability explanations
        for the observed behavior. Each counter-hypothesis includes a
        specific falsifier — an observation that, if made, would disprove
        the counter-hypothesis and thereby strengthen the original.

        Templates are selected based on the hypothesis's vulnerability class.
        If no class is set or no templates exist for the class, fallback
        templates are used.

        Args:
            hypothesis: The primary hypothesis to generate alternatives for.

        Returns:
            A list of counter-hypothesis Hypothesis objects (typically 2-3).
            Each has status GENERATED and lower initial confidence than the
            original.

        Raises:
            TypeError: If hypothesis is not a Hypothesis instance.
        """
        if not isinstance(hypothesis, Hypothesis):
            raise TypeError(
                f"Expected Hypothesis, got {type(hypothesis).__name__}"
            )

        templates = self._select_templates(hypothesis)
        counters: List[Hypothesis] = []
        file_ctx = hypothesis.file_path or "the target endpoint"

        for template in templates:
            claim = template["claim_pattern"].format(file_path=file_ctx)
            falsifier = template["falsifier_pattern"].format(file_path=file_ctx)

            counter = Hypothesis(
                claim=claim,
                confidence=0.3 + hypothesis.differential_score * 0.2,
                file_path=hypothesis.file_path,
                vulnerability_class=hypothesis.vulnerability_class,
                differential_score=hypothesis.differential_score * 0.6,
                intent_model_ref=hypothesis.intent_model_ref,
                implementation_model_ref=hypothesis.implementation_model_ref,
                is_novel=hypothesis.is_novel,
                severity=hypothesis.severity,
                status=HypothesisStatus.GENERATED,
            )
            counter.add_falsifier(falsifier)
            counter.metadata["is_counter_hypothesis"] = True
            counter.metadata["parent_hypothesis_id"] = hypothesis.id
            counters.append(counter)

        logger.info(
            "Generated %d counter-hypotheses for %s",
            len(counters),
            hypothesis.id,
        )

        return counters

    def record_outcome(
        self,
        hypothesis_id: str,
        predicted_confidence: float,
        was_confirmed: bool,
    ) -> None:
        """Record the actual outcome of a hypothesis to improve future calibration.

        This feeds the learning loop: after a hypothesis is confirmed or
        rejected, the engine compares its predicted confidence against the
        actual outcome (1.0 or 0.0) and updates its internal bias via
        exponential moving average.

        Args:
            hypothesis_id: The ID of the hypothesis that was resolved.
            predicted_confidence: The confidence the engine predicted earlier.
            was_confirmed: Whether the hypothesis was confirmed (True) or
                rejected (False).

        Raises:
            ValueError: If predicted_confidence is not in [0, 1].
        """
        if not (0.0 <= predicted_confidence <= 1.0):
            raise ValueError(
                f"predicted_confidence must be in [0, 1], got {predicted_confidence}"
            )

        actual = 1.0 if was_confirmed else 0.0
        record = CalibrationRecord(
            hypothesis_id=hypothesis_id,
            predicted_confidence=predicted_confidence,
            actual_outcome=actual,
        )

        self.calibration_records.append(record)

        # Update bias via EMA: bias = (1 - alpha) * bias + alpha * error
        # Positive error = overconfident, negative = underconfident
        self.calibration_bias = (
            (1.0 - self.learning_rate) * self.calibration_bias
            + self.learning_rate * record.error
        )

        logger.debug(
            "Calibration update: hyp=%s, predicted=%.3f, actual=%.1f, "
            "error=%.3f, new_bias=%.3f",
            hypothesis_id,
            predicted_confidence,
            actual,
            record.error,
            self.calibration_bias,
        )

    def get_calibration_accuracy(self) -> Dict[str, float]:
        """Compute calibration accuracy metrics over all recorded outcomes.

        Returns:
            A dictionary containing:
            - ``sample_size``: Number of calibration records.
            - ``mean_absolute_error``: Average |predicted - actual| (lower is better).
            - ``mean_signed_error``: Average (predicted - actual). Positive means
              systematically overconfident.
            - ``current_bias``: The EMA calibration bias being applied.
            - ``brier_score``: Mean squared error, the standard calibration metric.
        """
        n = len(self.calibration_records)
        if n == 0:
            return {
                "sample_size": 0,
                "mean_absolute_error": 0.0,
                "mean_signed_error": 0.0,
                "current_bias": self.calibration_bias,
                "brier_score": 0.0,
            }

        abs_errors = [abs(r.error) for r in self.calibration_records]
        signed_errors = [r.error for r in self.calibration_records]
        squared_errors = [r.error ** 2 for r in self.calibration_records]

        return {
            "sample_size": n,
            "mean_absolute_error": sum(abs_errors) / n,
            "mean_signed_error": sum(signed_errors) / n,
            "current_bias": self.calibration_bias,
            "brier_score": sum(squared_errors) / n,
        }

    def reset_calibration(self) -> None:
        """Clear all calibration history and reset the bias to zero.

        Useful when switching target applications or after a major
        configuration change.
        """
        self.calibration_records.clear()
        self.calibration_bias = 0.0
        logger.info("Calibration history cleared and bias reset.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_adversarial_signal(self, hypothesis: Hypothesis) -> Optional[float]:
        """
        The Debunker-survival signal.

        Reads ``hypothesis.metadata["debunker_overall_score"]`` (set by the
        orchestrator after the debunking phase). Returns ``None`` when the
        hypothesis has not been through hostile review — in which case the
        signal family simply does not participate in the weighted mean.
        """
        if not isinstance(hypothesis.metadata, dict):
            return None
        score = hypothesis.metadata.get("debunker_overall_score")
        if isinstance(score, (int, float)):
            return max(0.0, min(1.0, float(score)))
        return None

    def _compute_evidence_signal(self, hypothesis: Hypothesis) -> float:
        """Compute the evidence strength signal for a hypothesis.

        Combines two sub-signals:
        1. Average confidence of attached evidence pieces.
        2. A log-dimishing boost for the *number* of evidence pieces.

        If no evidence is attached, returns 0.0.

        Args:
            hypothesis: The hypothesis whose evidence to evaluate.

        Returns:
            A float in [0.0, 1.0] representing evidence strength.
        """
        evidence_list = hypothesis.evidence
        if not evidence_list:
            return 0.0

        # Average confidence of all evidence pieces
        avg_confidence = sum(e.confidence for e in evidence_list) / len(evidence_list)

        # Log-dimishing count boost: log(1 + n) / log(1 + max_reasonable)
        # max_reasonable = 20 evidence pieces gives full boost
        max_reasonable = 20.0
        count_boost = math.log(1.0 + len(evidence_list)) / math.log(
            1.0 + max_reasonable
        )

        # Weighted combination: 70% average confidence, 30% count boost
        signal = avg_confidence * 0.7 + count_boost * 0.3
        return min(signal, 1.0)

    def _select_templates(
        self, hypothesis: Hypothesis
    ) -> List[Dict[str, str]]:
        """Select counter-hypothesis templates for the given hypothesis.

        Uses the vulnerability class to pick the most relevant templates.
        Falls back to generic templates if the class is unknown or untemplated.

        Args:
            hypothesis: The hypothesis to select templates for.

        Returns:
            A list of template dictionaries, each with 'claim_pattern' and
            'falsifier_pattern' keys.
        """
        vuln_class = hypothesis.vulnerability_class
        if vuln_class is not None and vuln_class in _COUNTER_HYPOTHESIS_TEMPLATES:
            return _COUNTER_HYPOTHESIS_TEMPLATES[vuln_class]
        return _FALLBACK_TEMPLATES
