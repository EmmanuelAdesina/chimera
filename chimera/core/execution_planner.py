"""Chimera Execution Planner — Hypothesis prioritization and experiment generation.

The ExecutionPlanner decides *which* hypotheses to validate and *how* to
test them. It ranks active hypotheses by a composite score

    priority = confidence * severity_weight * differential_score * recency_boost

then generates concrete experiment plans — HTTP requests with expected
and falsifying outcomes — for the top-ranked hypotheses within the
available experiment budget.

The planner learns from experiment outcomes: if high-priority hypotheses
keep being rejected, it adjusts its severity weights to avoid wasting
budget on false leads. Conversely, if low-priority hypotheses are confirmed,
it raises the weight of signals that predicted them.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from chimera.models.hypothesis import (
    Hypothesis,
    HypothesisStatus,
    Severity,
    VulnerabilityClass,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity numeric weights
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

# ---------------------------------------------------------------------------
# Experiment template builders per vulnerability class
# ---------------------------------------------------------------------------

# Each function takes a hypothesis and returns an experiment plan dict.


def _resolve_target_url(hypothesis: Hypothesis) -> str:
    """
    Resolve the experiment target URL for a hypothesis.

    Priority: explicit route metadata (extracted from routing decorators) →
    attack surface only when it already looks like a path → an honest
    static-analysis marker that no live URL could be derived.
    """
    route = hypothesis.metadata.get("route") if isinstance(hypothesis.metadata, dict) else None
    if route:
        return str(route)
    for surface in hypothesis.attack_surface or []:
        surface_str = str(surface)
        if surface_str.startswith("/"):
            return surface_str
    return "/static-analysis-only/no-route-derived"


def _build_idor_plan(hypothesis: Hypothesis) -> Dict[str, Any]:
    """Generate an IDOR experiment plan."""
    target_url = _resolve_target_url(hypothesis)

    return {
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
        "target_url": target_url,
        "method": "GET",
        "headers": {
            "Authorization": "Bearer <attacker_session_token>",
            "Content-Type": "application/json",
            "X-Chimera-Experiment": "idor-test",
        },
        "body": None,
        "expected_outcome": {
            "description": "The server returns the victim's resource (200 OK with data belonging to another user)",
            "match_criteria": {
                "status_code": 200,
                "response_contains": "user_id",
            },
        },
        "falsifying_outcome": {
            "description": "The server returns 403 Forbidden, 404 Not Found, or the requester's own resource only",
            "match_criteria": {
                "status_codes": [403, 404],
                "or_response_missing": "user_id",
            },
        },
        "metadata": {
            "resource_id_param": "id",
            "requires_auth": True,
            "requires_two_users": True,
        },
    }


def _build_horizontal_escalation_plan(hypothesis: Hypothesis) -> Dict[str, Any]:
    """Generate a horizontal privilege escalation experiment plan."""
    target_url = _resolve_target_url(hypothesis)

    return {
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
        "target_url": target_url,
        "method": "GET",
        "headers": {
            "Authorization": "Bearer <user_a_token>",
            "Content-Type": "application/json",
            "X-Chimera-Experiment": "hpe-test",
        },
        "body": None,
        "expected_outcome": {
            "description": "User A can access data or perform actions belonging to User B at the same privilege level",
            "match_criteria": {
                "status_code": 200,
                "response_contains_any": ["email", "phone", "account_number", "ssn"],
            },
        },
        "falsifying_outcome": {
            "description": "The request is rejected or only returns User A's own data",
            "match_criteria": {
                "status_codes": [403, 404],
            },
        },
        "metadata": {
            "requires_same_role_users": True,
            "requires_auth": True,
        },
    }


def _build_vertical_escalation_plan(hypothesis: Hypothesis) -> Dict[str, Any]:
    """Generate a vertical privilege escalation experiment plan."""
    target_url = _resolve_target_url(hypothesis)

    return {
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
        "target_url": target_url,
        "method": "POST",
        "headers": {
            "Authorization": "Bearer <low_privilege_token>",
            "Content-Type": "application/json",
            "X-Chimera-Experiment": "vpe-test",
        },
        "body": {
            "action": "admin_operation",
        },
        "expected_outcome": {
            "description": "The low-privilege user successfully performs a high-privilege action",
            "match_criteria": {
                "status_code": 200,
            },
        },
        "falsifying_outcome": {
            "description": "The request is rejected with 403 or the action is silently ignored",
            "match_criteria": {
                "status_codes": [401, 403],
            },
        },
        "metadata": {
            "requires_low_priv_user": True,
            "requires_auth": True,
        },
    }


def _build_workflow_bypass_plan(hypothesis: Hypothesis) -> Dict[str, Any]:
    """Generate a workflow bypass experiment plan."""
    target_url = _resolve_target_url(hypothesis)

    return {
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
        "target_url": target_url,
        "method": "POST",
        "headers": {
            "Authorization": "Bearer <user_token>",
            "Content-Type": "application/json",
            "X-Chimera-Experiment": "workflow-bypass-test",
        },
        "body": {
            "step": "skip_to_final",
        },
        "expected_outcome": {
            "description": "The server allows skipping a required workflow step and advances to the final state",
            "match_criteria": {
                "status_code": 200,
                "response_contains": "success",
            },
        },
        "falsifying_outcome": {
            "description": "The server rejects the request or returns a state validation error",
            "match_criteria": {
                "status_codes": [400, 403, 409, 422],
            },
        },
        "metadata": {
            "requires_auth": True,
            "requires_workflow_in_progress": True,
        },
    }


def _build_race_condition_plan(hypothesis: Hypothesis) -> Dict[str, Any]:
    """Generate a race condition experiment plan."""
    target_url = _resolve_target_url(hypothesis)

    return {
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
        "target_url": target_url,
        "method": "POST",
        "headers": {
            "Authorization": "Bearer <user_token>",
            "Content-Type": "application/json",
            "X-Chimera-Experiment": "race-condition-test",
        },
        "body": {
            "action": "redeem",
            "amount": 1,
        },
        "expected_outcome": {
            "description": "Concurrent requests both succeed, allowing double-spending or duplicate action",
            "match_criteria": {
                "concurrent_success": True,
                "min_successful_requests": 2,
            },
        },
        "falsifying_outcome": {
            "description": "Only one request succeeds; others receive 409 Conflict or are correctly serialized",
            "match_criteria": {
                "max_successful_requests": 1,
                "or_status_codes": [409, 422],
            },
        },
        "metadata": {
            "requires_auth": True,
            "concurrency": 5,
            "timing_sensitive": True,
        },
    }


def _build_state_machine_violation_plan(hypothesis: Hypothesis) -> Dict[str, Any]:
    """Generate a state machine violation experiment plan."""
    target_url = _resolve_target_url(hypothesis)

    return {
        "hypothesis_id": hypothesis.id,
        "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
        "target_url": target_url,
        "method": "POST",
        "headers": {
            "Authorization": "Bearer <user_token>",
            "Content-Type": "application/json",
            "X-Chimera-Experiment": "state-machine-test",
        },
        "body": {
            "transition": "force_invalid",
        },
        "expected_outcome": {
            "description": "The server allows an invalid state transition, resulting in an inconsistent state",
            "match_criteria": {
                "status_code": 200,
            },
        },
        "falsifying_outcome": {
            "description": "The server rejects the invalid transition with a validation error",
            "match_criteria": {
                "status_codes": [400, 409, 422],
            },
        },
        "metadata": {
            "requires_auth": True,
            "requires_specific_state": True,
        },
    }


# Dispatch table: vuln class -> plan builder
_PLAN_BUILDERS: Dict[VulnerabilityClass, Any] = {
    VulnerabilityClass.IDOR: _build_idor_plan,
    VulnerabilityClass.PRIVILEGE_ESCALATION_HORIZONTAL: _build_horizontal_escalation_plan,
    VulnerabilityClass.PRIVILEGE_ESCALATION_VERTICAL: _build_vertical_escalation_plan,
    VulnerabilityClass.WORKFLOW_BYPASS: _build_workflow_bypass_plan,
    VulnerabilityClass.RACE_CONDITION: _build_race_condition_plan,
    VulnerabilityClass.STATE_MACHINE_VIOLATION: _build_state_machine_violation_plan,
}


# ---------------------------------------------------------------------------
# Prioritization feedback record
# ---------------------------------------------------------------------------


@dataclass
class PrioritizationRecord:
    """Records a single prioritization decision and its outcome for learning."""

    hypothesis_id: str
    priority_rank: int
    priority_score: float
    was_confirmed: bool
    timestamp: datetime = field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# ExecutionPlanner
# ---------------------------------------------------------------------------


class ExecutionPlanner:
    """Prioritizes hypotheses for validation and generates experiment plans.

    The planner uses a composite scoring function to rank hypotheses,
    then generates concrete HTTP experiment plans for the top candidates
    within the provided budget. It learns from past experiment outcomes
    to improve future prioritization.

    Attributes:
        severity_weights: Current learned severity weights (mutable copy).
        learning_rate: How aggressively to adjust weights from feedback.
        recency_half_life_hours: Time window for recency boost (hours).
        records: History of prioritization decisions and outcomes.
    """

    def __init__(
        self,
        base_url: str = "",
        severity_weights: Optional[Dict[Severity, float]] = None,
        learning_rate: float = 0.1,
        recency_half_life_hours: float = 24.0,
        default_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Initialize the ExecutionPlanner.

        Args:
            base_url: Base URL prefix for all generated experiment targets.
            severity_weights: Starting severity weights. If None, uses defaults.
            learning_rate: Rate at which severity weights adapt from feedback.
            recency_half_life_hours: Half-life for recency boost in hours.
                Hypotheses created more recently get a small priority boost.
            default_headers: Default HTTP headers merged into every experiment plan.

        Raises:
            ValueError: If learning_rate is out of (0, 1] or severity_weights
                are invalid.
        """
        if not (0.0 < learning_rate <= 1.0):
            raise ValueError("learning_rate must be in (0.0, 1.0].")
        if recency_half_life_hours <= 0:
            raise ValueError("recency_half_life_hours must be positive.")

        self.base_url: str = base_url.rstrip("/")
        self.severity_weights: Dict[Severity, float] = (
            dict(severity_weights) if severity_weights else dict(_SEVERITY_WEIGHTS)
        )
        self._validate_severity_weights()
        self.learning_rate: float = learning_rate
        self.recency_half_life_hours: float = recency_half_life_hours
        self.default_headers: Dict[str, str] = default_headers or {}
        self.records: List[PrioritizationRecord] = []

        logger.debug(
            "ExecutionPlanner initialized: base_url=%s, lr=%.2f, recency_hl=%.1fh",
            self.base_url,
            learning_rate,
            recency_half_life_hours,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def prioritize(
        self, hypotheses: List[Hypothesis], budget: int
    ) -> List[Dict[str, Any]]:
        """Rank hypotheses and generate experiment plans for the top candidates.

        Steps:
        1. Filter to active hypotheses (UNDER_REVIEW, EXPERIMENT_SCHEDULED,
           or EXPERIMENT_RUNNING).
        2. Score each using the composite priority function.
        3. Sort by score descending.
        4. Take the top ``budget`` hypotheses.
        5. Generate an experiment plan for each.

        Args:
            hypotheses: All candidate hypotheses (any status).
            budget: Maximum number of experiment plans to return.

        Returns:
            An ordered list of experiment plan dicts. Each contains:
            - ``hypothesis_id``: The hypothesis being tested.
            - ``target_url``: Full URL to send the request to.
            - ``method``: HTTP method (GET, POST, etc.).
            - ``headers``: HTTP headers dict.
            - ``body``: Request body (dict or None for GET).
            - ``expected_outcome``: Dict describing what a confirming result looks like.
            - ``falsifying_outcome``: Dict describing what would disprove the hypothesis.
            - ``priority_score``: The computed priority score for traceability.

        Raises:
            TypeError: If hypotheses is not a list or budget is not an int.
            ValueError: If budget is negative.
        """
        if not isinstance(hypotheses, list):
            raise TypeError(
                f"Expected list of Hypothesis, got {type(hypotheses).__name__}"
            )
        if not isinstance(budget, int):
            raise TypeError(f"Expected int for budget, got {type(budget).__name__}")
        if budget < 0:
            raise ValueError(f"budget must be non-negative, got {budget}")

        # Step 1: Filter to active hypotheses
        active_statuses = {
            HypothesisStatus.UNDER_REVIEW,
            HypothesisStatus.EXPERIMENT_SCHEDULED,
            HypothesisStatus.EXPERIMENT_RUNNING,
        }
        active = [
            h
            for h in hypotheses
            if isinstance(h, Hypothesis) and h.status in active_statuses
        ]

        if not active:
            logger.info("No active hypotheses to prioritize.")
            return []

        # Step 2: Score each hypothesis
        scored: List[Tuple[float, Hypothesis]] = []
        for h in active:
            score = self._compute_priority_score(h)
            scored.append((score, h))

        # Step 3: Sort by score descending (stable sort preserves insertion order)
        scored.sort(key=lambda pair: pair[0], reverse=True)

        # Step 4: Take top budget
        candidates = scored[:budget]

        # Step 5: Generate experiment plans
        plans: List[Dict[str, Any]] = []
        for rank, (score, hypothesis) in enumerate(candidates, start=1):
            plan = self._generate_plan(hypothesis, score, rank)
            plans.append(plan)

            logger.info(
                "Plan #%d: hyp=%s score=%.3f url=%s method=%s",
                rank,
                hypothesis.id,
                score,
                plan["target_url"],
                plan["method"],
            )

        return plans

    def record_outcome(
        self,
        hypothesis_id: str,
        priority_rank: int,
        priority_score: float,
        was_confirmed: bool,
    ) -> None:
        """Record the outcome of an experiment for learning.

        When a hypothesis is confirmed or rejected, the planner uses this
        feedback to adjust its severity weights. Confirmed hypotheses that
        were ranked low increase their severity class weight. Rejected
        hypotheses that were ranked high decrease it.

        Args:
            hypothesis_id: ID of the resolved hypothesis.
            priority_rank: The rank (1-based) this hypothesis had when planned.
            priority_score: The priority score at planning time.
            was_confirmed: True if the hypothesis was confirmed.

        Raises:
            ValueError: If priority_rank is not positive.
        """
        if priority_rank < 1:
            raise ValueError("priority_rank must be >= 1.")

        record = PrioritizationRecord(
            hypothesis_id=hypothesis_id,
            priority_rank=priority_rank,
            priority_score=priority_score,
            was_confirmed=was_confirmed,
        )
        self.records.append(record)

        # Adjust severity weights based on outcome
        # We need to find the hypothesis's severity from the last planned score.
        # The adjustment is: if confirmed but ranked low, boost severity;
        # if rejected but ranked high, penalize severity.
        # Since we don't store the full hypothesis here, we apply a generic
        # adjustment based on rank vs. expected outcome.
        self._adjust_weights_from_outcome(record)

        logger.debug(
            "Recorded outcome: hyp=%s rank=%d score=%.3f confirmed=%s",
            hypothesis_id,
            priority_rank,
            priority_score,
            was_confirmed,
        )

    def record_outcome_with_severity(
        self,
        hypothesis_id: str,
        priority_rank: int,
        priority_score: float,
        was_confirmed: bool,
        severity: Severity,
    ) -> None:
        """Record outcome with explicit severity for more targeted weight adjustment.

        This is the preferred method when the caller has access to the
        original hypothesis's severity, as it allows direct adjustment
        of the relevant severity weight.

        Args:
            hypothesis_id: ID of the resolved hypothesis.
            priority_rank: The rank (1-based) this hypothesis had when planned.
            priority_score: The priority score at planning time.
            was_confirmed: True if the hypothesis was confirmed.
            severity: The severity class of the hypothesis.
        """
        if priority_rank < 1:
            raise ValueError("priority_rank must be >= 1.")

        record = PrioritizationRecord(
            hypothesis_id=hypothesis_id,
            priority_rank=priority_rank,
            priority_score=priority_score,
            was_confirmed=was_confirmed,
        )
        self.records.append(record)

        # Compute a simple "surprise" factor based on rank and outcome.
        # High-rank confirmed = expected. Low-rank confirmed = surprise.
        # High-rank rejected = surprise. Low-rank rejected = expected.
        surprise = 0.0
        if was_confirmed and priority_rank > 3:
            # Confirmed but wasn't in top 3 — we under-prioritized this severity
            surprise = 0.05
        elif not was_confirmed and priority_rank <= 2:
            # Rejected but was in top 2 — we over-prioritized this severity
            surprise = -0.05

        if surprise != 0.0:
            old_weight = self.severity_weights.get(severity, 0.5)
            new_weight = old_weight + self.learning_rate * surprise
            new_weight = max(0.05, min(1.0, new_weight))
            self.severity_weights[severity] = new_weight
            logger.info(
                "Adjusted severity weight for %s: %.3f -> %.3f (surprise=%.3f)",
                severity.value,
                old_weight,
                new_weight,
                surprise,
            )

    def get_prioritization_stats(self) -> Dict[str, Any]:
        """Return statistics about the planner's prioritization performance.

        Returns:
            A dictionary with:
            - ``total_planned``: Number of hypotheses planned.
            - ``total_resolved``: Number with recorded outcomes.
            - ``confirmation_rate``: Fraction of resolved hypotheses confirmed.
            - ``top_rank_confirmation_rate``: Confirmation rate for rank-1 hypotheses.
            - ``current_severity_weights``: Snapshot of current weights.
            - ``avg_priority_score_confirmed``: Average score of confirmed hyps.
            - ``avg_priority_score_rejected``: Average score of rejected hyps.
        """
        total_resolved = len(self.records)
        confirmed = [r for r in self.records if r.was_confirmed]
        rejected = [r for r in self.records if not r.was_confirmed]
        top_rank = [r for r in self.records if r.priority_rank == 1]
        top_rank_confirmed = [r for r in top_rank if r.was_confirmed]

        avg_conf_score = (
            sum(r.priority_score for r in confirmed) / len(confirmed)
            if confirmed
            else 0.0
        )
        avg_rej_score = (
            sum(r.priority_score for r in rejected) / len(rejected)
            if rejected
            else 0.0
        )

        return {
            "total_planned": total_resolved,  # total that have outcomes
            "total_resolved": total_resolved,
            "confirmation_rate": len(confirmed) / total_resolved if total_resolved else 0.0,
            "top_rank_confirmation_rate": (
                len(top_rank_confirmed) / len(top_rank) if top_rank else 0.0
            ),
            "current_severity_weights": {
                s.value: w for s, w in self.severity_weights.items()
            },
            "avg_priority_score_confirmed": avg_conf_score,
            "avg_priority_score_rejected": avg_rej_score,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_priority_score(self, hypothesis: Hypothesis) -> float:
        """Compute the composite priority score for a hypothesis.

        Formula:
            score = confidence * severity_weight * (0.5 + 0.5 * differential) * recency_boost

        The differential term uses (0.5 + 0.5 * diff) so that hypotheses with
        zero differential still contribute half their weight.

        Args:
            hypothesis: The hypothesis to score.

        Returns:
            A float >= 0.0. Higher means higher priority.
        """
        # Confidence
        confidence = max(0.0, min(1.0, hypothesis.confidence))

        # Severity weight
        sev_weight = self.severity_weights.get(hypothesis.severity, 0.3)

        # Differential (scaled so 0.0 diff -> 0.5 contribution)
        differential_factor = 0.5 + 0.5 * max(0.0, min(1.0, hypothesis.differential_score))

        # Recency boost: hypotheses created more recently get a small boost.
        # Uses exponential decay: boost = 2^(-age / half_life)
        # Capped at [1.0, 1.2] to avoid dominating other signals.
        now = datetime.utcnow()
        age_hours = max(0.0, (now - hypothesis.created_at).total_seconds() / 3600.0)
        if age_hours < 1e-9:
            recency_boost = 1.2
        else:
            decay = math.pow(2.0, -age_hours / self.recency_half_life_hours)
            recency_boost = 1.0 + 0.2 * decay

        score = confidence * sev_weight * differential_factor * recency_boost
        return round(score, 6)

    def _generate_plan(
        self, hypothesis: Hypothesis, score: float, rank: int
    ) -> Dict[str, Any]:
        """Generate an experiment plan dict for a hypothesis.

        Selects the appropriate plan builder based on vulnerability class,
        then overlays the base_url and default headers.

        Args:
            hypothesis: The hypothesis to plan an experiment for.
            score: The pre-computed priority score (for traceability).
            rank: The rank position (1-based).

        Returns:
            A complete experiment plan dictionary.
        """
        builder = _PLAN_BUILDERS.get(hypothesis.vulnerability_class)

        if builder is not None:
            plan = builder(hypothesis)
        else:
            # Generic fallback plan for unknown vulnerability classes
            target_url = _resolve_target_url(hypothesis)

            plan = {
                "hypothesis_id": hypothesis.id,
                "vulnerability_class": (
                    hypothesis.vulnerability_class.value
                    if hypothesis.vulnerability_class
                    else "unknown"
                ),
                "target_url": target_url,
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer <token>",
                    "Content-Type": "application/json",
                },
                "body": None,
                "expected_outcome": {
                    "description": "The hypothesis is confirmed by the observed behavior",
                    "match_criteria": {"status_code": 200},
                },
                "falsifying_outcome": {
                    "description": "The hypothesis is falsified by the observed behavior",
                    "match_criteria": {"status_codes": [403, 404, 500]},
                },
                "metadata": {},
            }

        # Prepend base_url to target_url if set and target is a real route.
        # The static-analysis marker is not dispatchable — flag it instead.
        if plan["target_url"] == "/static-analysis-only/no-route-derived":
            plan["requires_live_target"] = False
            plan["dispatchable"] = False
        else:
            plan["requires_live_target"] = True
            plan["dispatchable"] = bool(self.base_url)
            if self.base_url and plan["target_url"].startswith("/"):
                plan["target_url"] = self.base_url + plan["target_url"]

        # Merge default headers (plan-specific headers take precedence)
        merged_headers = dict(self.default_headers)
        merged_headers.update(plan["headers"])
        plan["headers"] = merged_headers

        # Attach scoring metadata
        plan["priority_score"] = score
        plan["priority_rank"] = rank
        plan["generated_at"] = datetime.utcnow().isoformat()

        return plan

    def _validate_severity_weights(self) -> None:
        """Ensure all severity weights are valid floats in [0, 1]."""
        for sev, weight in self.severity_weights.items():
            if not isinstance(sev, Severity):
                raise TypeError(
                    f"Severity weight key must be a Severity enum, got {type(sev).__name__}"
                )
            if not isinstance(weight, (int, float)):
                raise TypeError(
                    f"Severity weight must be numeric, got {type(weight).__name__}"
                )
            if not (0.0 <= weight <= 1.0):
                raise ValueError(
                    f"Severity weight for {sev.value} must be in [0, 1], got {weight}"
                )

    def _adjust_weights_from_outcome(self, record: PrioritizationRecord) -> None:
        """Adjust severity weights based on a generic outcome record.

        This is a simpler version used when the caller doesn't provide the
        explicit severity. It adjusts ALL weights slightly toward the
        median based on the surprise factor.
        """
        if not self.records:
            return

        # If the top-ranked hypothesis was rejected, slightly reduce all weights
        # to make future scoring more conservative. If confirmed, slight increase.
        # This is a blunt instrument; prefer record_outcome_with_severity.
        if record.priority_rank <= 2:
            if not record.was_confirmed:
                # High-rank rejection: reduce all weights slightly
                for sev in self.severity_weights:
                    self.severity_weights[sev] = max(
                        0.05, self.severity_weights[sev] - self.learning_rate * 0.02
                    )
                logger.debug("Reduced all severity weights (top-rank rejection)")
            else:
                # High-rank confirmation: small increase
                for sev in self.severity_weights:
                    self.severity_weights[sev] = min(
                        1.0, self.severity_weights[sev] + self.learning_rate * 0.01
                    )
                logger.debug("Increased all severity weights (top-rank confirmation)")
