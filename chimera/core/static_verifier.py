"""Chimera Static Verifier — Closes the reasoning loop without a live target.

The experimentation phase traditionally needs a running HTTP target. The
StaticVerifier instead *executes* falsification probes against the semantic
graph: for each surviving hypothesis it re-interrogates the code, asking the
questions a hostile reviewer would ask at runtime:

    1. **Inter-procedural guard sweep** — maybe the function itself lacks a
       check, but EVERY caller guards before invoking it (witness elimination).
    2. **Container-level protection** — the class/module carrying the handler
       may bear an auth decorator that function-level AST analysis missed.
    3. **Framework protection indicators** — the graph may show middleware or
       permission classes on enclosing views.
    4. **Ownership sink verification** — the resource identifier may never
       reach a data-access sink at all (dead parameter → no IDOR).

Each probe produces verdict + Evidence (EXPERIMENT_RESULT), so the closed
loop is honest: plan -> execute (static) -> evidence -> belief update.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from chimera.models.evidence import (
    ChainOfCustody,
    Evidence,
    EvidenceSource,
    EvidenceType,
)

if TYPE_CHECKING:
    from chimera.core.implementation_model import ImplementationModel
    from chimera.core.intent_model import IntentModel
    from chimera.core.semantic_graph import SemanticGraph
    from chimera.models.hypothesis import Hypothesis

logger = logging.getLogger(__name__)


@dataclass
class VerificationOutcome:
    """Result of statically verifying one hypothesis."""
    hypothesis_id: str
    verdict: str  # "strengthened" | "weakened" | "neutral"
    confidence_delta: float  # [-0.25, +0.15]
    probes: List[str] = field(default_factory=list)
    rationale: str = ""
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "verdict": self.verdict,
            "confidence_delta": self.confidence_delta,
            "probes": self.probes,
            "rationale": self.rationale,
            "evidence_count": len(self.evidence),
        }


class StaticVerifier:
    """
    Executes static falsification/verification probes against the graph.

    Bounded and deterministic: every probe is a graph query with a clear
    verdict rule. No network, no subprocess, no LLM.
    """

    _AUTH_GUARD_NAMES = {
        "login_required", "permission_required", "authenticate",
        "is_authenticated", "check_permission", "require_auth",
        "jwt_required", "auth_required", "authorized",
    }

    def verify(
        self,
        hypothesis: "Hypothesis",
        graph: "SemanticGraph",
        intent_model: Optional["IntentModel"] = None,
        impl_model: Optional["ImplementationModel"] = None,
    ) -> VerificationOutcome:
        """Run all probes that apply to this hypothesis."""
        outcome = VerificationOutcome(
            hypothesis_id=hypothesis.id, verdict="neutral", confidence_delta=0.0
        )

        if not hypothesis.attack_surface:
            outcome.rationale = "No attack surface — nothing to verify."
            return outcome

        for entity_id in hypothesis.attack_surface:
            node = graph.get_node(entity_id)
            if node is None:
                outcome.probes.append(f"entity_missing:{entity_id}")
                # Decisive: the claim references code the analysis cannot see.
                outcome.confidence_delta -= 0.15
                outcome.rationale = (
                    "Referenced entity not present in the graph — the claim "
                    "cannot be cross-verified."
                )
                outcome.verdict = "weakened"
                continue

            # Probe 1: inter-procedural caller guard sweep
            caller_guarded, total_callers = self._callers_all_guarded(node.id, graph)
            outcome.probes.append(
                f"caller_guard_sweep:{node.name}(guarded={caller_guarded},callers={total_callers})"
            )
            if caller_guarded and total_callers > 0:
                outcome.confidence_delta -= 0.20
                outcome.rationale = (
                    f"All {total_callers} known caller(s) of '{node.name}' enforce "
                    f"guards before invocation — the gap is not reachable unguarded."
                )

            # Probe 2: container-level protection (class/module decorators)
            if self._container_is_protected(node.id, graph):
                outcome.probes.append(f"container_protected:{node.name}")
                outcome.confidence_delta -= 0.15
                outcome.rationale += (
                    f" Enclosing class/module of '{node.name}' carries an auth "
                    f"decorator that function-level analysis cannot see."
                )

            # Probe 3: ownership sink reachability (IDOR class only)
            if hypothesis.vulnerability_class and hypothesis.vulnerability_class.value in {
                "idor", "privilege_escalation_horizontal"
            }:
                if self._has_data_access_sink(node, graph):
                    outcome.probes.append(f"data_sink_reachable:{node.name}")
                    outcome.confidence_delta += 0.08
                else:
                    outcome.probes.append(f"no_data_sink:{node.name}")
                    outcome.confidence_delta -= 0.10
                    outcome.rationale += (
                        f" Resource identifier in '{node.name}' never reaches a "
                        f"data-access operation — exploitability is doubtful."
                    )

            # Probe 4: route exposure — an internal helper is not an attack surface
            if not self._is_exposed(node):
                outcome.probes.append(f"not_externally_exposed:{node.name}")
                outcome.confidence_delta -= 0.05

        # Clamp and decide. A probe that already decided "weakened" (missing
        # entity) is not overridden by a modest aggregate delta.
        outcome.confidence_delta = max(-0.25, min(0.15, outcome.confidence_delta))
        if outcome.verdict != "weakened":
            if outcome.confidence_delta <= -0.15:
                outcome.verdict = "weakened"
            elif outcome.confidence_delta >= 0.05:
                outcome.verdict = "strengthened"
            else:
                outcome.verdict = "neutral"
        if not outcome.rationale:
            outcome.rationale = (
                "Static probes found no contradicting protection layer; the "
                "hypothesis stands on its differential evidence."
            )

        outcome.evidence = [self._to_evidence(hypothesis, outcome)]
        return outcome

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------

    def _callers_all_guarded(self, node_id: str, graph: "SemanticGraph") -> tuple:
        """
        Check whether every graph caller of the node guards before calling.

        Returns (all_guarded, caller_count). A node with no recorded callers
        returns (False, 0) — we cannot claim protection we cannot see.
        """
        from chimera.core.semantic_graph import EdgeType

        callers = [
            e.source_id
            for e in graph.get_incoming_edges(node_id)
            if e.edge_type == EdgeType.CALLS
        ]
        if not callers:
            return False, 0

        for caller_id in callers:
            caller = graph.get_node(caller_id)
            if caller is None:
                return False, len(callers)
            guarded = (
                bool(caller.properties.get("auth_checks"))
                or "auth_checked" in caller.semantic_tags
                or "auth_protected" in caller.semantic_tags
                or "ownership_check" in caller.semantic_tags
            )
            if not guarded:
                # Check the caller's own graph edges for auth
                has_auth_edge = any(
                    e.edge_type in {EdgeType.AUTHORIZES, EdgeType.GUARDS}
                    for e in graph.get_incoming_edges(caller_id)
                )
                if not has_auth_edge:
                    return False, len(callers)
        return True, len(callers)

    def _container_is_protected(self, node_id: str, graph: "SemanticGraph") -> bool:
        """Whether the enclosing class/module node carries an auth decorator."""
        from chimera.core.semantic_graph import EdgeType

        for edge in graph.get_incoming_edges(node_id):
            if edge.edge_type != EdgeType.CONTAINS:
                continue
            parent = graph.get_node(edge.source_id)
            if parent is None:
                continue
            for pedge in graph.get_incoming_edges(parent.id):
                if pedge.edge_type in {EdgeType.AUTHORIZES, EdgeType.GUARDS}:
                    return True
                if pedge.edge_type == EdgeType.DECORATES:
                    src = graph.get_node(pedge.source_id)
                    if src and (
                        src.properties.get("is_auth")
                        or any(t in src.name.lower() for t in ("login", "auth", "permission"))
                    ):
                        return True
        return False

    def _has_data_access_sink(self, node: Any, graph: "SemanticGraph") -> bool:
        """
        Whether the handler's resource identifier plausibly reaches a data
        access operation (dict/subscript access, ORM call, query).
        """
        props = node.properties
        # data flows recorded by the parser
        for flow in props.get("data_flows", []):
            target = str(flow.get("target", "")).lower()
            if any(k in target for k in ("get", "query", "filter", "execute", "fetch", "[")):
                return True
        # comparisons on the id imply the id is used for lookup/branching
        if props.get("comparisons"):
            return True
        # state operations imply mutation of a stored entity
        if props.get("state_operations"):
            return True
        # call graph mentions ORM-ish names
        from chimera.core.semantic_graph import EdgeType

        for edge in graph.get_outgoing_edges(node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target and any(
                    k in target.name.lower()
                    for k in ("query", "filter", "get", "execute", "fetch", "save", "delete", "objects")
                ):
                    return True
        return False

    @staticmethod
    def _is_exposed(node: Any) -> bool:
        """Best-effort: whether the handler is externally reachable."""
        if node.properties.get("route"):
            return True
        if node.node_type.value == "endpoint":
            return True
        tags = getattr(node, "semantic_tags", set())
        if {"route", "endpoint"} & tags:
            return True
        # Leading underscore = private helper
        if node.name.startswith("_"):
            return False
        return True  # unknown -> assume exposed (conservative)

    def _to_evidence(self, hypothesis: "Hypothesis", outcome: VerificationOutcome) -> Evidence:
        chain = ChainOfCustody()
        ev_id = f"EVD-{uuid.uuid4().hex[:10].upper()}"
        chain.add_step(
            tool="StaticVerifier",
            action="static_falsification_probes",
            input_ref=hypothesis.id,
            output_ref=ev_id,
            parameters={"probes": outcome.probes, "verdict": outcome.verdict},
        )
        chain.finalize()
        return Evidence(
            source=EvidenceSource.EXPERIMENT,
            evidence_type=EvidenceType.EXPERIMENT_RESULT,
            data={
                "experiment": "static_interprocedural_verification",
                "verdict": outcome.verdict,
                "confidence_delta": outcome.confidence_delta,
                "probes": outcome.probes,
                "rationale": outcome.rationale,
            },
            chain_of_custody=chain,
            confidence=0.85,
            description=(
                f"Static verification of {hypothesis.id}: verdict={outcome.verdict} "
                f"(delta={outcome.confidence_delta:+.2f})"
            ),
            metadata={"verifier": "static", "hypothesis_id": hypothesis.id},
        )
