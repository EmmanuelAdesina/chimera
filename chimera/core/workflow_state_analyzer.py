"""Chimera Workflow State Machine Analyzer — THE CORE ENGINE.

This is the primary intelligence of Chimera. The LLM is a PLUGIN;
WorkflowStateMachineAnalyzer is the CORE. It:

1. Extracts state machines from the SemanticGraph (states, transitions, guards)
2. Builds an abstract state machine model for each workflow
3. Computes differentials between Expected (IntentModel) and
   Observed (ImplementationModel) state machines
4. Identifies violations: missing guards, unreachable states,
   illegal transitions, bypass paths

The Causal Differential Engine calls this to get raw differentials,
then converts them into Hypotheses.

This is NOT a wrapper around an LLM. It uses graph algorithms,
CFG analysis, and semantic reasoning.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from chimera.core.semantic_graph import SemanticGraph, GraphNode
    from chimera.core.intent_model import IntentModel, IntentExpectation
    from chimera.core.implementation_model import ImplementationModel, ImplementationObservation


@dataclass
class State:
    """A state in a workflow state machine."""
    name: str
    node_ids: List[str] = field(default_factory=list)  # Graph nodes that define this state
    is_initial: bool = False
    is_terminal: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)
    semantic_tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "node_ids": self.node_ids,
            "is_initial": self.is_initial,
            "is_terminal": self.is_terminal,
            "properties": self.properties,
        }


@dataclass
class Transition:
    """A state transition in a workflow."""
    name: str
    from_state: str
    to_state: str
    trigger_function_id: str = ""  # Graph node that triggers this
    guard_ids: List[str] = field(default_factory=list)  # Guard function node IDs
    is_guarded: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "trigger_function_id": self.trigger_function_id,
            "guard_ids": self.guard_ids,
            "is_guarded": self.is_guarded,
        }


@dataclass
class StateMachine:
    """A workflow state machine extracted from code."""
    name: str
    states: Dict[str, State] = field(default_factory=dict)
    transitions: List[Transition] = field(default_factory=list)
    initial_state: str = ""
    terminal_states: Set[str] = field(default_factory=set)
    source_file: str = ""
    entity_id: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def get_state(self, name: str) -> Optional[State]:
        return self.states.get(name)

    def get_transitions_from(self, state_name: str) -> List[Transition]:
        return [t for t in self.transitions if t.from_state == state_name]

    def get_transitions_to(self, state_name: str) -> List[Transition]:
        return [t for t in self.transitions if t.to_state == state_name]

    def is_reachable(self, target: str) -> bool:
        """BFS to check if a state is reachable from the initial state."""
        if not self.initial_state:
            return False
        from collections import deque
        visited = {self.initial_state}
        queue = deque([self.initial_state])
        while queue:
            current = queue.popleft()
            if current == target:
                return True
            for t in self.get_transitions_from(current):
                if t.to_state not in visited:
                    visited.add(t.to_state)
                    queue.append(t.to_state)
        return False

    def find_unguarded_transitions(self) -> List[Transition]:
        """Find all transitions that lack guards."""
        return [t for t in self.transitions if not t.is_guarded and not t.guard_ids]

    def find_unreachable_states(self) -> List[State]:
        """Find states not reachable from the initial state."""
        return [
            s for name, s in self.states.items()
            if name != self.initial_state and not self.is_reachable(name)
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "states": {k: v.to_dict() for k, v in self.states.items()},
            "transitions": [t.to_dict() for t in self.transitions],
            "initial_state": self.initial_state,
            "terminal_states": list(self.terminal_states),
            "source_file": self.source_file,
            "entity_id": self.entity_id,
        }


@dataclass
class StateMachineDifferential:
    """
    A difference between expected and observed state machines.
    This is the raw output that the Causal Differential Engine converts to Hypotheses.
    """
    state_machine_name: str
    differential_type: str  # "missing_guard", "extra_transition", "missing_state", "bypass_path"
    expected: str
    observed: str
    severity: float = 0.5  # 0.0-1.0
    entity_ids: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    file_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_machine_name": self.state_machine_name,
            "differential_type": self.differential_type,
            "expected": self.expected,
            "observed": self.observed,
            "severity": self.severity,
            "entity_ids": self.entity_ids,
            "context": self.context,
            "file_path": self.file_path,
        }


class WorkflowStateMachineAnalyzer:
    """
    THE CORE ENGINE of Chimera.

    This analyzer extracts workflow state machines from the SemanticGraph,
    then computes differentials between what is EXPECTED (from IntentModel)
    and what is OBSERVED (from ImplementationModel).

    The differential computation is the primary intelligence of Chimera.
    It identifies:
    1. Missing guards on state transitions
    2. Unauthorized state transitions (bypass paths)
    3. Unreachable states that may indicate dead code or missing checks
    4. State machine violations (illegal state jumps)

    Workflow:
    1. extract_state_machines(graph) -> List[StateMachine]
    2. compute_differentials(state_machines, intent_model, impl_model) -> List[StateMachineDifferential]
    """

    # Patterns that indicate state variables in code
    _STATE_VAR_NAMES = {"status", "state", "phase", "stage", "step", "workflow_state"}
    _STATE_ASSIGNMENT_PATTERNS = {
        "status": ["pending", "approved", "rejected", "completed", "cancelled",
                     "active", "inactive", "suspended", "archived"],
        "state": ["draft", "published", "private", "public", "deleted",
                   "open", "closed", "locked", "unlocked"],
        "phase": ["review", "approval", "processing", "shipping", "delivery"],
    }
    # Verb stems in handler names that imply a resulting state:
    # approve_order() -> "approved", cancel_order() -> "cancelled".
    _VERB_STATE_MAP = {
        "approve": ("status", "approved"),
        "approves": ("status", "approved"),
        "reject": ("status", "rejected"),
        "complete": ("status", "completed"),
        "cancel": ("status", "cancelled"),
        "suspend": ("status", "suspended"),
        "archive": ("status", "archived"),
        "activate": ("status", "active"),
        "deactivate": ("status", "inactive"),
        "publish": ("state", "published"),
        "close": ("state", "closed"),
        "reopen": ("state", "open"),
        "open": ("state", "open"),
        "lock": ("state", "locked"),
        "unlock": ("state", "unlocked"),
        "submit": ("status", "submitted"),
        "refund": ("status", "refunded"),
        "ship": ("phase", "shipping"),
        "deliver": ("phase", "delivery"),
        "pay": ("status", "paid"),
    }

    def __init__(self) -> None:
        self.state_machines: List[StateMachine] = []
        self._node_to_state: Dict[str, str] = {}  # node_id -> state machine name

    # ------------------------------------------------------------------
    # State Machine Extraction
    # ------------------------------------------------------------------

    def extract_state_machines(self, graph: SemanticGraph) -> List[StateMachine]:
        """
        Extract workflow state machines from the semantic graph.

        Strategy:
        1. Find all functions that modify state variables
        2. Group them by the state variable they modify
        3. Extract the states (assignments) and transitions (function triggers)
        4. Identify guards (authorization checks) on transition functions
        """
        self.state_machines = []
        from chimera.core.semantic_graph import NodeType

        # Find all state-related variable modifications
        state_modifiers = self._find_state_modifiers(graph)

        # Group modifiers by the state variable / model they operate on
        machine_groups = self._group_into_machines(state_modifiers, graph)

        # Build a StateMachine for each group
        for machine_name, group_info in machine_groups.items():
            sm = self._build_state_machine(machine_name, group_info, graph)
            if sm and len(sm.states) >= 2:
                self.state_machines.append(sm)

        # Also extract from class-based state machines (models with status fields)
        for cls_node in graph.find_nodes_by_type(NodeType.CLASS):
            if cls_node.properties.get("class_type") == "model":
                sm = self._extract_model_state_machine(cls_node, graph)
                if sm and len(sm.states) >= 2:
                    self.state_machines.append(sm)

        return self.state_machines

    @staticmethod
    def _normalize_state_value(raw: str) -> str:
        """
        Normalize a state value extracted from the AST.

        The python parser resolves constants via ``repr`` — ``"'APPROVED'"``
        — so strip surrounding quotes and lowercase for state naming.
        """
        if not raw:
            return ""
        value = str(raw).strip().strip("'\"")
        return value.lower()

    def _find_state_modifiers(self, graph: SemanticGraph) -> List[Dict[str, Any]]:
        """Find all functions that modify state variables."""
        from chimera.core.semantic_graph import NodeType
        modifiers = []
        for node in graph.find_nodes_by_type(NodeType.FUNCTION):
            state_ops = node.properties.get("state_operations", [])
            if state_ops:
                for op in state_ops:
                    # Parser emits "new_value"; tolerate legacy "value" key.
                    raw_value = op.get("new_value") or op.get("value", "")
                    modifiers.append({
                        "function_node": node,
                        "state_var": op.get("variable", ""),
                        "new_value": self._normalize_state_value(raw_value),
                        "line": op.get("line", 0),
                    })
            # Also check for status-related naming patterns
            name_lower = node.name.lower()
            for state_var, state_values in self._STATE_ASSIGNMENT_PATTERNS.items():
                for value in state_values:
                    if value in name_lower:
                        modifiers.append({
                            "function_node": node,
                            "state_var": state_var,
                            "new_value": value,
                            "line": node.line_range[0],
                        })
                        break
            # Verb-stem mapping: approve_order() implies a transition
            # to the "approved" state even without a status assignment.
            first_token = name_lower.split("_")[0] if name_lower else ""
            mapped = self._VERB_STATE_MAP.get(first_token)
            if mapped:
                modifiers.append({
                    "function_node": node,
                    "state_var": mapped[0],
                    "new_value": mapped[1],
                    "line": node.line_range[0],
                })

        # Dedupe: one (function, state_var, new_value) key per modifier —
        # the name-pattern and verb-map passes can agree on the same fact.
        seen: Set[tuple] = set()
        unique: List[Dict[str, Any]] = []
        for mod in modifiers:
            key = (
                mod["function_node"].id,
                mod["state_var"],
                mod["new_value"],
            )
            if key not in seen:
                seen.add(key)
                unique.append(mod)
        return unique

    def _group_into_machines(
        self, modifiers: List[Dict], graph: SemanticGraph
    ) -> Dict[str, Dict[str, Any]]:
        """Group state-modifying functions into logical state machines."""
        groups: Dict[str, Dict[str, Any]] = {}
        for mod in modifiers:
            func_node = mod["function_node"]
            state_var = mod["state_var"]

            # Try to determine the model/entity this state machine belongs to
            entity_name = self._infer_entity(func_node, graph)
            machine_name = f"{entity_name}_{state_var}_machine" if entity_name else f"{state_var}_machine"

            if machine_name not in groups:
                groups[machine_name] = {
                    "entity_name": entity_name,
                    "state_var": state_var,
                    "modifiers": [],
                    "file_path": func_node.file_path,
                }
            groups[machine_name]["modifiers"].append(mod)

        return groups

    def _infer_entity(self, func_node: GraphNode, graph: SemanticGraph) -> str:
        """Infer which model/entity a function belongs to via graph edges."""
        from chimera.core.semantic_graph import EdgeType

        # Check if function is contained in a class
        for edge in graph.get_incoming_edges(func_node.id):
            if edge.edge_type == EdgeType.CONTAINS:
                parent = graph.get_node(edge.source_id)
                if parent and parent.node_type.value == "class":
                    return parent.name

        # Check function name for entity hints (e.g., approve_order -> order)
        parts = func_node.name.split("_")
        if len(parts) >= 2:
            # Usually pattern is action_entity
            for i, part in enumerate(parts):
                if part in {"approve", "reject", "delete", "update", "create",
                            "cancel", "submit", "publish", "archive"} and i + 1 < len(parts):
                    return parts[i + 1]

        return "unknown"

    def _build_state_machine(
        self, name: str, group: Dict, graph: SemanticGraph
    ) -> Optional[StateMachine]:
        """Build a StateMachine from a group of state modifiers."""
        sm = StateMachine(
            name=name,
            source_file=group["file_path"],
            entity_id=name,
        )

        modifiers = group["modifiers"]

        # Collect all state values
        state_values: Set[str] = set()
        for mod in modifiers:
            val = mod["new_value"]
            if val:
                state_values.add(val.lower())

        # Create states
        for val in sorted(state_values):
            sm.states[val] = State(
                name=val,
                properties={"value": val},
            )

        # Set initial state (common defaults)
        for initial_candidate in ["pending", "draft", "open", "new", "created"]:
            if initial_candidate in sm.states:
                sm.initial_state = initial_candidate
                sm.states[initial_candidate].is_initial = True
                break

        # Create transitions (deduped on (from, to, trigger))
        seen_transitions: Set[tuple] = set()

        def _add_transition(from_state: str, to_state: str, func_node: Any) -> None:
            key = (from_state, to_state, func_node.id)
            if key in seen_transitions:
                return
            seen_transitions.add(key)
            t = Transition(
                name=f"{func_node.name}_{from_state}_to_{to_state}",
                from_state=from_state,
                to_state=to_state,
                trigger_function_id=func_node.id,
            )
            t.is_guarded = self._check_has_guard(func_node, graph)
            if t.is_guarded:
                t.guard_ids = self._get_guard_ids(func_node, graph)
            sm.transitions.append(t)

        for mod in modifiers:
            func_node = mod["function_node"]
            from_state = self._infer_from_state(func_node, graph)
            to_state = mod["new_value"].lower()

            if not from_state:
                # Unknown precondition: a single wildcard transition stands in
                # for "from any state".  Expanding to N concrete transitions
                # would report the same missing guard N times.
                _add_transition("*", to_state, func_node)
            else:
                if from_state in sm.states:
                    _add_transition(from_state, to_state, func_node)

        return sm if sm.states else None

    def _extract_model_state_machine(
        self, cls_node: GraphNode, graph: SemanticGraph
    ) -> Optional[StateMachine]:
        """Extract a state machine from a model class with status-like fields."""
        from chimera.core.semantic_graph import EdgeType, NodeType

        fields = cls_node.properties.get("fields", [])
        status_fields = [
            f for f in fields
            if any(kw in f.get("name", "").lower() for kw in self._STATE_VAR_NAMES)
            and f.get("type", "").lower() in {"string", "str", "text", "varchar", "char", "enum", "choice"}
        ]

        if not status_fields:
            return None

        field = status_fields[0]
        field_name = field.get("name", "status")
        choices = field.get("choices", [])

        if not choices:
            return None

        sm = StateMachine(
            name=f"{cls_node.name}_{field_name}_machine",
            source_file=cls_node.file_path,
            entity_id=cls_node.id,
        )

        for choice in choices:
            if isinstance(choice, (list, tuple)) and len(choice) >= 1:
                val = str(choice[0]).lower()
                sm.states[val] = State(name=val, properties={"value": val})
            elif isinstance(choice, str):
                sm.states[choice.lower()] = State(name=choice.lower())

        if sm.states:
            first_state = next(iter(sm.states))
            sm.initial_state = first_state
            sm.states[first_state].is_initial = True

        # Find methods that change this field
        from chimera.core.semantic_graph import EdgeType
        for edge in graph.get_outgoing_edges(cls_node.id):
            if edge.edge_type == EdgeType.CONTAINS:
                method_node = graph.get_node(edge.target_id)
                if method_node and method_node.node_type == NodeType.FUNCTION:
                    state_ops = method_node.properties.get("state_operations", [])
                    for op in state_ops:
                        if op.get("variable", "").lower() == field_name.lower():
                            to_state = self._normalize_state_value(
                                op.get("new_value") or op.get("value", "")
                            )
                            if to_state in sm.states:
                                for sname in sm.states:
                                    if sname != to_state:
                                        t = Transition(
                                            name=f"{method_node.name}_{sname}_to_{to_state}",
                                            from_state=sname, to_state=to_state,
                                            trigger_function_id=method_node.id,
                                        )
                                        t.is_guarded = self._check_has_guard(method_node, graph)
                                        sm.transitions.append(t)

        return sm if len(sm.states) >= 2 else None

    def _infer_from_state(self, func_node: GraphNode, graph: SemanticGraph) -> str:
        """Infer which state a transition function expects as pre-condition."""
        name_lower = func_node.name.lower()
        for state_val in ["pending", "draft", "open", "submitted", "active"]:
            if state_val in name_lower:
                return state_val
        # Check if function has a state check in its comparisons
        comparisons = func_node.properties.get("comparisons", [])
        for comp in comparisons:
            comp_str = str(comp).lower()
            for state_val in ["pending", "draft", "open", "submitted", "active"]:
                if state_val in comp_str:
                    return state_val
        return ""

    def _check_has_guard(self, func_node: GraphNode, graph: SemanticGraph) -> bool:
        """Check if a transition function has a guard via graph traversal."""
        from chimera.core.semantic_graph import EdgeType

        # Parser-emitted inline guards (is_admin gates, PermissionError...)
        if func_node.properties.get("auth_checks"):
            return True
        if "auth_checked" in getattr(func_node, "semantic_tags", set()):
            return True

        # Incoming AUTHORIZES / GUARDS edges are conclusive — the parser only
        # creates them for auth-classified decorators. A bare DECORATES edge
        # (e.g. @app.route) is NOT a guard; the decorator name must be authy.
        for edge in graph.get_incoming_edges(func_node.id):
            if edge.edge_type in {EdgeType.GUARDS, EdgeType.AUTHORIZES}:
                return True
            if edge.edge_type == EdgeType.DECORATES:
                src = graph.get_node(edge.source_id)
                if src and (
                    src.properties.get("is_auth")
                    or any(kw in src.name.lower() for kw in ("login", "auth", "permission", "role"))
                ):
                    return True

        # Check if the function calls any guard-like function
        guard_names = {"check", "guard", "validate", "verify", "can", "is_allowed", "permit"}
        for edge in graph.get_outgoing_edges(func_node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target:
                    tname_lower = target.name.lower()
                    if any(g in tname_lower for g in guard_names):
                        return True

        return False

    def _get_guard_ids(self, func_node: GraphNode, graph: SemanticGraph) -> List[str]:
        """Get IDs of guard nodes for a function."""
        from chimera.core.semantic_graph import EdgeType

        guard_ids = []
        for edge in graph.get_incoming_edges(func_node.id):
            if edge.edge_type in {EdgeType.GUARDS, EdgeType.AUTHORIZES, EdgeType.DECORATES}:
                guard_ids.append(edge.source_id)
        for edge in graph.get_outgoing_edges(func_node.id):
            if edge.edge_type == EdgeType.CALLS:
                target = graph.get_node(edge.target_id)
                if target and any(g in target.name.lower()
                                   for g in {"check", "guard", "validate", "verify"}):
                    guard_ids.append(edge.target_id)
        return guard_ids

    # ------------------------------------------------------------------
    # Differential Computation
    # ------------------------------------------------------------------

    def compute_differentials(
        self,
        intent_model: IntentModel,
        impl_model: ImplementationModel,
        graph: SemanticGraph,
    ) -> List[StateMachineDifferential]:
        """
        Compute differentials between expected and observed state machines.

        This is the core intelligence: comparing IntentModel expectations
        against ImplementationModel observations and the extracted state machines.

        Differential types:
        1. missing_guard: A transition should have a guard (intent says auth) but doesn't
        2. extra_transition: An unguarded transition exists that intent didn't expect
        3. missing_state: A state exists in the model but no function reaches it
        4. bypass_path: A path exists that skips required state transitions
        """
        differentials: List[StateMachineDifferential] = []

        for sm in self.state_machines:
            # Differential 1: Unguarded transitions
            for t in sm.find_unguarded_transitions():
                trigger = graph.get_node(t.trigger_function_id)
                if not trigger:
                    continue

                # Check if intent expects auth/ownership on this trigger
                expects_auth = intent_model.has_expectation(trigger.id, "auth")
                expects_ownership = intent_model.has_expectation(trigger.id, "ownership")
                has_auth_obs = impl_model.has_observation(trigger.id, "no_auth")
                has_no_ownership = impl_model.has_observation(trigger.id, "no_ownership")

                if expects_auth and has_auth_obs:
                    differentials.append(StateMachineDifferential(
                        state_machine_name=sm.name,
                        differential_type="missing_guard",
                        expected=(
                            f"Transition {t.from_state}->{t.to_state} via '{trigger.name}' "
                            f"should require authorization (intent expects auth)"
                        ),
                        observed=(
                            f"No authorization guard found on '{trigger.name}'. "
                            f"The transition is unguarded — any authenticated user can trigger it."
                        ),
                        severity=0.8,
                        entity_ids=[trigger.id],
                        context={
                            "transition": t.to_dict(),
                            "state_machine": sm.name,
                            "vulnerability_class": "state_machine_violation",
                        },
                        file_path=trigger.file_path,
                    ))

                if expects_ownership and has_no_ownership:
                    differentials.append(StateMachineDifferential(
                        state_machine_name=sm.name,
                        differential_type="missing_guard",
                        expected=(
                            f"Transition {t.from_state}->{t.to_state} via '{trigger.name}' "
                            f"should verify resource ownership"
                        ),
                        observed=(
                            f"No ownership check found on '{trigger.name}'. "
                            f"Any user can trigger this state transition on any resource."
                        ),
                        severity=0.85,
                        entity_ids=[trigger.id],
                        context={
                            "transition": t.to_dict(),
                            "state_machine": sm.name,
                            "vulnerability_class": "privilege_escalation_horizontal",
                        },
                        file_path=trigger.file_path,
                    ))

            # Differential 2: Bypass paths (direct jumps that skip intermediate states)
            for t in sm.transitions:
                if self._is_bypass(sm, t):
                    trigger = graph.get_node(t.trigger_function_id)
                    if trigger:
                        differentials.append(StateMachineDifferential(
                            state_machine_name=sm.name,
                            differential_type="bypass_path",
                            expected=(
                                f"Transition to '{t.to_state}' should require passing through "
                                f"intermediate states (workflow integrity)"
                            ),
                            observed=(
                                f"Function '{trigger.name}' allows direct transition to '{t.to_state}' "
                                f"from '{t.from_state}', bypassing required workflow steps"
                            ),
                            severity=0.7,
                            entity_ids=[trigger.id],
                            context={
                                "transition": t.to_dict(),
                                "state_machine": sm.name,
                                "vulnerability_class": "workflow_bypass",
                            },
                            file_path=trigger.file_path,
                        ))

            # Differential 3: Unreachable states may indicate missing transitions
            for unreachable in sm.find_unreachable_states():
                differentials.append(StateMachineDifferential(
                    state_machine_name=sm.name,
                    differential_type="missing_state",
                    expected=f"State '{unreachable.name}' should be reachable via some transition",
                    observed=f"State '{unreachable.name}' is unreachable from '{sm.initial_state}'",
                    severity=0.3,
                    entity_ids=unreachable.node_ids,
                    context={
                        "state": unreachable.to_dict(),
                        "state_machine": sm.name,
                    },
                    file_path=sm.source_file,
                ))

        # Also compute entity-level differentials (not just state machine level)
        entity_differentials = self._compute_entity_differentials(
            intent_model, impl_model, graph
        )
        differentials.extend(entity_differentials)

        # Grammar differentials (unsafe sinks) — violations of the universal
        # expectation "queries/commands must not be string-built with
        # attacker-controlled values". No per-entity intent needed.
        from chimera.core.semantic_graph import NodeType
        for node_type in (NodeType.FUNCTION, NodeType.ENDPOINT):
            for node in graph.find_nodes_by_type(node_type):
                for obs in impl_model.get_observations_for(node.id):
                    if obs.observation_type != "unsafe_sql":
                        continue
                    differentials.append(StateMachineDifferential(
                        state_machine_name="grammar_cascade",
                        differential_type="unsafe_sink",
                        expected=(
                            f"'{node.name}' should only execute parameterized "
                            f"queries (bound parameters keep data out of the SQL grammar)"
                        ),
                        observed=obs.description,
                        severity=0.85,
                        entity_ids=[node.id],
                        context={
                            "observation": obs.to_dict() if hasattr(obs, "to_dict") else {},
                            "vulnerability_class": "injection",
                        },
                        file_path=node.file_path,
                    ))

        # Final dedupe: one differential per (primary entity, concern). The
        # same missing guard must never be reported twice under different
        # framings (entity-level IDOR vs state-machine privilege_escalation_horizontal
        # describe the same ownership gap). Keep the highest-severity framing.
        concern_of = {
            "idor": "ownership",
            "privilege_escalation_horizontal": "ownership",
            "privilege_escalation_vertical": "auth",
            "state_machine_violation": "state",
            "workflow_bypass": "bypass",
            "race_condition": "auth",
            "injection": "injection",
        }
        best: Dict[tuple, StateMachineDifferential] = {}
        for d in differentials:
            vuln_class = d.context.get("vulnerability_class", "")
            concern = concern_of.get(vuln_class, d.differential_type)
            if d.differential_type == "bypass_path":
                concern = "bypass"
            elif d.differential_type == "missing_state":
                concern = "state_reachability"
            key = (d.entity_ids[0] if d.entity_ids else "", concern)
            existing = best.get(key)
            if existing is None or d.severity > existing.severity:
                best[key] = d
        return list(best.values())

    def _is_bypass(self, sm: StateMachine, transition: Transition) -> bool:
        """
        Check if a transition bypasses required intermediate states.

        A bypass exists when a transition jumps from an early state to a
        late state, skipping states that should require explicit transitions.
        """
        # Build a topological ordering of states based on transition structure
        state_order = self._topological_state_order(sm)

        from_idx = state_order.get(transition.from_state, -1)
        to_idx = state_order.get(transition.to_state, -1)

        if from_idx < 0 or to_idx < 0:
            return False

        # If the gap is more than 1, it's a potential bypass
        if to_idx - from_idx > 1:
            # But only if the intermediate states exist and the transition is unguarded
            if not transition.is_guarded:
                return True

        return False

    def _topological_state_order(self, sm: StateMachine) -> Dict[str, int]:
        """Assign a topological order to states based on transition structure."""
        order: Dict[str, int] = {}
        if not sm.initial_state:
            return order

        # BFS from initial state assigns order
        from collections import deque
        queue = deque([sm.initial_state])
        order[sm.initial_state] = 0

        while queue:
            current = queue.popleft()
            current_order = order[current]
            for t in sm.get_transitions_from(current):
                if t.to_state not in order:
                    order[t.to_state] = current_order + 1
                    queue.append(t.to_state)

        return order

    def _compute_entity_differentials(
        self,
        intent_model: IntentModel,
        impl_model: ImplementationModel,
        graph: SemanticGraph,
    ) -> List[StateMachineDifferential]:
        """
        Compute differentials at the entity level (not just state machines).

        Cross-references IntentModel expectations with ImplementationModel
        observations for ALL entities, finding contradictions.
        """
        differentials = []

        # Get all entities that have intent expectations
        all_entity_ids: Set[str] = set()
        for exp in intent_model.expectations:
            all_entity_ids.add(exp.entity_id)

        for entity_id in all_entity_ids:
            expectations = intent_model.get_expectations_for(entity_id)
            observations = impl_model.get_observations_for(entity_id)

            entity_name = expectations[0].entity_name if expectations else entity_id
            file_path = ""
            from chimera.core.semantic_graph import NodeType

            node = graph.get_node(entity_id)
            if node:
                entity_name = node.name
                file_path = node.file_path

            # Check each expectation against observations
            for exp in expectations:
                if exp.expectation_type == "auth":
                    has_no_auth = any(
                        obs.observation_type == "no_auth" for obs in observations
                    )
                    if has_no_auth:
                        differentials.append(StateMachineDifferential(
                            state_machine_name="entity_auth",
                            differential_type="missing_guard",
                            expected=exp.description,
                            observed=(
                                f"No authorization check found on '{entity_name}'. "
                                f"Implementation has no auth decorator, no auth function call, "
                                f"and no auth-related attribute check in the call graph."
                            ),
                            severity=exp.confidence * 0.9,
                            entity_ids=[entity_id],
                            context={
                                "expectation": exp.to_dict(),
                                "observations": [o.to_dict() for o in observations],
                                "vulnerability_class": "privilege_escalation_vertical",
                            },
                            file_path=file_path,
                        ))

                elif exp.expectation_type == "ownership":
                    has_no_ownership = any(
                        obs.observation_type == "no_ownership" for obs in observations
                    )
                    if has_no_ownership:
                        # Guard-kind mismatch: when the handler enforces a ROLE
                        # gate (is_staff/is_admin...) but not ownership, the
                        # unguarded-caller premise is false. The residual claim
                        # — "the gate uses a different principal than intended"
                        # — is materially weaker than pure IDOR.
                        guard_kind_mismatch = False
                        if node is not None:
                            guard_kind_mismatch = bool(
                                node.properties.get("auth_checks")
                                or "auth_checked" in node.semantic_tags
                            )
                        severity = exp.confidence * (0.35 if guard_kind_mismatch else 0.85)
                        observed_text = (
                            f"No ownership verification found on '{entity_name}'. "
                            f"Resource ID parameter is used without comparing against "
                            f"the requesting user's ID."
                        )
                        if guard_kind_mismatch:
                            observed_text += (
                                " Note: a role/attribute guard IS present — this is a "
                                "guard-kind mismatch, not an unguarded endpoint."
                            )
                        differentials.append(StateMachineDifferential(
                            state_machine_name="entity_ownership",
                            differential_type="missing_guard",
                            expected=exp.description,
                            observed=observed_text,
                            severity=severity,
                            entity_ids=[entity_id],
                            context={
                                "expectation": exp.to_dict(),
                                "observations": [o.to_dict() for o in observations],
                                "vulnerability_class": "idor",
                                "guard_kind_mismatch": guard_kind_mismatch,
                            },
                            file_path=file_path,
                        ))

        return differentials
