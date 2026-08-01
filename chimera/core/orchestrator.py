from typing import List
from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.core.epistemic_engine import EpistemicMonitor
from chimera.core.memory import ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.causal import GrammarModel

from chimera.core.world_state import WorldState
from chimera.core.counterfactual import CounterfactualEngine
from chimera.core.adversarial_sim import AdversarialSimulation
from chimera.core.knowledge_graph import KnowledgeGraph
from chimera.knowledge.taxonomies.cwe import CWETaxonomy
from chimera.knowledge.frameworks.django_security_model import DjangoSecurityModel

class ChimeraOrchestrator:
    """
    The Reasoning Loop:
    1. OBSERVE        -> Gather raw data
    2. MODEL          -> Build parser cascades
    3. HYPOTHESIZE    -> Generate falsifiable claims
    4. INTERROGATE    -> Skeptic challenges
    5. TEST           -> Gather evidence
    6. UPDATE         -> Revise confidence
    7. DECIDE         -> Confirm/reject/iterate
    8. REMEMBER       -> Store in structured memory
    """

    def __init__(self, config_path: str = "configs/default.yaml"):
        self.causal = CausalEngine()
        self.epistemic = EpistemicMonitor(confidence_threshold=0.6)
        self.memory = ChimeraMemory()
        self.config_path = config_path
        self.hypotheses: List[Hypothesis] = []

        # NEW: Reasoning enhancements
        self.world_state = WorldState()
        self.counterfactual = CounterfactualEngine()
        self.adversarial = AdversarialSimulation()
        self.knowledge_graph = KnowledgeGraph()
        
        # NEW: Knowledge bases
        self.cwe_taxonomy = CWETaxonomy()
        self.framework_models = {
            "django": DjangoSecurityModel()
        }

    def run(self, target: str):
        print(f"[CHIMERA] Starting Reasoning Loop on: {target}")
        print("=" * 60)
        
        print("[1] OBSERVE: Gathering target surface...")
        observations = self._observe(target)
        print(f"    -> {len(observations)} raw observations")
        
        print("[2] MODEL: Building parser cascades...")
        cascades = self._build_cascades(target, observations)
        print(f"    -> {len(cascades)} parser cascades modeled")
        
        print("[3] HYPOTHESIZE: Generating falsifiable claims...")
        for cascade in cascades:
            hyps = self.causal.analyze_cascade(cascade, target=target)
            self.hypotheses.extend(hyps)
        print(f"    -> {len(self.hypotheses)} hypotheses generated")
        
        print("[4] INTERROGATE: Skeptic challenges hypotheses...")
        survivors = []
        for hyp in self.hypotheses:
            if self.epistemic.interrogate(hyp):
                hyp.status = "testing"
                survivors.append(hyp)
                print(f"    [PASS] {hyp.id}: {hyp.claim[:60]}...")
            else:
                hyp.status = "rejected"
                print(f"    [FAIL] {hyp.id}: REJECTED")
        print(f"    -> {len(survivors)} survived interrogation")
        
        print("[5] TEST: Gathering runtime evidence...")
        for hyp in survivors:
            self._test_hypothesis(hyp, target)
        
        print("[6] UPDATE: Revising confidence...")
        for hyp in survivors:
            self._update_confidence(hyp)
        
        print("[7] DECIDE: Final classification...")
        confirmed = []
        for hyp in survivors:
            if hyp.confidence > 0.85 and hyp.check_completeness() > 0.8:
                hyp.status = "confirmed"
                confirmed.append(hyp)
            elif hyp.confidence < 0.3:
                hyp.status = "rejected"
        print(f"    -> {len(confirmed)} CONFIRMED")
        
        print("[8] REMEMBER: Storing in structured memory...")
        for hyp in self.hypotheses:
            self.memory.structured.store_hypothesis(hyp)
        print("    -> All hypotheses stored")
        
        self._print_report(confirmed)

         # NEW: Phase 9 - Counterfactual exploration
        print("[9] COUNTERFACTUAL: Exploring what-ifs...")
        for hyp in confirmed:
            variants = self.counterfactual.generate_counterfactuals(hyp)
            print(f"    -> {len(variants)} counterfactual variants generated")
        
        # NEW: Phase 10 - Adversarial hardening
        print("[10] ADVERSARIAL: Red/blue team debate...")
        for hyp in confirmed:
            debate_result = self.adversarial.debate(hyp)
            if debate_result["recommendation"] == "gather_more_evidence":
                hyp.status = "testing"  # Send back for more work
        
        # NEW: Phase 11 - Knowledge graph update
        print("[11] KNOWLEDGE GRAPH: Updating entity model...")
        self.knowledge_graph.add_entity(target, "target", {"type": "web_app"})
        for hyp in confirmed:
            self.knowledge_graph.add_entity(hyp.id, "vulnerability", 
                                            {"claim": hyp.claim, "confidence": hyp.confidence})
            self.knowledge_graph.add_relationship(target, hyp.id, "contains")

    def _observe(self, target: str) -> List[dict]:
        return [{"source": "static", "type": "file", "path": target}]

    def _build_cascades(self, target: str, observations: List[dict]) -> List[List[ParserLayer]]:
        return [[
            ParserLayer(
                name="JSON",
                grammar=GrammarModel(
                    safe_chars={"a","b"," ","'", "\\"},
                    meta_chars={"\\", '"'},
                    escape_rules={"\\": "\\\\", '"': '\\"'}
                ),
                sanitizer="JSON RFC 8259 escape"
            ),
            ParserLayer(
                name="Python_str",
                grammar=GrammarModel(
                    safe_chars={"a","b"," ","'"},
                    meta_chars=set()
                ),
                sanitizer=None
            ),
            ParserLayer(
                name="SQL_literal",
                grammar=GrammarModel(
                    safe_chars={"a","b"," "},
                    meta_chars={"'"}
                ),
                sanitizer=None
            ),
        ]]

    def _test_hypothesis(self, hyp: Hypothesis, target: str):
        from chimera.models.evidence import Evidence
        hyp.add_evidence(Evidence(
            source="static_analysis",
            data={"finding": "f-string query construction detected"},
            confidence=0.8,
            metadata={"file": target}
        ))

    def _update_confidence(self, hyp: Hypothesis):
        if not hyp.evidence:
            return
        total_conf = sum(e.confidence for e in hyp.evidence)
        avg_conf = total_conf / len(hyp.evidence)
        missing_penalty = 0.1 * len(hyp.missing_information)
        hyp.confidence = max(0.0, min(1.0, avg_conf - missing_penalty))

    def _print_report(self, confirmed: List[Hypothesis]):
        print("\n" + "=" * 60)
        print("CHIMERA REASONING LOOP REPORT")
        print("=" * 60)
        print(f"Total hypotheses generated: {len(self.hypotheses)}")
        print(f"Confirmed: {len(confirmed)}")
        print(f"Rejected: {sum(1 for h in self.hypotheses if h.status == 'rejected')}")
        print(f"In testing: {sum(1 for h in self.hypotheses if h.status == 'testing')}")
        
        if confirmed:
            print("\n--- CONFIRMED FINDINGS ---")
            for hyp in confirmed:
                print(f"\n[{hyp.id}] {hyp.claim[:80]}")
                print(f"    Confidence: {hyp.confidence:.2f}")
                print(f"    Evidence: {len(hyp.evidence)} items")
                print(f"    Missing: {len(hyp.missing_information)} items")
        print("=" * 60)
