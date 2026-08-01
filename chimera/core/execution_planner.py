# chimera/core/execution_planner.py

from typing import Dict, List, Optional
from dataclasses import dataclass

from chimera.models.hypothesis import Hypothesis

@dataclass
class Experiment:
    name: str
    hypothesis_id: str
    capability: str  # "browser_automation", "controlled_testing", etc.
    cost: float  # Estimated compute/time cost
    expected_info_gain: float  # 0-1, how much this will reduce uncertainty
    detection_risk: float  # 0-1, probability of triggering alerts
    prerequisites: List[str]

class ExecutionPlanner:
    """
    The diagram's 'Execution Planner' — choose cheapest experiment
    that maximizes information gain and minimizes detection.
    """
    
    def __init__(self):
        self.experiment_history: List[Experiment] = []
    
    def plan_experiments(self, hypotheses: List[Hypothesis]) -> List[Experiment]:
        """
        Given hypotheses, generate candidate experiments and rank them.
        """
        candidates = []
        
        for hyp in hypotheses:
            if hyp.status != "testing":
                continue
            
            # Generate experiments based on missing information
            for missing in hyp.missing_information:
                if "runtime" in missing.lower():
                    candidates.append(Experiment(
                        name=f"Runtime test for {hyp.id}",
                        hypothesis_id=hyp.id,
                        capability="controlled_testing",
                        cost=0.3,
                        expected_info_gain=0.4,
                        detection_risk=0.2,
                        prerequisites=["Target reachable"]
                    ))
                
                if "WAF" in missing:
                    candidates.append(Experiment(
                        name=f"WAF probe for {hyp.id}",
                        hypothesis_id=hyp.id,
                        capability="browser_automation",
                        cost=0.5,
                        expected_info_gain=0.3,
                        detection_risk=0.4,
                        prerequisites=["HTTP endpoint known"]
                    ))
                
                if "authentication" in missing.lower():
                    candidates.append(Experiment(
                        name=f"Auth check for {hyp.id}",
                        hypothesis_id=hyp.id,
                        capability="observation",
                        cost=0.1,
                        expected_info_gain=0.2,
                        detection_risk=0.05,
                        prerequisites=[]
                    ))
        
        # Rank by: expected_info_gain / (cost + detection_risk)
        # This maximizes learning per unit of risk spent
        candidates.sort(
            key=lambda e: e.expected_info_gain / (e.cost + e.detection_risk + 0.01),
            reverse=True
        )
        
        return candidates
    
    def select_next(self, candidates: List[Experiment], budget_remaining: float) -> Optional[Experiment]:
        """Pick the best experiment that fits remaining budget."""
        for exp in candidates:
            if exp.cost <= budget_remaining:
                self.experiment_history.append(exp)
                return exp
        return None
    
    def update_from_result(self, experiment: Experiment, result: Dict):
        """Learn from experiment outcome to improve future planning."""
        # If experiment succeeded, similar ones should have higher expected gain
        # If failed, reduce gain for similar experiments
        pass