"""Driver: run the Chimera reasoning loop against a target with full logging."""
import asyncio
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from chimera.core.orchestrator import ChimeraOrchestrator
from chimera.core.world_state import AnalysisConfig

def run_analysis(target: str, dynamic: bool = False, threshold: float = 0.6):
    print(f"\n{'='*70}\nCHIMERA ANALYSIS RUN\ntarget={target} dynamic={dynamic}\n{'='*70}")
    config = AnalysisConfig(
        target_path=target,
        enable_dynamic_analysis=dynamic,
        confidence_threshold=threshold,
        verbose=True,
    )
    orch = ChimeraOrchestrator(config=config)
    summary = orch.analyze()
    return orch, summary

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "tests/targets/vuln_app.py"
    dynamic = "--dynamic" in sys.argv
    orch, summary = run_analysis(target, dynamic)

    print(f"\n{'='*70}\nSUMMARY\n{'='*70}")
    import json
    print(json.dumps(summary, indent=2, default=str))

    st = orch.state
    print(f"\n{'='*70}\nHYPOTHESES ({len(st.hypotheses)})\n{'='*70}")
    for h in st.hypotheses:
        print(f"\n[{h.status.value}] {h.id} conf={h.confidence:.3f}")
        print(f"  class={getattr(h, 'vulnerability_class', '?')} sev={getattr(h, 'severity', '?')}")
        print(f"  claim: {h.claim[:300]}")
        counters = getattr(h, 'counter_hypotheses', [])
        if counters:
            print(f"  counters: {len(counters)}")
        ev = getattr(h, 'supporting_evidence', []) or []
        print(f"  evidence: {len(ev)} items")

    print(f"\nphases: {[p['to'] for p in st.phase_history]}")
    print(f"errors: {st.errors}")
    print(f"warnings: {st.warnings}")
    print(f"confirmed: {st.confirmed_count}  debunked: {st.debunked_count}")
