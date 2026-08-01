from chimera.core.orchestrator import ChimeraOrchestrator

def test_reasoning_loop_runs():
    orch = ChimeraOrchestrator()
    orch.run("tests/targets/vuln_app.py")
