import sys
from chimera.core.orchestrator import ChimeraOrchestrator

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m chimera <command>")
        print("Commands:")
        print("  analyze <target>    Run causal analysis on target")
        print("  test                Run self-tests")
        sys.exit(1)
    
    cmd = sys.argv[1]
    orchestrator = ChimeraOrchestrator()
    
    if cmd == "analyze":
        target = sys.argv[2] if len(sys.argv) > 2 else "./tests/targets"
        orchestrator.run(target)
    elif cmd == "test":
        print("[chimera] Run pytest separately: pytest tests/ -v")
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == "__main__":
    main()
