"""Chimera CLI — `python -m chimera`.

Commands
--------
    analyze <path>     Run the full reasoning loop against a file or directory.
    version            Print the Chimera version.

Examples
--------
    python -m chimera analyze tests/targets/vuln_app.py
    python -m chimera analyze ./my_service --threshold 0.65 --json report.json
    python -m chimera analyze ./app --dynamic --base-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, List, Optional

import chimera
from chimera.core.orchestrator import ChimeraOrchestrator
from chimera.core.world_state import AnalysisConfig


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chimera",
        description="Closed-loop causal reasoning engine for offensive security.",
    )
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser(
        "analyze", help="Run the full analysis loop against a target path."
    )
    analyze.add_argument("target", help="File or directory to analyze.")
    analyze.add_argument(
        "--threshold",
        type=float,
        default=0.6,
        help="Confidence threshold for CONFIRMED findings (default: 0.6).",
    )
    analyze.add_argument(
        "--budget",
        type=int,
        default=20,
        help="Experiment budget (max plans + static probes, default: 20).",
    )
    analyze.add_argument(
        "--max-hypotheses",
        type=int,
        default=50,
        help="Cap on generated hypotheses (default: 50).",
    )
    analyze.add_argument(
        "--dynamic",
        action="store_true",
        help="Enable dynamic analysis (experiment plans marked dispatchable).",
    )
    analyze.add_argument(
        "--base-url",
        default="",
        help="Base URL of a live target for dispatchable experiment plans.",
    )
    analyze.add_argument(
        "--version-tag",
        default="",
        help="Target version/commit hash recorded on each hypothesis.",
    )
    analyze.add_argument(
        "--json",
        dest="json_path",
        default="",
        help="Write the full JSON report to this path.",
    )
    analyze.add_argument(
        "--quiet", action="store_true", help="Only print the JSON summary."
    )
    analyze.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=(
            "Exit 1 when confirmed vulnerabilities are found (CI gating). "
            "Default exit codes stay 0 on successful analysis and 2 on "
            "usage/IO errors."
        ),
    )
    analyze.add_argument("-v", "--verbose", action="store_true", help="Verbose logging.")

    sub.add_parser("version", help="Print version information.")
    return parser


def _print_report(summary: Dict[str, Any]) -> None:
    print("=" * 72)
    print("CHIMERA ANALYSIS REPORT")
    print("=" * 72)
    print(f"Target:        {summary.get('target')}")
    print(f"Files parsed:  {summary['files_parsed']}  (parse errors: {summary['parse_errors']})")
    print(
        f"Differentials: {summary['differentials_found']}   "
        f"Hypotheses: {summary['total_hypotheses']}   "
        f"Experiments(static): {summary['experiments_run']}"
    )
    print(
        f"Confirmed: {summary['confirmed']}   Flagged: {len(summary.get('flagged_findings', []))}   "
        f"Debunked: {summary['debunked']}   Rejected: {summary['rejected']}"
    )
    print(f"Errors: {summary['error_count']}   Warnings: {summary['warning_count']}")

    confirmed = summary.get("confirmed_vulnerabilities", [])
    if confirmed:
        print("\n--- CONFIRMED VULNERABILITIES ---")
        for h in confirmed:
            print(f"  [{h['severity'].upper():>8}] [{h['vulnerability_class']}] "
                  f"conf={h['confidence']:.2f}  {h['file_path']}")
            print(f"           {h['claim'][:150]}")

    flagged = summary.get("flagged_findings", [])
    if flagged:
        print("\n--- FLAGGED (below confirmation threshold) ---")
        for f in flagged:
            print(f"  conf={f['confidence']:.2f} [{f['vulnerability_class']}] "
                  f"{f['file_path']} :: {f['summary'][:110]}")

    if summary.get("errors"):
        print("\n--- ERRORS ---")
        for e in summary["errors"][:20]:
            print(f"  ! {e}")
    print("=" * 72)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"chimera {chimera.__version__}")
        return 0

    if args.command != "analyze":
        parser.print_help()
        return 2

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    config = AnalysisConfig(
        target_path=args.target,
        target_version=args.version_tag,
        confidence_threshold=args.threshold,
        experiment_budget=args.budget,
        max_hypotheses=args.max_hypotheses,
        enable_dynamic_analysis=bool(args.dynamic),
        base_url=args.base_url or "http://localhost:8000",
        verbose=args.verbose,
    )

    orchestrator = ChimeraOrchestrator(config)
    summary = orchestrator.analyze()

    if args.json_path:
        try:
            with open(args.json_path, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2, default=str)
        except OSError as exc:
            print(f"error: cannot write JSON report: {exc}", file=sys.stderr)
            return 2

    if args.quiet:
        print(json.dumps(summary, indent=2, default=str))
    else:
        _print_report(summary)
        if args.json_path:
            print(f"\nJSON report written to {args.json_path}")

    if args.fail_on_findings and summary.get("confirmed_vulnerabilities"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
