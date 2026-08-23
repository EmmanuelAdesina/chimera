"""End-to-end integration tests — the full reasoning loop on real targets."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from chimera.core.orchestrator import ChimeraOrchestrator
from chimera.core.world_state import AnalysisConfig


VULN_APP = "tests/targets/vuln_orders_app.py"
SAFE_APP = "tests/targets/safe_orders_app.py"
LEGACY_APP = "tests/targets/vuln_app.py"


def test_reasoning_loop_runs(vuln_app_path):
    """The original integration contract: the loop runs end to end."""
    orch = ChimeraOrchestrator(AnalysisConfig(target_path=vuln_app_path))
    result = orch.analyze()
    assert result["phase"] == "complete"
    assert result["files_parsed"] == 1
    assert result["error_count"] == 0


def test_vulnerable_vs_guarded_differential():
    """
    THE anti-blindness test.

    A vulnerable service and its fully-guarded twin must NOT produce the same
    findings. If they ever agree again, guard detection has gone blind.
    """
    vuln = ChimeraOrchestrator(AnalysisConfig(target_path=VULN_APP)).analyze()
    safe = ChimeraOrchestrator(AnalysisConfig(target_path=SAFE_APP)).analyze()

    assert vuln["confirmed"] >= 5, (
        f"expected >= 5 confirmed findings on the vulnerable app, "
        f"got {vuln['confirmed']}"
    )
    assert safe["confirmed"] == 0, (
        f"expected 0 confirmed findings on the guarded app, got {safe['confirmed']}: "
        f"{[h['claim'][:80] for h in safe['confirmed_vulnerabilities']]}"
    )
    assert vuln["total_hypotheses"] > safe["total_hypotheses"]


def test_every_planted_flaw_found():
    """Each planted vulnerable function must appear in some confirmed claim."""
    result = ChimeraOrchestrator(AnalysisConfig(target_path=VULN_APP)).analyze()
    blob = " ".join(h["claim"] for h in result["hypotheses"])
    for fn in ("get_order", "delete_order", "admin_dashboard", "approve_refund"):
        assert f"'{fn}'" in blob, f"{fn} not covered by any hypothesis"


def test_confirmed_findings_have_full_provenance():
    result = ChimeraOrchestrator(AnalysisConfig(target_path=VULN_APP)).analyze()
    for h in result["confirmed_vulnerabilities"]:
        assert h["evidence_count"] >= 2  # static + verification evidence
        assert h["status"] == "confirmed"
        assert h["confidence"] >= 0.6
        assert h["causal_chain"]


def test_legacy_grammar_differential_target_still_parses():
    result = ChimeraOrchestrator(AnalysisConfig(target_path=LEGACY_APP)).analyze()
    assert result["phase"] == "complete"
    assert result["files_parsed"] == 1
    assert result["error_count"] == 0


def test_cli_analyze_quiet_json():
    proc = subprocess.run(
        [sys.executable, "-m", "chimera", "analyze", VULN_APP, "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["confirmed"] >= 5
    assert summary["phase"] == "complete"


def test_cli_analyze_human_report():
    proc = subprocess.run(
        [sys.executable, "-m", "chimera", "analyze", SAFE_APP],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert "CHIMERA ANALYSIS REPORT" in proc.stdout
    assert "Confirmed: 0" in proc.stdout


def test_cli_write_json_report(tmp_path):
    out = tmp_path / "report.json"
    proc = subprocess.run(
        [sys.executable, "-m", "chimera", "analyze", VULN_APP, "--json", str(out)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["confirmed"] >= 5


def test_cli_fail_on_findings_exit_codes():
    """--fail-on-findings: exit 1 with confirmed vulns, 0 on a clean target."""
    vuln = subprocess.run(
        [sys.executable, "-m", "chimera", "analyze", VULN_APP,
         "--quiet", "--fail-on-findings"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert vuln.returncode == 1, vuln.stderr
    assert json.loads(vuln.stdout)["confirmed"] >= 5

    safe = subprocess.run(
        [sys.executable, "-m", "chimera", "analyze", SAFE_APP,
         "--quiet", "--fail-on-findings"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert safe.returncode == 0, safe.stderr
    assert json.loads(safe.stdout)["confirmed"] == 0
