"""Unit tests for the ChimeraOrchestrator analysis loop."""

from __future__ import annotations

import os

import pytest

from chimera.core.orchestrator import ChimeraOrchestrator
from chimera.core.world_state import AnalysisConfig
from chimera.models.hypothesis import HypothesisStatus


class TestSummaryContract:
    """The result structure is a public API — it must match its contract."""

    def test_summary_structure(self, vuln_orders_path):
        result = ChimeraOrchestrator(AnalysisConfig(target_path=vuln_orders_path)).analyze()
        # Counts
        assert isinstance(result["files_parsed"], int)
        assert isinstance(result["error_count"], int)
        assert isinstance(result["total_hypotheses"], int)
        # Detail lists (previously these were bare ints — the structure bug)
        assert isinstance(result["errors"], list)
        assert isinstance(result["warnings"], list)
        assert isinstance(result["hypotheses"], list)
        assert isinstance(result["confirmed_vulnerabilities"], list)
        assert isinstance(result["flagged_findings"], list)
        assert result["phase"] == "complete"
        assert result["completed_at"] is not None

    def test_pending_dynamic_confirmation_static_marker(self, vuln_orders_path):
        """Decorator-less service code yields honest static-only plans:
        nothing is falsely reported as dispatchable."""
        result = ChimeraOrchestrator(AnalysisConfig(target_path=vuln_orders_path)).analyze()
        assert isinstance(result["pending_dynamic_confirmation"], list)
        assert isinstance(result["pending_dynamic_confirmation_count"], int)
        assert result["pending_dynamic_confirmation_count"] >= len(
            result["pending_dynamic_confirmation"]
        )
        # vuln_orders has no route decorators → honest static marker, and
        # the summary must NOT claim dispatchable live-target plans exist.
        assert result["confirmed_vulnerabilities"]  # analysis still works
        assert result["pending_dynamic_confirmation"] == []

    def test_pending_dynamic_confirmation_real_routes(self, tmp_path):
        """Decorated handlers produce dispatchable plans with real route URLs,
        and those plans are surfaced in the summary."""
        app = tmp_path / "route_app.py"
        app.write_text(
            "from flask import Flask, jsonify\n"
            "app = Flask(__name__)\n"
            "ORDERS = {1: {'id': 1, 'owner': 'alice'}}\n\n"
            "@app.route('/orders/<int:order_id>', methods=['GET'])\n"
            "def get_order(order_id):\n"
            "    return jsonify(ORDERS.get(order_id))\n",
            encoding="utf-8",
        )
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=str(tmp_path), base_url="http://example.test")
        ).analyze()
        pending = result["pending_dynamic_confirmation"]
        assert pending, result["hypotheses"]
        assert result["pending_dynamic_confirmation_count"] == len(pending)
        for entry in pending:
            assert set(entry) == {
                "hypothesis_id",
                "method",
                "target_url",
                "expected_outcome",
                "falsifying_outcome",
            }
            assert entry["hypothesis_id"]
            assert entry["method"] == "GET"
            assert entry["target_url"] == "http://example.test/orders/<int:order_id>"

    def test_pending_dynamic_confirmation_present_on_empty_runs(self, tmp_path):
        """Key exists even when the experimentation phase returns early."""
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=str(tmp_path))
        ).analyze()
        assert result["pending_dynamic_confirmation"] == []
        assert result["pending_dynamic_confirmation_count"] == 0

    def test_run_alias(self, vuln_app_path):
        orch = ChimeraOrchestrator()
        result = orch.run(vuln_app_path)  # legacy entrypoint compatibility
        assert result["phase"] == "complete"
        assert result["files_parsed"] == 1


class TestResilience:
    def test_missing_target_does_not_crash(self):
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path="/nonexistent/path/xyz.py")
        ).analyze()
        assert result["phase"] == "complete"
        assert result["files_parsed"] == 0
        assert result["warning_count"] >= 1

    def test_broken_python_file_recorded_not_fatal(self, tmp_path):
        bad = tmp_path / "broken.py"
        bad.write_text("def broken(:\n    pass\n")
        good = tmp_path / "good.py"
        good.write_text("def f(a):\n    return a\n")
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=str(tmp_path))
        ).analyze()
        assert result["phase"] == "complete"
        assert result["files_parsed"] == 1
        assert result["parse_errors"] == 1
        assert "broken.py" in next(iter(result["parse_error_details"]))

    def test_syntax_error_message_has_context(self, tmp_path):
        bad = tmp_path / "bad.py"
        bad.write_text("def f(:\n")
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=str(tmp_path))
        ).analyze()
        detail = next(iter(result["parse_error_details"].values()))
        assert "bad.py" in detail
        assert "ParseError" in detail or "invalid syntax" in detail

    def test_empty_directory(self, tmp_path):
        result = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
        assert result["phase"] == "complete"
        assert result["total_hypotheses"] == 0

    def test_mixed_cascade_directory(self, tmp_path):
        (tmp_path / "app.py").write_text("def f(a):\n    return a\n")
        (tmp_path / "schema.sql").write_text(
            "CREATE TABLE t (id INTEGER PRIMARY KEY);\n"
        )
        (tmp_path / "broken.py").write_text("def (:\n")
        (tmp_path / "notes.txt").write_text("not parsed")
        result = ChimeraOrchestrator(AnalysisConfig(target_path=str(tmp_path))).analyze()
        assert result["files_parsed"] == 2
        assert result["parse_errors"] == 1


class TestReasoningResults:
    def test_vulnerable_app_produces_confirmed(self, vuln_orders_path):
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=vuln_orders_path)
        ).analyze()
        assert result["error_count"] == 0
        assert result["total_hypotheses"] >= 6
        assert result["confirmed"] >= 5

    def test_guarded_app_confirms_nothing(self, safe_orders_path):
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=safe_orders_path)
        ).analyze()
        assert result["error_count"] == 0
        assert result["confirmed"] == 0

    def test_differential_discriminates(self, vuln_orders_path, safe_orders_path):
        """The core anti-blindness invariant: vulnerable > guarded."""
        vuln = ChimeraOrchestrator(
            AnalysisConfig(target_path=vuln_orders_path)
        ).analyze()
        safe = ChimeraOrchestrator(
            AnalysisConfig(target_path=safe_orders_path)
        ).analyze()
        assert vuln["total_hypotheses"] > safe["total_hypotheses"]
        assert vuln["confirmed"] > safe["confirmed"]

    def test_hypotheses_carry_evidence_and_falsifiers(self, vuln_orders_path):
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=vuln_orders_path)
        ).analyze()
        for h in result["hypotheses"]:
            assert h["evidence_count"] >= 1, f"{h['id']} has no evidence"
            assert h["falsifiers"], f"{h['id']} has no falsifiers"

    def test_status_machine_respected(self, vuln_orders_path):
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=vuln_orders_path)
        ).analyze()
        by_status = {}
        for h in result["hypotheses"]:
            by_status.setdefault(h["status"], 0)
            by_status[h["status"]] += 1
        # terminal states are consistent with counts
        confirmed = by_status.get("confirmed", 0)
        assert confirmed == result["confirmed"]

    def test_experiments_actually_ran(self, vuln_orders_path):
        """The loop must close: static verification probes execute."""
        result = ChimeraOrchestrator(
            AnalysisConfig(target_path=vuln_orders_path)
        ).analyze()
        assert result["experiments_run"] >= 1
