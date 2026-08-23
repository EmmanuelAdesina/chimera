"""Unit tests for Chimera memory (structured plane + facade)."""

from __future__ import annotations

from chimera.core.memory import ChimeraMemory, SemanticMemory, StructuredMemory
from chimera.models.hypothesis import Hypothesis, VulnerabilityClass


class TestStructuredMemory:
    def test_roundtrip(self):
        mem = StructuredMemory()
        mem.put("k", {"v": 1}, category="pattern")
        assert mem.get("k") == {"v": 1}
        assert mem.get("missing") is None

    def test_persistence(self, tmp_path):
        path = str(tmp_path / "mem.json")
        mem = StructuredMemory(persist_path=path)
        mem.put("k", [1, 2, 3], category="pattern")
        reloaded = StructuredMemory(persist_path=path)
        assert reloaded.get("k") == [1, 2, 3]

    def test_categories(self):
        mem = StructuredMemory()
        mem.put("a", 1, category="pattern")
        mem.put("b", 2, category="result")
        assert [e.key for e in mem.get_by_category("pattern")] == ["a"]

    def test_store_and_get_hypothesis(self):
        mem = StructuredMemory()
        h = Hypothesis(claim="Test claim", confidence=0.8)
        key = mem.store_hypothesis(h)
        assert key == f"hypothesis:{h.id}"
        retrieved = mem.get_hypothesis(h.id)
        assert retrieved is not None
        assert retrieved["claim"] == "Test claim"
        assert retrieved["confidence"] == 0.8

    def test_store_hypothesis_rejects_junk(self):
        mem = StructuredMemory()
        try:
            mem.store_hypothesis(42)
        except TypeError:
            pass
        else:
            raise AssertionError("expected TypeError")

    def test_delete(self):
        mem = StructuredMemory()
        mem.put("x", 1, category="pattern")
        assert mem.delete("x") is True
        assert mem.get("x") is None
        assert mem.delete("x") is False


class TestSemanticMemory:
    def test_fallback_store_and_search(self):
        mem = SemanticMemory()  # chromadb absent in CI -> fallback
        mem.initialize()
        mem.store(
            "idor missing ownership check on order endpoint",
            metadata={"vulnerability_class": "idor"},
        )
        results = mem.search("ownership check idor", n_results=3)
        assert results
        assert results[0]["score"] > 0

    def test_search_filter(self):
        mem = SemanticMemory()
        mem.initialize()
        mem.store("idor pattern ctx", metadata={"vulnerability_class": "idor"})
        mem.store("xss pattern ctx", metadata={"vulnerability_class": "xss"})
        results = mem.search("pattern", filter_dict={"vulnerability_class": "idor"})
        assert all(r["metadata"]["vulnerability_class"] == "idor" for r in results)

    def test_store_hypothesis(self):
        mem = SemanticMemory()
        mem.initialize()
        h = Hypothesis(
            claim="Missing ownership on orders",
            vulnerability_class=VulnerabilityClass.IDOR,
        )
        doc_id = mem.store_hypothesis(h)
        assert doc_id.startswith("hyp-")


class TestChimeraMemoryFacade:
    def test_has_both_planes(self):
        mem = ChimeraMemory()
        assert mem.structured is not None
        assert mem.semantic is not None

    def test_store_and_recall(self):
        mem = ChimeraMemory()
        mem.initialize()
        h = Hypothesis(
            claim="IDOR on /orders/<id>",
            confidence=0.7,
            vulnerability_class=VulnerabilityClass.IDOR,
            file_path="app.py",
        )
        key = mem.store_hypothesis(h)
        assert mem.get_hypothesis(h.id) is not None
        similar = mem.recall_similar("orders ownership idor", vuln_class="idor")
        assert isinstance(similar, list)

    def test_stats_shape(self):
        mem = ChimeraMemory()
        stats = mem.stats()
        assert {"structured", "semantic", "initialized"} <= set(stats)

    def test_result_roundtrip(self):
        mem = ChimeraMemory()
        mem.record_result("/tmp/app", "v1.2.3", {"confirmed": 3})
        assert mem.get_result("/tmp/app", "v1.2.3") == {"confirmed": 3}
