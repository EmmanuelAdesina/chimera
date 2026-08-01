import pytest
from chimera.core.causal_engine import CausalEngine, ParserLayer
from chimera.models.causal import GrammarModel

class TestCausalEngine:
    def test_json_python_sql_differential(self):
        layers = [
            ParserLayer(
                name="JSON",
                grammar=GrammarModel(
                    safe_chars={"a", "b", "'", "\\", " "},
                    meta_chars={"\\", '"'},
                    escape_rules={"\\": "\\\\", '"': '\\"'}
                ),
                sanitizer="JSON RFC 8259 escape"
            ),
            ParserLayer(
                name="Python_str",
                grammar=GrammarModel(
                    safe_chars={"a", "b", "'", " "},
                    meta_chars=set()
                ),
                sanitizer=None
            ),
            ParserLayer(
                name="SQL_literal",
                grammar=GrammarModel(
                    safe_chars={"a", "b", " "},
                    meta_chars={"'"}
                ),
                sanitizer=None
            ),
        ]

        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers, target="test")

        assert len(hyps) == 1
        assert hyps[0].status == "proposed"
        assert "'" in hyps[0].claim
        assert len(hyps[0].required_conditions) == 4

    def test_no_differential_with_sanitizer(self):
        layers = [
            ParserLayer(
                name="Input",
                grammar=GrammarModel(safe_chars={"'"}, meta_chars=set()),
                sanitizer="parameterized_query"
            ),
            ParserLayer(
                name="SQL",
                grammar=GrammarModel(safe_chars=set(), meta_chars={"'"}),
                sanitizer=None
            ),
        ]

        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers)
        assert len(hyps) == 0

    def test_hypothesis_has_falsifiers(self):
        layers = [
            ParserLayer(name="A", grammar=GrammarModel(safe_chars={";"}, meta_chars=set()), sanitizer=None),
            ParserLayer(name="B", grammar=GrammarModel(safe_chars=set(), meta_chars={";"}), sanitizer=None),
        ]
        engine = CausalEngine()
        hyps = engine.analyze_cascade(layers)
        assert len(hyps) == 1
        assert len(hyps[0].falsifiers) > 0
