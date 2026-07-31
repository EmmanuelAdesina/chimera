from chimera.core.memory import StructuredMemory, ChimeraMemory
from chimera.models.hypothesis import Hypothesis
from chimera.models.evidence import Evidence

def test_structured_memory_roundtrip(tmp_path):
    db = tmp_path / 'test.db'
    mem = StructuredMemory(db_path=str(db))
    hyp = Hypothesis(id='HYP-TEST-001', claim='Test claim', confidence=0.8, evidence=[Evidence(source='test', data='x')])
    mem.store_hypothesis(hyp)
    retrieved = mem.get_hypothesis('HYP-TEST-001')
    assert retrieved is not None
    assert retrieved.claim == 'Test claim'
    assert retrieved.confidence == 0.8

def test_chimera_memory_has_both_planes():
    mem = ChimeraMemory(db_path=':memory:')
    assert mem.structured is not None
    assert mem.semantic is not None
