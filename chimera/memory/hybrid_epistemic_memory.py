"""Hybrid sparse/dense memory with phase-based temporal decay."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Tuple

try:
    from rank_bm25 import BM25Okapi
except ImportError:  # optional dependency
    BM25Okapi = None  # type: ignore[misc,assignment]


class HybridEpistemicMemory:
    def __init__(self, collection: Any = None, decay_lambda: float = 0.05) -> None:
        if decay_lambda < 0:
            raise ValueError("decay_lambda must be non-negative")
        self.collection = collection
        self.decay_lambda = decay_lambda
        self.phase_epoch = 0
        self.corpus: List[List[str]] = []
        self.document_ids: List[str] = []
        self.bm25: Any = None

    def advance_phase(self, count: int = 1) -> None:
        self.phase_epoch += max(0, count)

    def temporal_decay(self, base_score: float, creation_epoch: int) -> float:
        return base_score * math.exp(-self.decay_lambda * max(0, self.phase_epoch - creation_epoch))

    def index(self, documents: List[Tuple[str, str]]) -> None:
        self.document_ids = [doc_id for doc_id, _ in documents]
        self.corpus = [text.lower().split() for _, text in documents]
        self.bm25 = BM25Okapi(self.corpus) if BM25Okapi and self.corpus else None

    def hybrid_search(self, query: str, k: int = 5) -> List[Tuple[str, float]]:
        if k <= 0:
            return []
        if self.collection is None:
            scores = self.bm25.get_scores(query.lower().split()) if self.bm25 else [0.0] * len(self.document_ids)
            return sorted(zip(self.document_ids, scores), key=lambda item: item[1], reverse=True)[:k]
        result: Dict[str, float] = {}
        raw = self.collection.query(query_texts=[query], n_results=k, include=["distances", "metadatas"])
        ids = raw.get("ids", [[]])[0]
        distances = raw.get("distances", [[]])[0]
        metadata = raw.get("metadatas", [[]])[0]
        sparse = self.bm25.get_scores(query.lower().split()) if self.bm25 else []
        sparse_by_id = dict(zip(self.document_ids, sparse))
        max_sparse = max(sparse, default=0.0)
        for doc_id, distance, meta in zip(ids, distances, metadata):
            dense_score = max(0.0, 1.0 - float(distance))
            sparse_score = sparse_by_id.get(doc_id, 0.0)
            if max_sparse > 0:
                sparse_score /= max_sparse
            epoch = int((meta or {}).get("creation_epoch", self.phase_epoch))
            result[doc_id] = self.temporal_decay(0.7 * dense_score + 0.3 * sparse_score, epoch)
        return sorted(result.items(), key=lambda item: item[1], reverse=True)[:k]
