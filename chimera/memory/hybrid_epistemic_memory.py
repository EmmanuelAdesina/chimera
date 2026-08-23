"""
Hybrid epistemic memory.

Combines:
- dense semantic retrieval from Chimera core SemanticMemory
- sparse lexical retrieval inspired by BM25
- temporal decay to reduce stale-memory dominance during long autonomous runs

This class wraps chimera.core.memory.SemanticMemory without requiring changes to
the existing memory.py file.
"""

from __future__ import annotations

import math
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from chimera.core.memory import SemanticMemory


def _tokens(text: str) -> List[str]:
    return re.findall(r"[A-Za-z0-9_.$:/-]+", text.lower())


@dataclass
class HybridMemoryDocument:
    id: str
    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_epoch: float = field(default_factory=time.time)


class HybridEpistemicMemory:
    def __init__(
        self,
        semantic_memory: Optional[SemanticMemory] = None,
        decay_lambda: float = 0.015,
        dense_weight: float = 0.65,
        sparse_weight: float = 0.35,
    ) -> None:
        self.semantic = semantic_memory or SemanticMemory()
        self.decay_lambda = decay_lambda
        self.dense_weight = dense_weight
        self.sparse_weight = sparse_weight
        self.documents: Dict[str, HybridMemoryDocument] = {}

    def store(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
        doc_id: Optional[str] = None,
    ) -> str:
        metadata = dict(metadata or {})
        doc_id = doc_id or f"hyb-{uuid.uuid4().hex[:12]}"
        created_epoch = float(metadata.get("created_epoch", time.time()))
        metadata.setdefault("created_epoch", created_epoch)
        metadata.setdefault("created_at", datetime.utcfromtimestamp(created_epoch).isoformat())

        self.documents[doc_id] = HybridMemoryDocument(
            id=doc_id,
            text=text,
            metadata=metadata,
            created_epoch=created_epoch,
        )

        self.semantic.store(text, metadata=metadata, doc_id=doc_id)
        return doc_id

    def search(
        self,
        query: str,
        n_results: int = 5,
        filter_dict: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        dense = self.semantic.search(query, n_results=max(n_results * 4, 10), filter_dict=filter_dict)
        dense_by_id = {item["id"]: item for item in dense}

        sparse = self._sparse_search(query, filter_dict)
        sparse_by_id = {item["id"]: item for item in sparse}

        all_ids = set(dense_by_id) | set(sparse_by_id)
        fused: List[Dict[str, Any]] = []

        for doc_id in all_ids:
            dense_score = float(dense_by_id.get(doc_id, {}).get("score", 0.0))
            sparse_score = float(sparse_by_id.get(doc_id, {}).get("score", 0.0))
            doc = self.documents.get(doc_id)

            metadata = {}
            text = ""
            created_epoch = time.time()

            if doc is not None:
                metadata = doc.metadata
                text = doc.text
                created_epoch = doc.created_epoch
            elif doc_id in dense_by_id:
                metadata = dense_by_id[doc_id].get("metadata", {})
                text = dense_by_id[doc_id].get("text", "")
                created_epoch = float(metadata.get("created_epoch", time.time()))

            fused_score = (self.dense_weight * dense_score) + (self.sparse_weight * sparse_score)
            fused_score = self._apply_decay(fused_score, created_epoch)

            fused.append({
                "id": doc_id,
                "text": text,
                "metadata": metadata,
                "score": fused_score,
                "dense_score": dense_score,
                "sparse_score": sparse_score,
            })

        fused.sort(key=lambda item: item["score"], reverse=True)
        return fused[:n_results]

    def _sparse_search(
        self,
        query: str,
        filter_dict: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        query_tokens = _tokens(query)
        if not query_tokens:
            return []

        query_set = set(query_tokens)
        results: List[Dict[str, Any]] = []

        for doc in self.documents.values():
            if filter_dict and not all(doc.metadata.get(k) == v for k, v in filter_dict.items()):
                continue

            doc_tokens = _tokens(doc.text)
            if not doc_tokens:
                continue

            doc_set = set(doc_tokens)
            overlap = len(query_set & doc_set)
            if overlap == 0:
                continue

            # Lightweight BM25-like scoring without mandatory external deps.
            score = overlap / math.sqrt(len(doc_set) * len(query_set))
            results.append({
                "id": doc.id,
                "text": doc.text,
                "metadata": doc.metadata,
                "score": score,
            })

        results.sort(key=lambda item: item["score"], reverse=True)
        return results

    def _apply_decay(self, score: float, created_epoch: float) -> float:
        age_hours = max(0.0, (time.time() - created_epoch) / 3600.0)
        return score * math.exp(-self.decay_lambda * age_hours)

    def store_hypothesis(self, hypothesis: Any) -> str:
        text = getattr(hypothesis, "claim", str(hypothesis))
        vuln_class = getattr(getattr(hypothesis, "vulnerability_class", None), "value", "unknown")
        status = getattr(getattr(hypothesis, "status", None), "value", "unknown")
        confidence = getattr(hypothesis, "confidence", 0.0)
        file_path = getattr(hypothesis, "file_path", "")

        return self.store(
            text,
            metadata={
                "vulnerability_class": vuln_class,
                "status": status,
                "confidence": confidence,
                "file_path": file_path,
            },
            doc_id=f"hyp-{getattr(hypothesis, 'id', uuid.uuid4().hex[:12])}",
        )
