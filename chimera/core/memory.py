"""Chimera Memory System — Memory is the Moat.

Dual memory architecture:
    1. StructuredMemory — Key-value store for confirmed patterns, past results,
       calibration data. Fast exact lookups.
    2. SemanticMemory — Vector embeddings for cross-target pattern retrieval.
       Finds structurally similar vulnerabilities across different codebases.

Uses ChromaDB for vector storage (embedded, zero-config).
Memory is the competitive moat: the more targets Chimera analyzes,
the better it gets at recognizing vulnerability patterns.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
import json
import hashlib
import uuid


# ==================================================================
# Structured Memory — Fast exact-lookup key-value store
# ==================================================================


@dataclass
class MemoryEntry:
    """A single entry in structured memory."""
    key: str
    value: Any
    category: str  # "pattern", "result", "calibration", "config"
    target_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class StructuredMemory:
    """
    Key-value store for structured, exact-lookup data.

    Stores:
    - Confirmed vulnerability patterns (keyed by pattern hash)
    - Past analysis results (keyed by target path + version)
    - Calibration records for the Epistemic Engine
    - Configuration learned from past analyses
    """

    def __init__(self, persist_path: Optional[str] = None) -> None:
        self._store: Dict[str, MemoryEntry] = {}
        self._category_index: Dict[str, List[str]] = {}
        self.persist_path = persist_path
        if persist_path:
            self._load()

    def put(self, key: str, value: Any, category: str = "pattern",
             target_id: str = "", metadata: Optional[Dict] = None) -> str:
        """Store a value. Returns the storage key."""
        entry = MemoryEntry(
            key=key, value=value, category=category,
            target_id=target_id, metadata=metadata or {},
        )
        self._store[key] = entry
        self._category_index.setdefault(category, []).append(key)
        if self.persist_path:
            self._save()
        return key

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value by key."""
        entry = self._store.get(key)
        return entry.value if entry else default

    def get_entry(self, key: str) -> Optional[MemoryEntry]:
        """Retrieve a full entry by key."""
        return self._store.get(key)

    def get_by_category(self, category: str) -> List[MemoryEntry]:
        """Get all entries in a category."""
        keys = self._category_index.get(category, [])
        return [self._store[k] for k in keys if k in self._store]

    def delete(self, key: str) -> bool:
        """Delete an entry."""
        entry = self._store.pop(key, None)
        if entry:
            cat_keys = self._category_index.get(entry.category, [])
            if key in cat_keys:
                cat_keys.remove(key)
            if self.persist_path:
                self._save()
            return True
        return False

    def search(self, category: str, predicate) -> List[MemoryEntry]:
        """Search entries in a category using a predicate function."""
        return [e for e in self.get_by_category(category) if predicate(e)]

    def pattern_hash(self, data: str) -> str:
        """Create a deterministic hash for a pattern."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def store_pattern(self, pattern_data: Dict, vuln_class: str) -> str:
        """Store a confirmed vulnerability pattern."""
        key = f"pattern:{self.pattern_hash(json.dumps(pattern_data, sort_keys=True))}"
        return self.put(key, pattern_data, category="pattern",
                        metadata={"vulnerability_class": vuln_class})

    def find_similar_patterns(self, pattern_data: Dict, vuln_class: str) -> List[MemoryEntry]:
        """Find patterns with the same vulnerability class."""
        return self.search("pattern", lambda e:
            e.metadata.get("vulnerability_class") == vuln_class)

    def store_result(self, target_path: str, version: str, result: Dict) -> str:
        """Store analysis results for a target."""
        key = f"result:{target_path}:{version}"
        return self.put(key, result, category="result",
                        target_id=target_path)

    def get_result(self, target_path: str, version: str) -> Optional[Dict]:
        """Retrieve past analysis results."""
        key = f"result:{target_path}:{version}"
        return self.get(key)

    def _save(self) -> None:
        """Persist to disk."""
        if not self.persist_path:
            return
        os.makedirs(os.path.dirname(self.persist_path) or ".", exist_ok=True)
        data = {k: {"key": e.key, "value": e.value, "category": e.category,
                      "target_id": e.target_id, "created_at": e.created_at,
                      "metadata": e.metadata}
                for k, e in self._store.items()}
        with open(self.persist_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _load(self) -> None:
        """Load from disk."""
        if not self.persist_path or not os.path.exists(self.persist_path):
            return
        try:
            with open(self.persist_path, "r") as f:
                data = json.load(f)
            for k, v in data.items():
                entry = MemoryEntry(**v)
                self._store[k] = entry
                self._category_index.setdefault(entry.category, []).append(k)
        except Exception:
            pass  # Corrupted file — start fresh

    def stats(self) -> Dict[str, Any]:
        return {
            "total_entries": len(self._store),
            "categories": {cat: len(keys) for cat, keys in self._category_index.items()},
        }


# ==================================================================
# Semantic Memory — Vector embeddings for cross-target retrieval
# ==================================================================


class SemanticMemory:
    """
    Vector-based semantic memory using ChromaDB.

    Stores vulnerability patterns as embeddings and retrieves
    structurally similar patterns across different targets.

    This is Chimera's cross-target learning mechanism. When analyzing
    a new codebase, SemanticMemory finds patterns from previous
    analyses that are structurally similar.
    """

    def __init__(self, persist_dir: Optional[str] = None) -> None:
        self.persist_dir = persist_dir or ".chimera/memory/semantic"
        self._client = None
        self._collection = None
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize ChromaDB client and collection."""
        try:
            import chromadb
            self._client = chromadb.PersistentClient(path=self.persist_dir)
            self._collection = self._client.get_or_create_collection(
                name="chimera_patterns",
                metadata={"hnsw:space": "cosine"},
            )
            self._initialized = True
            return True
        except ImportError:
            # ChromaDB not installed — fall back to in-memory
            self._fallback_store: List[Dict] = []
            self._initialized = True
            return False
        except Exception as e:
            self._fallback_store: List[Dict] = []
            self._initialized = True
            return False

    def store(self, text: str, metadata: Optional[Dict] = None,
              doc_id: Optional[str] = None) -> str:
        """Store a pattern with its embedding."""
        if not self._initialized:
            self.initialize()
        doc_id = doc_id or f"doc-{uuid.uuid4().hex[:12]}"
        metadata = metadata or {}

        if self._collection is not None:
            try:
                self._collection.upsert(
                    documents=[text],
                    metadatas=[metadata],
                    ids=[doc_id],
                )
            except Exception:
                if not hasattr(self, '_fallback_store'):
                    self._fallback_store = []
                self._fallback_store.append({
                    "id": doc_id, "text": text, "metadata": metadata,
                })
        else:
            if not hasattr(self, '_fallback_store'):
                self._fallback_store = []
            self._fallback_store.append({
                "id": doc_id, "text": text, "metadata": metadata,
            })
        return doc_id

    def search(self, query: str, n_results: int = 5,
               filter_dict: Optional[Dict] = None) -> List[Dict]:
        """Search for similar patterns."""
        if not self._initialized:
            self.initialize()

        if self._collection is not None:
            try:
                kwargs = {
                    "query_texts": [query],
                    "n_results": min(n_results, self._collection.count() or 1),
                }
                if filter_dict:
                    kwargs["where"] = filter_dict
                results = self._collection.query(**kwargs)
                return self._format_results(results)
            except Exception:
                return self._fallback_search(query, n_results, filter_dict)
        else:
            return self._fallback_search(query, n_results, filter_dict)

    def _format_results(self, results: Any) -> List[Dict]:
        """Format ChromaDB results into uniform list of dicts."""
        formatted = []
        if not results or not results.get("ids"):
            return formatted
        ids = results["ids"][0] if results["ids"] else []
        documents = results["documents"][0] if results.get("documents") else []
        metadatas = results["metadatas"][0] if results.get("metadatas") else []
        distances = results["distances"][0] if results.get("distances") else []

        for i, doc_id in enumerate(ids):
            entry = {
                "id": doc_id,
                "text": documents[i] if i < len(documents) else "",
                "metadata": metadatas[i] if i < len(metadatas) else {},
                "score": 1.0 - distances[i] if i < len(distances) else 0.0,
            }
            formatted.append(entry)
        return formatted

    def _fallback_search(self, query: str, n_results: int,
                          filter_dict: Optional[Dict] = None) -> List[Dict]:
        """Simple keyword-based fallback when ChromaDB is unavailable."""
        if not hasattr(self, '_fallback_store'):
            return []
        query_lower = query.lower()
        query_words = set(query_lower.split())
        scored = []
        for entry in self._fallback_store:
            text = entry.get("text", "").lower()
            metadata = entry.get("metadata", {})
            if filter_dict:
                match = all(
                    metadata.get(k) == v for k, v in filter_dict.items()
                )
                if not match:
                    continue
            text_words = set(text.split())
            overlap = len(query_words & text_words)
            if overlap > 0:
                scored.append({**entry, "score": overlap / len(query_words)})
        scored.sort(key=lambda x: x.get("score", 0), reverse=True)
        return scored[:n_results]

    def store_hypothesis(self, hypothesis: Any) -> str:
        """Store a hypothesis in semantic memory."""
        text = hypothesis.claim
        metadata = {
            "vulnerability_class": hypothesis.vulnerability_class.value if hypothesis.vulnerability_class else "unknown",
            "file_path": hypothesis.file_path,
            "status": hypothesis.status.value,
            "confidence": hypothesis.confidence,
        }
        return self.store(text, metadata, doc_id=f"hyp-{hypothesis.id}")

    def delete(self, doc_id: str) -> None:
        """Delete a document from memory."""
        if self._collection is not None:
            try:
                self._collection.delete(ids=[doc_id])
            except Exception:
                pass

    def count(self) -> int:
        """Return the number of stored patterns."""
        if self._collection is not None:
            try:
                return self._collection.count()
            except Exception:
                return len(getattr(self, '_fallback_store', []))
        return len(getattr(self, '_fallback_store', []))

    def stats(self) -> Dict[str, Any]:
        return {
            "total_patterns": self.count(),
            "backend": "chromadb" if self._collection else "fallback",
            "persist_dir": self.persist_dir,
        }
