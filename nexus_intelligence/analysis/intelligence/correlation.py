import os
import json
import numpy as np
from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class VectorCorrelator:
    """
    High-performance Semantic Correlation Engine.
    Uses TF-IDF Vectorization and Cosine Similarity for local threat mapping.
    """
    def __init__(self):
        self.vectorizer = TfidfVectorizer(stop_words='english')
        self.metadata = []
        self.corpus = []
        self.matrix = None
        self.index_error = None

    def _update_index(self):
        if not self.corpus:
            self.matrix = None
            self.index_error = None
            return
        try:
            self.matrix = self.vectorizer.fit_transform(self.corpus)
            self.index_error = None
        except ValueError as exc:
            # A corpus made only of stop words or empty observations has no
            # usable TF-IDF vocabulary. Keep ingestion successful and expose
            # the reason to callers instead of crashing a completed scan.
            self.matrix = None
            self.index_error = str(exc)

    def ingest_edr_logs(self, log_path: str):
        if not os.path.exists(log_path): return
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    text = f"EDR: {data.get('category')} {data.get('description')} {data.get('ioc')}"
                    self.corpus.append(text)
                    self.metadata.append({"source": "EDR", "original": data})
                except (json.JSONDecodeError, TypeError):
                    continue
        self._update_index()

    def ingest_nexus_results(self, db_results: List[Dict[str, Any]]):
        for entry in db_results:
            text = f"NEXUS: {entry.get('target')} {entry.get('module')} {str(entry.get('data'))}"
            self.corpus.append(text)
            self.metadata.append({"source": "NEXUS", "original": entry})
        self._update_index()

    def find_related_threats(self, query_text: str, threshold: float = 0.3, top_k: int = 5) -> List[Dict[str, Any]]:
        if self.matrix is None: return []
        
        query_vec = self.vectorizer.transform([query_text])
        similarities = cosine_similarity(query_vec, self.matrix).flatten()
        
        related_indices = similarities.argsort()[-top_k:][::-1]
        matches = []
        for idx in related_indices:
            score = float(similarities[idx])
            if score >= threshold:
                matches.append({
                    "score": round(score, 4),
                    "artifact": self.metadata[idx]
                })
        return matches

    def find_related_pairs(self, threshold: float = 0.3, top_k: int = 20) -> List[Dict[str, Any]]:
        """Return similar findings belonging to different targets.

        Bulk correlation compares persisted observations directly rather than
        inventing a single query string for the whole file. Pairs from the
        same target are excluded because they describe one scan, not a
        cross-target relationship.
        """
        if self.matrix is None or len(self.metadata) < 2:
            return []

        similarities = cosine_similarity(self.matrix)
        pairs = []
        for left in range(len(self.metadata)):
            left_entry = self.metadata[left].get("original", {})
            left_target = left_entry.get("target")
            for right in range(left + 1, len(self.metadata)):
                right_entry = self.metadata[right].get("original", {})
                right_target = right_entry.get("target")
                if not left_target or not right_target or left_target == right_target:
                    continue
                score = float(similarities[left, right])
                if score < threshold:
                    continue
                pairs.append({
                    "score": round(score, 4),
                    "left": self.metadata[left],
                    "right": self.metadata[right],
                })

        pairs.sort(key=lambda item: item["score"], reverse=True)
        return pairs[:top_k]
