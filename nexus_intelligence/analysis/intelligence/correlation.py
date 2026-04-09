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

    def _update_index(self):
        if self.corpus:
            self.matrix = self.vectorizer.fit_transform(self.corpus)

    def ingest_edr_logs(self, log_path: str):
        if not os.path.exists(log_path): return
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    text = f"EDR: {data.get('category')} {data.get('description')} {data.get('ioc')}"
                    self.corpus.append(text)
                    self.metadata.append({"source": "EDR", "original": data})
                except: continue
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
