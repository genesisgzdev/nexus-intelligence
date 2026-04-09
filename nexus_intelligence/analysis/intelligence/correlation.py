import os
import json
import numpy as np
import faiss
from typing import List, Dict, Any
from sentence_transformers import SentenceTransformer

class VectorCorrelator:
    """
    Semantic correlation engine using local vector embeddings.
    
    Unifies EDR telemetry and OSINT findings into a high-dimensional 
    vector space for similarity-based threat mapping.
    """
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.dimension = 384
        self.index = faiss.IndexFlatIP(self.dimension)
        self.metadata = []

    def ingest_edr_logs(self, log_path: str):
        """
        Parses Ring 0 telemetry logs into the vector index.
        """
        if not os.path.exists(log_path):
            return
            
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    text = f"Category: {data.get('category')} | Description: {data.get('description')} | IoC: {data.get('ioc')}"
                    self._add_to_index(text, {"source": "EDR", "original": data})
                except json.JSONDecodeError:
                    continue

    def ingest_nexus_results(self, db_results: List[Dict[str, Any]]):
        """
        Indexes local OSINT findings for cross-project correlation.
        """
        for entry in db_results:
            text = f"Target: {entry.get('target')} | Module: {entry.get('module')} | Data: {str(entry.get('data'))}"
            self._add_to_index(text, {"source": "NEXUS", "original": entry})

    def _add_to_index(self, text: str, meta: Dict[str, Any]):
        embedding = self.model.encode([text])[0]
        faiss.normalize_L2(np.array([embedding]))
        self.index.add(np.array([embedding]).astype('float32'))
        self.metadata.append(meta)

    def find_related_threats(self, query_text: str, threshold: float = 0.7, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Executes semantic search via cosine similarity.
        """
        query_vec = self.model.encode([query_text])[0]
        faiss.normalize_L2(np.array([query_vec]))
        
        distances, indices = self.index.search(np.array([query_vec]).astype('float32'), top_k)
        
        matches = []
        for dist, idx in zip(distances[0], indices[0]):
            if idx != -1 and dist >= threshold:
                matches.append({
                    "score": round(float(dist), 4),
                    "artifact": self.metadata[idx]
                })
        return matches
