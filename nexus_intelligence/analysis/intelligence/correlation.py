import os
import json
import numpy as np
import faiss
from typing import List, Dict, Any
from sentence_transformers import SentenceTransformer

class VectorCorrelator:
    """
    Semantic Correlation Engine.
    Links EDR kernel events, MegaTicketing fraud logs, and Nexus OSINT 
    using local vector embeddings and cosine similarity.
    """
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        # Load model locally (no APIs)
        self.model = SentenceTransformer(model_name)
        self.dimension = 384 # Dimension for all-MiniLM-L6-v2
        self.index = faiss.IndexFlatIP(self.dimension) # Inner Product for Cosine Similarity
        self.metadata = []

    def ingest_edr_logs(self, log_path: str):
        """Processes Ring 0 telemetry from TDS."""
        if not os.path.exists(log_path): return
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    text = f"EDR Event: {data['category']} - {data['description']} IoC: {data['ioc']}"
                    self._add_to_index(text, {"source": "EDR", "original": data})
                except: continue

    def ingest_nexus_results(self, db_results: List[Dict[str, Any]]):
        """Processes OSINT findings from Nexus."""
        for entry in db_results:
            text = f"OSINT Finding for {entry['target']} in {entry['module']}: {str(entry['data'])}"
            self._add_to_index(text, {"source": "NEXUS", "original": entry})

    def _add_to_index(self, text: str, meta: Dict[str, Any]):
        embedding = self.model.encode([text])[0]
        # Normalize for cosine similarity
        faiss.normalize_L2(np.array([embedding]))
        self.index.add(np.array([embedding]).astype('float32'))
        self.metadata.append(meta)

    def find_related_threats(self, query_text: str, threshold: float = 0.7, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Performs semantic search to find related artifacts across all projects.
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
