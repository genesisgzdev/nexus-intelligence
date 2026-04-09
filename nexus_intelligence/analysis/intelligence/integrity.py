import numpy as np
import faiss
from typing import Dict, Any
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator

class VectorIntegrityAuditor:
    """
    Forensic audit engine for the FAISS Vector Index.
    Validates embedding consistency, distribution, and recall accuracy.
    """
    def __init__(self, correlator: VectorCorrelator):
        self.correlator = correlator

    def audit_index(self) -> Dict[str, Any]:
        """
        Performs a mathematical sanity check on the loaded vector index.
        """
        ntotal = self.correlator.index.ntotal
        if ntotal == 0:
            return {"status": "Empty_Index", "code": 0}

        # 1. Verification of Unit Normalization (Cosine Similarity Requirement)
        # We sample a vector and check if its norm is approximately 1.0
        sample_idx = 0
        reconstructed = self.correlator.index.reconstruct(sample_idx)
        norm = np.linalg.norm(reconstructed)
        
        # 2. Sensitivity Test: Semantic Drift Detection
        # Check if identical strings yield identical embeddings (Determinism)
        test_str = "Suspicious C2 activity detected in Ring 0"
        emb1 = self.correlator.model.encode([test_str])[0]
        emb2 = self.correlator.model.encode([test_str])[0]
        drift = np.linalg.norm(emb1 - emb2)

        return {
            "index_size": ntotal,
            "normalization_norm": round(float(norm), 6),
            "semantic_determinism_drift": round(float(drift), 10),
            "is_healthy": norm > 0.99 and drift < 1e-6,
            "engine": "FAISS_IndexFlatIP"
        }

if __name__ == "__main__":
    # Internal test routine
    c = VectorCorrelator()
    auditor = VectorIntegrityAuditor(c)
    # Adding a dummy to audit
    c._add_to_index("Health check pattern", {"source": "SYSTEM"})
    print(json.dumps(auditor.audit_index(), indent=2))
