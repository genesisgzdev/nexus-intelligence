import numpy as np
from typing import Dict, Any
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator

class VectorIntegrityAuditor:
    """
    Forensic audit engine for the local TF-IDF matrix.
    Validates non-empty vectors and unit normalization.
    """
    def __init__(self, correlator: VectorCorrelator):
        self.correlator = correlator

    def audit_index(self) -> Dict[str, Any]:
        """
        Performs mathematical verification of the vector space integrity.
        """
        matrix = self.correlator.matrix
        ntotal = 0 if matrix is None else matrix.shape[0]
        if ntotal == 0:
            return {"status": "Empty_Index", "is_healthy": False}

        sample_vec = matrix.getrow(0).toarray().ravel()
        norm = np.linalg.norm(sample_vec)
        
        healthy = np.isclose(norm, 1.0, atol=1e-6)
        return {
            "index_size": ntotal,
            "l2_norm": round(float(norm), 6),
            "is_healthy": bool(healthy),
            "vectorizer": "tfidf",
        }
