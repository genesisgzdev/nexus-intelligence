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

        norms = np.sqrt(matrix.multiply(matrix).sum(axis=1)).A1
        healthy = bool(np.all(np.isfinite(norms)) and np.all(np.isclose(norms, 1.0, atol=1e-6)))
        norm = float(norms[0])
        return {
            "index_size": ntotal,
            "l2_norm": round(norm, 6),
            "min_l2_norm": round(float(norms.min()), 6),
            "max_l2_norm": round(float(norms.max()), 6),
            "is_healthy": healthy,
            "vectorizer": "tfidf",
        }
