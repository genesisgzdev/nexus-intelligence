import math
from collections import Counter
from typing import Dict, Any

class EntropyAnalyzer:
    @staticmethod
    def analyze(data: str) -> Dict[str, Any]:
        if not data: return {"shannon": 0.0, "is_synthetic": False}
        n = len(data)
        freqs = Counter(data)
        probs = [c/n for c in freqs.values()]
        shannon = -sum(p * math.log(p, 2) for p in probs)
        max_h = math.log(len(freqs), 2) if len(freqs) > 1 else 1.0
        eff = shannon / max_h
        return {
            "shannon": round(shannon, 4),
            "efficiency": round(eff, 4),
            "is_synthetic": eff > 0.92 and n > 15
        }
