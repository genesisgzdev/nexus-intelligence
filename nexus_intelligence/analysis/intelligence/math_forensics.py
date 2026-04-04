import math
from collections import Counter
from typing import List, Dict, Any

class BenfordAnalyzer:
    EXPECTED = {d: math.log10(1 + 1/d) for d in range(1, 10)}
    @classmethod
    def compute(cls, values: List[float]) -> Dict[str, Any]:
        digits = [int(str(abs(v)).lstrip('0.')[0]) for v in values if str(abs(v)).lstrip('0.')]
        digits = [d for d in digits if 1 <= d <= 9]
        if len(digits) < 20: return {"status": "insufficient_data"}
        counts = Counter(digits)
        n = len(digits)
        chi_sq = sum(((counts.get(d, 0) - (cls.EXPECTED[d]*n))**2) / (cls.EXPECTED[d]*n) for d in range(1, 10))
        return {"chi_squared": round(chi_sq, 4), "is_anomalous": chi_sq > 15.507}

class MarkovChain:
    @staticmethod
    def analyze(sequence: List[str]) -> Dict[str, Any]:
        if len(sequence) < 10: return {"status": "short_sequence"}
        transitions = {}
        for i in range(len(sequence)-1):
            curr, nxt = sequence[i], sequence[i+1]
            if curr not in transitions: transitions[curr] = Counter()
            transitions[curr][nxt] += 1
        det_idx = sum(max(c.values())/sum(c.values()) for c in transitions.values()) / len(transitions)
        return {"determinism": round(det_idx, 4), "states": len(set(sequence))}
