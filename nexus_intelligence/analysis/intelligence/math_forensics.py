import math
from collections import Counter
from typing import List, Dict, Any

class BenfordAnalyzer:
    """
    Forensic engine using Benford's Law (First-Digit Law).
    Detects data manipulation/faking in numerical series (latencies, counts, lengths).
    """
    EXPECTED = {d: math.log10(1 + 1/d) for d in range(1, 10)}
    
    @classmethod
    def get_first_digit(cls, v: float) -> int:
        """
        Pure mathematical extraction of the first non-zero digit.
        Prevents failures from floating point formatting (scientific notation).
        """
        if v == 0: return 0
        v = abs(v)
        # Use log10 to determine the order of magnitude
        return int(v / (10 ** int(math.log10(v))))

    @classmethod
    def compute(cls, values: List[float]) -> Dict[str, Any]:
        """
        Calculates Pearson's Chi-squared test for the dataset.
        Critical value: 15.507 for 8 DoF at alpha=0.05.
        """
        digits = [cls.get_first_digit(v) for v in values]
        digits = [d for d in digits if 1 <= d <= 9]
        
        if len(digits) < 20: 
            return {
                "status": "insufficient_data", 
                "count": len(digits), 
                "requirement": 20
            }
            
        counts = Counter(digits)
        n = len(digits)
        
        # Chi-Squared Test Calculation
        chi_sq = sum(
            ((counts.get(d, 0) - (cls.EXPECTED[d] * n))**2) / (cls.EXPECTED[d] * n) 
            for d in range(1, 10)
        )
        
        return {
            "chi_squared": round(chi_sq, 4), 
            "is_anomalous": chi_sq > 15.507,
            "sample_size": n,
            "distribution": {d: round(counts.get(d, 0)/n, 4) for d in range(1, 10)}
        }

class MarkovChain:
    """
    Analyzes sequence determinism and state transition probabilities.
    Used for detecting DGA (Domain Generation Algorithms) vs Natural Language.
    """
    @staticmethod
    def analyze(sequence: str) -> Dict[str, Any]:
        """
        Computes transition probability matrix for N-grams.
        """
        if len(sequence) < 10: return {"status": "sequence_too_short"}
        
        # Character-level transitions
        transitions: Dict[str, Counter] = {}
        for i in range(len(sequence)-1):
            curr, nxt = sequence[i], sequence[i+1]
            if curr not in transitions: transitions[curr] = Counter()
            transitions[curr][nxt] += 1
            
        # Compute average determinism index (max likelihood transition)
        det_scores = []
        for state, counts in transitions.items():
            total = sum(counts.values())
            det_scores.append(max(counts.values()) / total)
            
        avg_det = sum(det_scores) / len(det_scores) if det_scores else 0
        
        return {
            "determinism_index": round(avg_det, 4), 
            "alphabet_size": len(set(sequence)),
            "is_likely_synthetic": avg_det < 0.4 and len(set(sequence)) > 8,
            "sequence_length": len(sequence)
        }
