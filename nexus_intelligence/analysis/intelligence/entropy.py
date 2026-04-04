import math
from collections import Counter
from typing import Dict, Any
from nexus_intelligence.analysis.intelligence.math_forensics import MarkovChain

class EntropyAnalyzer:
    """
    Advanced Information Density & Determinism Analyzer.
    Combines Shannon Entropy with Markovian Determinism to distinguish 
    between natural language, encrypted payloads, and DGA strings.
    """
    @staticmethod
    def analyze(data: str) -> Dict[str, Any]:
        """
        Calculates forensic metrics for a given sequence.
        
        Metrics:
        - Shannon Entropy: Raw information density.
        - Efficiency: Normalized entropy (H / H_max).
        - Markov Determinism: State transition predictability.
        """
        if not data: 
            return {"shannon": 0.0, "is_synthetic": False, "confidence": 0.0}
            
        n = len(data)
        freqs = Counter(data)
        probs = [c/n for c in freqs.values()]
        
        # Shannon Entropy (Bits per character)
        shannon = -sum(p * math.log(p, 2) for p in probs)
        
        # Maximum possible entropy for this alphabet size
        max_h = math.log(len(freqs), 2) if len(freqs) > 1 else 1.0
        efficiency = shannon / max_h
        
        # Markovian Structural Analysis
        markov = MarkovChain.analyze(data)
        det_idx = markov.get("determinism_index", 0.0)
        
        # Heuristic: Synthetic strings (DGA/Encrypted) typically have high efficiency 
        # but very low Markovian determinism compared to natural language.
        is_synthetic = (efficiency > 0.85 and det_idx < 0.45) or (efficiency > 0.94)
        
        return {
            "shannon": round(shannon, 4),
            "efficiency": round(efficiency, 4),
            "determinism": round(det_idx, 4),
            "is_synthetic": is_synthetic,
            "forensic_summary": "High_Entropy_Synthetic" if is_synthetic else "Natural_Structure"
        }
