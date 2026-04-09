import time
import numpy as np
import json
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator

def run_stress_test(num_entries: int = 500):
    print(f"--- Starting Stress Test: {num_entries} entries ---")
    c = VectorCorrelator()
    
    start = time.time()
    for i in range(num_entries):
        c.corpus.append(f"Forensic sample {i} with noise {np.random.bytes(4).hex()}")
        c.metadata.append({"id": i})
    
    c._update_index()
    duration = time.time() - start
    print(f"Ingestion: {duration:.4f}s")

    s_start = time.time()
    matches = c.find_related_threats("Forensic sample 10", threshold=0.1)
    print(f"Search Latency: {(time.time() - s_start)*1000:.2f}ms")
    print(f"Results: {len(matches)} matches found.")

if __name__ == "__main__":
    run_stress_test()
