import asyncio
import sys
import os
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator
from nexus_intelligence.core.persistence import PersistenceManager

async def run_correlation():
    print("--- Starting Multi-Project Semantic Correlation ---")
    
    # Paths to source data
    edr_logs = "C:/Users/Genesisif/Desktop/TDS-MegaTicketing-Industrial/threat-detection-suite/tds_threat_events.jsonl"
    
    correlator = VectorCorrelator()
    db = PersistenceManager()
    await db.initialize()

    # 1. Ingest EDR Telemetry
    print("[*] Ingesting EDR Ring 0 telemetry...")
    correlator.ingest_edr_logs(edr_logs)

    # 2. Ingest Nexus Forensic Database
    print("[*] Ingesting Nexus OSINT findings...")
    # Mocking DB fetch for demo - in production, we'd query SQLite
    # db_results = await db.get_all_findings()
    # correlator.ingest_nexus_results(db_results)

    # 3. Execution: Cross-search
    # Example: Find if an EDR network alert matches any OSINT record
    query = "Suspicious connection to known C2 infrastructure"
    print(f"[*] Searching for: {query}")
    matches = correlator.find_related_threats(query)

    for m in matches:
        print(f"Found Match [Score: {m['score']}]: {m['artifact']['source']} - {m['artifact']['original'].get('description', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(run_correlation())
