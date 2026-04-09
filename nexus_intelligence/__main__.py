import asyncio
import sys
import argparse
import os
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.core.persistence import PersistenceManager
from nexus_intelligence.core.reporting import ReportingEngine
from nexus_intelligence.core.orchestrator import IntelligenceOrchestrator
from nexus_intelligence.analysis.intelligence.correlation import VectorCorrelator
from nexus_intelligence.analysis.intelligence.integrity import VectorIntegrityAuditor

async def run_single_target(target, engine, reporting, db, logger):
    from nexus_intelligence.analysis.dns import DNSIntelligence
    from nexus_intelligence.analysis.web import WebIntelligence
    from nexus_intelligence.analysis.ssl import SSLForensics
    from nexus_intelligence.analysis.mail import MailIntelligence
    from nexus_intelligence.analysis.subdomains import SubdomainDiscovery

    modules = [DNSIntelligence, WebIntelligence, SSLForensics, MailIntelligence, SubdomainDiscovery]
    results = await engine.run(modules)
    
    for mod_name, data in results.items():
        await db.save_finding(target, mod_name, data)
    
    path = reporting.generate_markdown(target, results)
    logger.info(f"Report generated: {path}")

    # --- AUTOMATED VECTOR CORRELATION ---
    logger.info("Initializing automated semantic correlation...")
    correlator = VectorCorrelator()
    
    # Ingest existing EDR and Nexus logs for context
    # Note: Using neutral environment paths
    edr_logs = os.environ.get("TDS_LOG_PATH", "logs/tds_threats.jsonl")
    if os.path.exists(edr_logs):
        correlator.ingest_edr_logs(edr_logs)
    
    # Search for related threats based on current findings
    query = f"Significant findings for {target}"
    matches = correlator.find_related_threats(query)
    
    if matches:
        logger.info(f"Found {len(matches)} semantically related historical threats.")
        for m in matches:
            logger.info(f"Match [{m['score']}]: {m['artifact']['source']} - {m['artifact']['original'].get('description', 'N/A')}")
    
    # --- VECTOR INTEGRITY AUDIT ---
    auditor = VectorIntegrityAuditor(correlator)
    audit_results = auditor.audit_index()
    if not audit_results.get("is_healthy"):
        logger.warning("Vector index integrity check failed. Semantic results may be degraded.")

async def main():
    parser = argparse.ArgumentParser(description="Nexus Intelligence: Async OSINT Platform")
    parser.add_argument("target", nargs="?", help="Single target domain or IP")
    parser.add_argument("--file", help="File containing list of targets")
    parser.add_argument("--concurrency", type=int, default=3, help="Number of parallel workers")
    args = parser.parse_args()

    logger = setup_logger(config.verbose)
    db = PersistenceManager()
    await db.initialize()
    reporting = ReportingEngine()

    if args.file:
        if not os.path.exists(args.file):
            logger.error(f"Target file {args.file} not found.")
            return
        
        with open(args.file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        
        engine = IntelligenceEngine("", config, logger)
        orchestrator = IntelligenceOrchestrator(engine, reporting, logger)
        await orchestrator.add_targets(targets)
        await orchestrator.run_parallel(args.concurrency)
        
    elif args.target:
        engine = IntelligenceEngine(args.target, config, logger)
        await run_single_target(args.target, engine, reporting, db, logger)
    else:
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
