import asyncio
import sys
import argparse
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.core.persistence import PersistenceManager
from nexus_intelligence.core.reporting import ReportingEngine
from nexus_intelligence.core.orchestrator import IntelligenceOrchestrator

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
            print(f"Error: Target file {args.file} not found.")
            return
        
        with open(args.file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
        
        # Launching Orchestrator for automated bulk processing
        engine = IntelligenceEngine("", config, logger) # Dynamic target engine
        orchestrator = IntelligenceOrchestrator(engine, reporting)
        await orchestrator.add_targets(targets)
        await orchestrator.run_parallel(args.concurrency)
        
    elif args.target:
        # Standard single execution
        from nexus_intelligence.analysis.dns import DNSIntelligence
        from nexus_intelligence.analysis.web import WebIntelligence
        from nexus_intelligence.analysis.ssl import SSLForensics
        from nexus_intelligence.analysis.mail import MailIntelligence
        from nexus_intelligence.analysis.subdomains import SubdomainDiscovery

        engine = IntelligenceEngine(args.target, config, logger)
        modules = [DNSIntelligence, WebIntelligence, SSLForensics, MailIntelligence, SubdomainDiscovery]
        results = await engine.run(modules)
        
        for mod_name, data in results.items():
            await db.save_finding(args.target, mod_name, data)
        
        path = reporting.generate_markdown(args.target, results)
        print(f"\n[SUCCESS] Intelligence session completed. Report: {path}")
    else:
        parser.print_help()

if __name__ == "__main__":
    asyncio.run(main())
