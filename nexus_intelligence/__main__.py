import asyncio
import sys
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.core.persistence import PersistenceManager
from nexus_intelligence.analysis.dns import DNSIntelligence
from nexus_intelligence.analysis.web import WebIntelligence
from nexus_intelligence.analysis.ssl import SSLForensics
from nexus_intelligence.analysis.mail import MailIntelligence
from nexus_intelligence.analysis.subdomains import SubdomainDiscovery

async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m nexus_intelligence <target>")
        return

    target = sys.argv[1]
    logger = setup_logger(config.verbose)
    
    # Initialize Persistence
    db = PersistenceManager()
    await db.initialize()

    engine = IntelligenceEngine(target, config, logger)
    modules = [
        DNSIntelligence, 
        WebIntelligence, 
        SSLForensics, 
        MailIntelligence, 
        SubdomainDiscovery
    ]
    
    results = await engine.run(modules)
    
    # Save findings to local DB
    for mod_name, data in results.items():
        await db.save_finding(target, mod_name, data)
    
    print(f"\n[DONE] Intelligence session for {target} stored in local database.")

if __name__ == "__main__":
    asyncio.run(main())
