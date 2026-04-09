import asyncio
import sys
from nexus_intelligence.core.engine import IntelligenceEngine
from nexus_intelligence.core.config import config
from nexus_intelligence.core.logger import setup_logger
from nexus_intelligence.analysis.dns import DNSIntelligence
from nexus_intelligence.analysis.web import WebIntelligence
from nexus_intelligence.analysis.ssl import SSLForensics

async def main():
    if len(sys.argv) < 2:
        print("Usage: python -m nexus_intelligence <target>")
        return

    target = sys.argv[1]
    logger = setup_logger(config.verbose)
    
    engine = IntelligenceEngine(target, config, logger)
    modules = [DNSIntelligence, WebIntelligence, SSLForensics]
    
    results = await engine.run(modules)
    print(results)

if __name__ == "__main__":
    asyncio.run(main())
