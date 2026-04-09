import asyncio
import os
from typing import List
from nexus_intelligence.core.engine import IntelligenceEngine

class IntelligenceOrchestrator:
    """
    Automated job scheduler for continuous intelligence gathering.
    """
    def __init__(self, engine: IntelligenceEngine, reporting: Any):
        self.engine = engine
        self.reporting = reporting
        self.queue = asyncio.Queue()

    async def add_targets(self, targets: List[str]):
        for t in targets:
            await self.queue.put(t)

    async def worker(self, worker_id: int):
        while True:
            target = await self.queue.get()
            print(f"[Worker-{worker_id}] Starting automation for: {target}")
            try:
                # We assume modules are passed to run() or pre-configured
                from nexus_intelligence.analysis.dns import DNSIntelligence
                from nexus_intelligence.analysis.web import WebIntelligence
                from nexus_intelligence.analysis.ssl import SSLForensics
                
                modules = [DNSIntelligence, WebIntelligence, SSLForensics]
                results = await self.engine.run(modules)
                
                # Automated report generation
                report_path = self.reporting.generate_markdown(target, results)
                print(f"[Worker-{worker_id}] Report finalized at: {report_path}")
                
            except Exception as e:
                print(f"[Worker-{worker_id}] Critical failure processing {target}: {e}")
            finally:
                self.queue.task_done()

    async def run_parallel(self, concurrency: int = 3):
        workers = [asyncio.create_task(self.worker(i)) for i in range(concurrency)]
        await self.queue.join()
        for w in workers:
            w.cancel()
