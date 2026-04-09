import asyncio
import logging
from typing import List, Any
from nexus_intelligence.core.engine import IntelligenceEngine

class IntelligenceOrchestrator:
    """
    Production-grade job scheduler.
    Manages worker lifecycles and ensures clean teardown.
    """
    def __init__(self, engine: IntelligenceEngine, reporting: Any, logger: logging.Logger):
        self.engine = engine
        self.reporting = reporting
        self.logger = logger
        self.queue = asyncio.Queue()
        self._workers: List[asyncio.Task] = []

    async def add_targets(self, targets: List[str]):
        for t in targets: await self.queue.put(t)

    async def _worker_loop(self, worker_id: int):
        while True:
            target = await self.queue.get()
            self.logger.info(f"Worker-{worker_id} processing target: {target}")
            try:
                # Explicit module imports to prevent circular dependencies
                from nexus_intelligence.analysis.dns import DNSIntelligence
                from nexus_intelligence.analysis.web import WebIntelligence
                from nexus_intelligence.analysis.ssl import SSLForensics
                
                modules = [DNSIntelligence, WebIntelligence, SSLForensics]
                results = await self.engine.run(modules)
                
                path = self.reporting.generate_markdown(target, results)
                self.logger.info(f"Worker-{worker_id} finalized report: {path}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Worker-{worker_id} encountered fatal error on {target}: {str(e)}")
            finally:
                self.queue.task_done()

    async def run_parallel(self, concurrency: int = 5):
        self._workers = [asyncio.create_task(self._worker_loop(i)) for i in range(concurrency)]
        try:
            await self.queue.join()
        finally:
            for w in self._workers:
                w.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)
