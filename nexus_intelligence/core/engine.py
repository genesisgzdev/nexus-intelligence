import asyncio
from typing import List, Type, Dict, Any
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.core.security import SecurityValidator

class IntelligenceEngine:
    """
    Async execution engine for nexus-intelligence.
    Handles thousands of concurrent requests using an event loop.
    """
    def __init__(self, target: str, config: Any, logger: Any):
        self.target = target
        self.config = config
        self.logger = logger

    async def run(self, modules: List[Type[BaseModule]]) -> Dict[str, Any]:
        """
        Executes intelligence modules concurrently via asyncio.
        """
        if not SecurityValidator.is_safe_target(self.target):
            self.logger.error(f"SSRF Attempt Blocked: Target {self.target} is in a restricted range.")
            return {"error": "security_violation", "detail": "Target is restricted"}

        results: Dict[str, Any] = {}
        
        # Instantiate modules
        tasks = []
        for mod_class in modules:
            instance = mod_class(self.target, self.config, self.logger)
            # We assume the new execute() method is async
            tasks.append(asyncio.wait_for(instance.execute(), timeout=self.config.timeout))

        # Parallel execution with result aggregation
        module_names = [m.__name__ for m in modules]
        executed_results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, res in zip(module_names, executed_results):
            if isinstance(res, Exception):
                self.logger.error(f"Module {name} failed: {str(res)}")
                results[name] = {"error": "module_failure", "detail": str(res)}
            else:
                results[name] = res

        return results
