import asyncio
import logging
from typing import List, Type, Dict, Any
from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.core.security import SecurityValidator

class IntelligenceEngine:
    """
    Asynchronous execution engine for forensic modules.
    
    Coordinates concurrent task execution across the event loop,
    implementing resource gating and security validation for targets.
    """
    def __init__(self, target: str, config: Any, logger: logging.Logger):
        self.target = target
        self.config = config
        self.logger = logger

    async def run(self, modules: List[Type[BaseModule]]) -> Dict[str, Any]:
        """
        Executes a suite of forensic modules concurrently.
        
        Args:
            modules: List of module classes to instantiate and execute.
            
        Returns:
            Dictionary containing aggregated results indexed by module name.
        """
        if not SecurityValidator.is_safe_target(self.target):
            self.logger.error(f"Security Policy Violation: Target {self.target} resides in restricted address space.")
            return {"error": "security_violation", "detail": "Restricted_Target_Range"}

        results: Dict[str, Any] = {}
        tasks = []
        
        for mod_class in modules:
            instance = mod_class(self.target, self.config, self.logger)
            tasks.append(asyncio.wait_for(instance.execute(), timeout=self.config.timeout))

        module_names = [m.__name__ for m in modules]
        executed_results = await asyncio.gather(*tasks, return_exceptions=True)

        for name, res in zip(module_names, executed_results):
            if isinstance(res, Exception):
                self.logger.error(f"Execution fault in module {name}: {str(res)}")
                results[name] = {"error": "module_fault", "detail": str(res)}
            else:
                results[name] = res

        return results
