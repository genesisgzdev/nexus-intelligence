import concurrent.futures
from typing import List, Type, Dict, Any
from nexus_intelligence.analysis.base import BaseModule

class IntelligenceEngine:
    """
    Core execution engine for nexus-intelligence.
    Orchestrates parallel forensic modules with global reliability controls.
    """
    def __init__(self, target: str, config: Any, logger: Any):
        self.target = target
        self.config = config
        self.logger = logger

    def run(self, modules: List[Type[BaseModule]]) -> Dict[str, Any]:
        """
        Executes intelligence modules in parallel.
        Implements strict timing controls to prevent OS-level thread exhaustion (zombie hilos).
        """
        results: Dict[str, Any] = {}
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.max_threads,
            thread_name_prefix="NexusForensic"
        ) as executor:
            # Instantiate and submit forensic tasks
            instances = [m(self.target, self.config, self.logger) for m in modules]
            futures = {executor.submit(i.execute): i.__class__.__name__ for i in instances}
            
            # Global timeout enforcement to prevent stalling on tarpits or corrupt sockets
            done, not_done = concurrent.futures.wait(
                futures.keys(), 
                timeout=self.config.timeout * 2, # Buffer for total execution
                return_when=concurrent.futures.ALL_COMPLETED
            )
            
            for f in done:
                mod_name = futures[f]
                try:
                    results[mod_name] = f.result()
                except Exception as e:
                    self.logger.error(f"Critical module error in {mod_name}: {str(e)}")
                    results[mod_name] = {"error": "unhandled_module_failure", "detail": str(e)}
            
            # Clean up timed-out futures
            for f in not_done:
                mod_name = futures[f]
                self.logger.warning(f"Forced termination of zombie thread: {mod_name}")
                results[mod_name] = {"error": "module_timeout", "status": "terminated_by_engine"}
                
        return results
