"""
Orchestration engine for Nexus Intelligence.
Manages concurrent execution of analysis modules.
"""
import concurrent.futures
from typing import List, Dict, Any, Type
import logging

from nexus_intelligence.analysis.base import BaseModule
from nexus_intelligence.core.config import Config

class Orchestrator:
    """Manages the lifecycle of analysis modules."""

    def __init__(self, target: str, config: Config, logger: logging.Logger):
        self.target = target
        self.config = config
        self.logger = logger
        self.results: Dict[str, Any] = {}

    def run_parallel(self, module_classes: List[Type[BaseModule]]) -> Dict[str, Any]:
        """
        Executes multiple analysis modules in parallel.
        
        Args:
            module_classes: List of module classes to instantiate and run.
        """
        self.logger.info(f"[bold cyan]Initiating intelligence gathering for:[/] [bold white]{self.target}[/]")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            # Instantiate modules
            modules = [cls(self.target, self.config, self.logger) for cls in module_classes]
            
            # Map futures
            future_to_module = {executor.submit(mod.execute): mod.__class__.__name__ for mod in modules}
            
            for future in concurrent.futures.as_completed(future_to_module):
                name = future_to_module[future]
                try:
                    data = future.result()
                    self.results[name] = data
                    self.logger.debug(f"[green]Module {name} completed successfully.[/]")
                except Exception as exc:
                    self.logger.error(f"[red]Module {name} generated an exception: {exc}[/]")
                    self.results[name] = {"error": str(exc)}
                    
        return self.results
