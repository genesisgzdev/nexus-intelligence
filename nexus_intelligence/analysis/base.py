"""
Base classes for analysis modules.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any
import logging
import time
from nexus_intelligence.core.config import Config

class BaseModule(ABC):
    """Abstract base class for all security intelligence modules."""

    def __init__(self, target: str, config: Config, logger: logging.Logger):
        self.target = target
        self.config = config
        self.logger = logger
        self.start_time = 0.0
        self.end_time = 0.0

    def execute(self) -> Dict[str, Any]:
        """Wrapper to track execution time and handle common logic."""
        self.start_time = time.time()
        results = self.run()
        self.end_time = time.time()
        results['_metadata'] = {
            'execution_time_seconds': round(self.end_time - self.start_time, 4)
        }
        return results

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """Core logic of the module. Must be implemented by subclasses."""
        pass
