from abc import ABC, abstractmethod
import time
import logging
from typing import Dict, Any
from nexus_intelligence.core.config import NexusSettings

class BaseModule(ABC):
    """
    Abstract Base Class for Nexus Intelligence Modules.
    Provides standard lifecycle hooks for execution and profiling.
    """
    def __init__(self, target: str, config: NexusSettings, logger: logging.Logger):
        self.target = target
        self.config = config
        self.logger = logger

    def execute(self) -> Dict[str, Any]:
        """
        Executes the module's core logic with telemetry.
        """
        start = time.time()
        try:
            res = self.run()
        except Exception as e:
            self.logger.error(f"Module {self.__class__.__name__} crashed: {str(e)}")
            res = {"error": "unhandled_crash", "detail": str(e)}
            
        res['_meta'] = {
            "runtime": round(time.time() - start, 4),
            "module": self.__class__.__name__
        }
        return res

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        """
        Core logic to be implemented by forensic modules.
        """
        pass
