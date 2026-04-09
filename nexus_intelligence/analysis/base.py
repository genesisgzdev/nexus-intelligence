from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseModule(ABC):
    """
    Abstract base class for all forensic and intelligence modules.
    Now supports asynchronous execution.
    """
    def __init__(self, target: str, config: Any, logger: Any):
        self.target = target
        self.config = config
        self.logger = logger

    async def execute(self) -> Dict[str, Any]:
        """
        Wrapper for async module execution with lifecycle hooks.
        """
        self.logger.debug(f"Starting module: {self.__class__.__name__}")
        try:
            result = await self.run()
            return result
        finally:
            self.logger.debug(f"Module finished: {self.__class__.__name__}")

    @abstractmethod
    async def run(self) -> Dict[str, Any]:
        """
        Primary execution logic to be implemented by child classes.
        """
        pass
