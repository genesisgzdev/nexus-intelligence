from abc import ABC, abstractmethod
from typing import Dict, Any
from core.config import Config
import logging

class BaseModule(ABC):
    def __init__(self, target: str, config: Config, logger: logging.Logger):
        self.target = target
        self.config = config
        self.logger = logger
        self.results: Dict[str, Any] = {}

    @abstractmethod
    def run(self) -> Dict[str, Any]:
        pass
