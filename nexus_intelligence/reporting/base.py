"""
Base reporting interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseReporter(ABC):
    """Abstract base for report generators."""
    
    def __init__(self, target: str, data: Dict[str, Any], output_path: str):
        self.target = target
        self.data = data
        self.output_path = output_path

    @abstractmethod
    def generate(self):
        """Executes the report generation."""
        pass
