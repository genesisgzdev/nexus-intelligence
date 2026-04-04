"""
JSON report generator.
"""
import json
from nexus_intelligence.reporting.base import BaseReporter

class JSONReporter(BaseReporter):
    """Outputs findings in structured JSON format."""
    
    def generate(self):
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": self.target,
                "findings": self.data
            }, f, indent=4)
