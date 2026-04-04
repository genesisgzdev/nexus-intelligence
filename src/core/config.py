import os
from typing import Dict, Any

class Config:
    def __init__(self):
        self.timeout = int(os.getenv("NEXUS_TIMEOUT", 10))
        self.user_agent = os.getenv("NEXUS_USER_AGENT", "NexusIntelligence/1.0 (Security Scanner)")
        self.output_dir = os.getenv("NEXUS_OUTPUT_DIR", "reports")
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
