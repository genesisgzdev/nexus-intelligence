"""
Configuration management for Nexus Intelligence.
Handles environment variables and global settings.
"""
import os
from typing import Dict

class Config:
    """Central configuration class for the framework."""

    def __init__(self):
        self.timeout = int(os.getenv("NEXUS_TIMEOUT", 15))
        self.user_agent = os.getenv(
            "NEXUS_USER_AGENT", 
            "NexusIntelligence/2.0 (Security Forensic Analyzer; Enterprise Edition)"
        )
        self.output_dir = os.getenv("NEXUS_OUTPUT_DIR", "reports")
        self.max_threads = int(os.getenv("NEXUS_THREADS", 5))
        
        # Ensure output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

    def get_http_headers(self) -> Dict[str, str]:
        """Returns standard HTTP headers for passive fingerprinting."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        }
