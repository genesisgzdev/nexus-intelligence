from typing import Optional, List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import os

class NexusSettings(BaseSettings):
    """
    Nexus Intelligence Core Configuration Schema.
    Validates environment variables with strict typing.
    """
    model_config = SettingsConfigDict(
        env_prefix="NEXUS_",
        env_file=".env",
        extra="ignore"
    )

    # Core engine parameters
    timeout: int = Field(default=15, gt=0, description="Global request timeout in seconds")
    max_threads: int = Field(default=8, gt=0, description="Max parallel module execution")
    output_dir: str = Field(default="reports", description="Base directory for forensic logs")
    verbose: bool = Field(default=False)

    # OPSEC & Networking
    proxy_url: Optional[str] = Field(default=None, description="SOCKS5/HTTP proxy (e.g. socks5://127.0.0.1:9050)")
    use_tor: bool = Field(default=False, description="Enable automatic Tor circuit control")
    allow_external_ct: bool = Field(default=False, description="Explicitly allow external CT log lookups (Breaks Zero-API Mandate)")
    
    # DNS Intelligence (Privacy-oriented)
    dns_resolvers: List[str] = Field(
        default=["1.1.1.1", "9.9.9.9", "8.8.8.8"],
        description="Standard DNS resolvers"
    )
    doh_endpoint: str = Field(
        default="https://cloudflare-dns.com/dns-query",
        description="DNS-over-HTTPS endpoint for leak prevention"
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

# Export singleton instance
config = NexusSettings()
