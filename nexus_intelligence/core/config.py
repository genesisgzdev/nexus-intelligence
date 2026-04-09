from typing import Optional, List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import os

class NexusSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NEXUS_",
        env_file=".env",
        extra="ignore"
    )

    # Core Parameters
    timeout: int = Field(default=15, gt=0)
    max_concurrent: int = Field(default=100, gt=0)
    output_dir: str = Field(default="reports")
    verbose: bool = Field(default=False)

    # Enterprise Persistence (Added)
    redis_url: Optional[str] = Field(default=None, description="Redis for result caching and task queuing")
    mongodb_url: Optional[str] = Field(default=None, description="MongoDB for persistent intelligence graph")
    milvus_url: Optional[str] = Field(default=None, description="Vector DB for similarity-based threat intelligence")

    # Networking
    proxy_url: Optional[str] = Field(default=None)
    allow_external_ct: bool = Field(default=False)
    doh_endpoint: str = Field(default="https://cloudflare-dns.com/dns-query")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

config = NexusSettings()
