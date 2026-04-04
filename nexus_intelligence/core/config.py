import os

class Config:
    def __init__(self):
        self.timeout = int(os.getenv("NEXUS_TIMEOUT", 15))
        self.max_threads = int(os.getenv("NEXUS_THREADS", 8))
        self.output_dir = os.getenv("NEXUS_OUTPUT_DIR", "reports")
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
