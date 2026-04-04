import logging
import json
import os
from datetime import datetime
from rich.logging import RichHandler
from typing import Any, Dict

class JSONLFormatter(logging.Formatter):
    """
    Format logs as JSONL (JSON Lines) for immutable forensic auditing.
    Captures structured metadata for later analysis.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
            "metadata": record.__dict__.get("extra_data", {})
        }
        return json.dumps(log_entry)

def setup_logger(output_dir: str = "reports", name: str = "Nexus", verbose: bool = False):
    """
    Initialize dual-channel logging:
    1. Rich console output for real-time visualization.
    2. JSONL file logging for persistent research traceability.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # 1. Console Handler (Rich)
    console_handler = RichHandler(rich_tracebacks=True, markup=True)
    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # 2. Forensic File Handler (JSONL)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        
    log_file = os.path.join(output_dir, f"forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(JSONLFormatter())
    file_handler.setLevel(logging.DEBUG) # Always log full detail to disk
    logger.addHandler(file_handler)

    return logger
