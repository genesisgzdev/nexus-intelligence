"""
Advanced logging system using the Rich library for formatted console output.
"""
import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def setup_logger(name: str = "Nexus", verbose: bool = False) -> logging.Logger:
    """
    Configures and returns a logger with Rich formatting.
    
    Args:
        name: Name of the logger.
        verbose: If true, sets level to DEBUG.
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console, markup=True)]
    )
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger
