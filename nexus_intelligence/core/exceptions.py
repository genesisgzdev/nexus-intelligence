"""
Custom exceptions for the Nexus Intelligence Framework.
"""

class NexusError(Exception):
    """Base exception for all Nexus errors."""
    pass

class AnalysisError(NexusError):
    """Raised when an analysis module fails."""
    pass

class ReportingError(NexusError):
    """Raised when a report generator fails."""
    pass

class ConfigurationError(NexusError):
    """Raised when configuration is invalid."""
    pass
