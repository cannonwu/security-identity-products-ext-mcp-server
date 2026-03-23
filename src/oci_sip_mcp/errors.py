"""Project-specific exceptions."""


class OCIIAMMCPError(Exception):
    """Base project error."""


class ConfigurationError(OCIIAMMCPError):
    """Raised when runtime configuration is invalid."""


class PolicyParseError(OCIIAMMCPError):
    """Raised when a policy statement cannot be parsed."""
