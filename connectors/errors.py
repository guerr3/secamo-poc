from __future__ import annotations


class ConnectorError(Exception):
    """Base exception for connector-layer failures."""


class ConnectorPermanentError(ConnectorError):
    """Failure that should not be retried without input/config changes."""


class ConnectorTransientError(ConnectorError):
    """Failure that may succeed when retried."""


class ConnectorConfigurationError(ConnectorPermanentError):
    """Invalid connector configuration or provider selection."""


class ConnectorUnsupportedActionError(ConnectorPermanentError):
    """Unsupported connector action for the selected provider."""
