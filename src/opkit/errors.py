"""Unified exception hierarchy for opkit.

Before this module existed, the three transport modules each declared their
own ``RuntimeError`` subclass (``SSHExecError``, ``SessionError``,
``HTTPBackendError``) while config used a ``ValueError``. Callers that wanted
to catch anything opkit raises had to enumerate unrelated types.

The hierarchy is deliberately tiny:

- ``OpkitError``     — base for everything opkit raises; UI layers catch this.
- ``ConfigError``    — configuration could not be loaded or violates the schema.
- ``ProtocolError``  — a runtime operation against a device failed (connect,
                      authentication, malformed request, timeout, ...).

Messages stay human-readable and instructive ("call open_session first")
because they propagate uncaught through FastMCP back to the calling model.
"""

from __future__ import annotations


class OpkitError(RuntimeError):
    """Base class for every exception opkit raises."""


class ConfigError(OpkitError):
    """Raised when the configuration cannot be loaded or fails validation."""


class ProtocolError(OpkitError):
    """Raised when an operation against a device fails at runtime."""
