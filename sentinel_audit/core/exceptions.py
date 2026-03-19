"""
sentinel_audit/core/exceptions.py
──────────────────────────────────
Custom exception hierarchy for SentinelAudit.
"""

from __future__ import annotations


class SentinelAuditError(Exception):
    """Base exception for all SentinelAudit errors."""


class ConnectionError(SentinelAuditError):  # noqa: A001
    """Raised when an SSH or network connection cannot be established."""


class AuthenticationError(SentinelAuditError):
    """Raised when SSH authentication fails."""


class HostKeyVerificationError(SentinelAuditError):
    """Raised when the remote host key does not match known_hosts."""


class CommandExecutionError(SentinelAuditError):
    """Raised when a critical command fails and the audit cannot continue."""


class ConfigurationError(SentinelAuditError):
    """Raised when a configuration file or rule set is invalid."""


class AuditModuleError(SentinelAuditError):
    """Raised by an audit module when it encounters an unrecoverable error."""

    def __init__(self, module: str, message: str) -> None:
        self.module = module
        super().__init__(f"[{module}] {message}")


class ReportError(SentinelAuditError):
    """Raised when a report cannot be generated or written to disk."""


class InventoryError(SentinelAuditError):
    """Raised when the inventory file is invalid or unreadable."""
