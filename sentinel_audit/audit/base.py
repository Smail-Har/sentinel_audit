"""
sentinel_audit/audit/base.py
─────────────────────────────
Abstract base class that every audit module must inherit from.

Architecture contract
─────────────────────
A module:

1.  Inherits :class:`BaseAuditor`.
2.  Implements :meth:`run` which may call helpers via ``self.executor``.
3.  Adds findings via ``self.result.add_finding(…)``.
4.  Never raises unhandled exceptions externally — catches errors and
    appends them to ``self.result.audit_errors`` instead.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from sentinel_audit.core.executor import BaseExecutor
from sentinel_audit.core.models import AuditResult, Finding, Severity

logger = logging.getLogger(__name__)


class BaseAuditor(ABC):
    """
    Abstract auditor.  All concrete audit modules extend this class.

    Parameters
    ----------
    executor:
        The command executor to use (local or remote).
    result:
        The shared :class:`~sentinel_audit.core.models.AuditResult` to
        populate with findings.
    config:
        Optional dict of module-specific configuration values.
    """

    #: Human-readable name shown in logs and reports.
    name: str = "BaseAuditor"

    #: Category tag stored on every finding this module produces.
    category: str = "generic"

    def __init__(
        self,
        executor: BaseExecutor,
        result: AuditResult,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        self.executor = executor
        self.result = result
        self.config: dict[str, Any] = config or {}
        self._log = logging.getLogger(f"sentinel_audit.audit.{self.category}")

    # ── public interface ──────────────────────

    @abstractmethod
    def run(self) -> None:
        """
        Execute the audit and populate ``self.result`` with findings.

        Must never raise; catch all exceptions and append a message to
        ``self.result.audit_errors``.
        """
        ...

    # ── protected helpers ─────────────────────

    def _add_finding(
        self,
        *,
        id: str,
        title: str,
        description: str,
        severity: Severity,
        evidence: str = "",
        recommendation: str = "",
        reference: str = "",
    ) -> None:
        """Convenience wrapper for creating and registering a finding."""
        finding = Finding(
            id=id,
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            evidence=evidence,
            recommendation=recommendation,
            reference=reference,
        )
        self.result.add_finding(finding)
        self._log.debug("Finding registered: [%s] %s (%s)", id, title, severity.value)

    def _record_error(self, message: str) -> None:
        """Append a non-fatal error message to the audit result."""
        full_msg = f"[{self.name}] {message}"
        self._log.warning(full_msg)
        self.result.audit_errors.append(full_msg)

    def _run_command(self, command: str, timeout: int = 30):
        """
        Run *command* and return the result; record errors gracefully.

        Returns a :class:`~sentinel_audit.core.models.CommandResult`.
        """
        try:
            return self.executor.run(command, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Command failed '{command}': {exc}")
            from sentinel_audit.core.models import CommandResult
            return CommandResult(command=command, stdout="", stderr=str(exc), return_code=-1)

    def _read_file(self, path: str):
        """Read a file; record errors gracefully."""
        try:
            return self.executor.read_file(path)
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Cannot read file '{path}': {exc}")
            from sentinel_audit.core.models import CommandResult
            return CommandResult(command=f"read:{path}", stdout="", stderr=str(exc), return_code=-1)
