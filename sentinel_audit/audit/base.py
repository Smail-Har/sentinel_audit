"""
sentinel_audit/audit/base.py
─────────────────────────────
Abstract base class that every audit module must inherit from.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.executor import BaseExecutor
from sentinel_audit.core.models import AuditResult, CommandResult, Finding
from sentinel_audit.core.utils import sanitise_evidence

logger = logging.getLogger(__name__)


class BaseAuditor(ABC):
    """Abstract auditor.  All concrete audit modules extend this class."""

    name: str = "BaseAuditor"
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

    @abstractmethod
    def run(self) -> None:
        """Execute the audit and populate ``self.result`` with findings."""
        ...

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
        """Create and register a finding with sanitised evidence."""
        finding = Finding(
            id=id,
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            evidence=sanitise_evidence(evidence),
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

    def _run_command(self, command: str, timeout: int = 30) -> CommandResult:
        """Run *command* and return the result; record errors gracefully."""
        try:
            return self.executor.run(command, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Command failed '{command}': {exc}")
            return CommandResult(command=command, stdout="", stderr=str(exc), return_code=-1)

    @staticmethod
    def _is_permission_denied(result: CommandResult) -> bool:
        """Return True if *result* failed due to insufficient privileges."""
        if result.ok:
            return False
        combined = (result.stdout + result.stderr).lower()
        return any(kw in combined for kw in (
            "permission denied", "not permitted", "operation not permitted",
            "you need to be root", "must be root", "requires root",
            "access denied", "insufficient privileges",
        ))

    def _read_file(self, path: str) -> CommandResult:
        """Read a file; record errors gracefully."""
        try:
            return self.executor.read_file(path)
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Cannot read file '{path}': {exc}")
            return CommandResult(command=f"read:{path}", stdout="", stderr=str(exc), return_code=-1)
