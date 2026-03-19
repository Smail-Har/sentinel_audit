"""Shared test fixtures for SentinelAudit."""

from __future__ import annotations

from typing import Any

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult, CommandResult, Finding


class FakeExecutor:
    """Fake executor that returns pre-configured CommandResult responses."""

    def __init__(
        self,
        command_map: dict[str, CommandResult] | None = None,
        file_map: dict[str, CommandResult] | None = None,
        *,
        default_stdout: str = "",
        default_rc: int = 1,
    ) -> None:
        self.command_map: dict[str, CommandResult] = command_map or {}
        self.file_map: dict[str, CommandResult] = file_map or {}
        self._default_stdout = default_stdout
        self._default_rc = default_rc
        self.commands_run: list[str] = []
        self.files_read: list[str] = []

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        self.commands_run.append(command)
        return self.command_map.get(
            command,
            CommandResult(command=command, stdout=self._default_stdout, stderr="", return_code=self._default_rc),
        )

    def read_file(self, path: str) -> CommandResult:
        self.files_read.append(path)
        return self.file_map.get(
            path,
            CommandResult(command=f"read:{path}", stdout="", stderr="not found", return_code=1),
        )


def make_finding(
    id: str = "TEST-001",
    title: str = "Test finding",
    severity: Severity = Severity.MEDIUM,
    category: str = "test",
    **kwargs: Any,
) -> Finding:
    """Factory for creating test Finding objects."""
    return Finding(
        id=id,
        title=title,
        description=kwargs.get("description", "Test description"),
        severity=severity,
        category=category,
        evidence=kwargs.get("evidence", ""),
        recommendation=kwargs.get("recommendation", "Fix it"),
        reference=kwargs.get("reference", ""),
    )


def make_result(target: str = "localhost", **kwargs: Any) -> AuditResult:
    """Factory for creating test AuditResult objects."""
    return AuditResult(target=target, **kwargs)


def cmd(stdout: str = "", stderr: str = "", rc: int = 0) -> CommandResult:
    """Shortcut to create a CommandResult."""
    return CommandResult(command="", stdout=stdout, stderr=stderr, return_code=rc)
