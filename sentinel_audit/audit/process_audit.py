"""
sentinel_audit/audit/process_audit.py
──────────────────────────────────────
List root processes and those exposing network ports.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity


class ProcessAuditor(BaseAuditor):
    """Audit sensitive processes (root, network-exposed)."""

    name = "Process Audit"
    category = "process"

    def run(self) -> None:
        # ── root processes ───────────────────
        r = self._run_command("ps -eo user,pid,comm | grep '^root '")
        if r.ok:
            for line in r.stdout.splitlines():
                self._add_finding(
                    id="PROC-001",
                    title="Root-owned process",
                    description="A process is running as root.",
                    severity=Severity.MEDIUM,
                    evidence=line,
                )

        # ── processes exposing ports ──────────
        r = self._run_command("ss -tlnup 2>/dev/null")
        if r.ok:
            for line in r.stdout.splitlines():
                if "/" in line:
                    self._add_finding(
                        id="PROC-002",
                        title="Process exposing network port",
                        description="A process is listening on a network port.",
                        severity=Severity.HIGH,
                        evidence=line,
                    )
