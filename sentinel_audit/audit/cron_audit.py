"""
sentinel_audit/audit/cron_audit.py
────────────────────────────────────
Inspect /etc/crontab, /etc/cron.d, and user crontabs.
"""

from __future__ import annotations

from pathlib import Path

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity


class CronAuditor(BaseAuditor):
    """Audit system and user cron jobs."""

    name = "Cron Audit"
    category = "cron"

    def run(self) -> None:
        # ── /etc/crontab ─────────────────────
        r = self._read_file("/etc/crontab")
        if r.ok and r.stdout.strip():
            self._add_finding(
                id="CRON-001",
                title="System crontab present",
                description="/etc/crontab exists and may contain scheduled jobs.",
                severity=Severity.INFO,
                evidence=r.stdout,
            )

        # ── /etc/cron.d ──────────────────────
        r = self._run_command("ls -1 /etc/cron.d 2>/dev/null")
        if r.ok and r.stdout.strip():
            for fname in r.stdout.splitlines():
                self._add_finding(
                    id="CRON-002",
                    title=f"Cron job in /etc/cron.d: {fname}",
                    description="A job is scheduled in /etc/cron.d.",
                    severity=Severity.LOW,
                    evidence=fname,
                )

        # ── user crontabs ────────────────────
        r = self._run_command("ls -1 /var/spool/cron/crontabs 2>/dev/null")
        if r.ok and r.stdout.strip():
            for user in r.stdout.splitlines():
                self._add_finding(
                    id="CRON-003",
                    title=f"User crontab: {user}",
                    description="User has a personal crontab.",
                    severity=Severity.LOW,
                    evidence=user,
                )
