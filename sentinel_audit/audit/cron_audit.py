"""
sentinel_audit/audit/cron_audit.py
────────────────────────────────────
Inspect cron jobs for suspicious patterns.
Cron jobs list → inventory.  Only suspicious patterns → findings.
"""

from __future__ import annotations

import re

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

# Patterns that are suspicious in cron jobs
_SUSPICIOUS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"curl\s+.*(http|ftp)"), "Downloads content from the internet"),
    (re.compile(r"wget\s+.*(http|ftp)"), "Downloads content from the internet"),
    (re.compile(r"bash\s+-c\s+"), "Executes arbitrary shell commands"),
    (re.compile(r"/tmp/|/var/tmp/|/dev/shm/"), "References world-writable directory"),
    (re.compile(r"\|\s*bash|\|\s*sh"), "Pipes output to a shell interpreter"),
    (re.compile(r"chmod\s+777"), "Sets world-writable permissions"),
    (re.compile(r"nc\s+-[el]|ncat\s+-[el]|netcat"), "Uses netcat (potential reverse shell)"),
]


class CronAuditor(BaseAuditor):
    """Audit cron jobs for suspicious patterns."""

    name = "Cron Audit"
    category = "cron"

    def run(self) -> None:
        all_jobs: list[str] = []

        # System crontab
        r = self._read_file("/etc/crontab")
        if r.ok and r.stdout.strip():
            all_jobs.extend(self._extract_jobs(r.stdout))

        # /etc/cron.d
        r = self._run_command("cat /etc/cron.d/* 2>/dev/null || true")
        if r.ok and r.stdout.strip():
            all_jobs.extend(self._extract_jobs(r.stdout))

        # User crontabs (may fail for non-root — graceful degradation)
        r = self._run_command(
            "for u in $(cut -d: -f1 /etc/passwd); do "
            "crontab -l -u \"$u\" 2>/dev/null; done"
        )
        if self._is_permission_denied(r):
            # Try at least the current user's crontab
            r = self._run_command("crontab -l 2>/dev/null")
        if r.ok and r.stdout.strip():
            all_jobs.extend(self._extract_jobs(r.stdout))

        # Store as inventory
        self.result.system_info.cron_jobs = all_jobs[:50]  # cap for report readability

        # Check for suspicious patterns
        for job in all_jobs:
            for pattern, reason in _SUSPICIOUS_PATTERNS:
                if pattern.search(job):
                    self._add_finding(
                        id="CRON-001",
                        title="Suspicious cron job detected",
                        description=f"A cron job contains a suspicious pattern: {reason}.",
                        severity=Severity.MEDIUM,
                        evidence=job[:200],
                        recommendation=(
                            "Review this cron job and verify it is legitimate. "
                            "Remove if unauthorized."
                        ),
                    )
                    break  # One finding per job, even if multiple patterns match

    @staticmethod
    def _extract_jobs(text: str) -> list[str]:
        """Extract non-comment, non-empty lines from crontab content."""
        jobs: list[str] = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("SHELL=") \
               and not stripped.startswith("PATH=") and not stripped.startswith("MAILTO="):
                jobs.append(stripped)
        return jobs
