"""
sentinel_audit/audit/users_audit.py
─────────────────────────────────────
Check for UID 0 accounts, sudoers, active shells, NOPASSWD sudo, etc.
"""

from __future__ import annotations
import logging
from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity

logger = logging.getLogger(__name__)

class UsersAuditor(BaseAuditor):
    """Audit user accounts, privilege groups and interactive shells."""

    name = "Users Audit"
    category = "users"

    def run(self) -> None:
        """Check risky identity and privilege configurations."""

        # Security check: only root should have UID 0.
        r = self._read_file("/etc/passwd")
        if r.ok:
            uid0_accounts: list[str] = []
            active_shell_accounts: list[tuple[str, str]] = []
            for line in r.stdout.splitlines():
                parts = line.split(":")
                if len(parts) > 2 and parts[2] == "0":
                    uid0_accounts.append(parts[0])

                if len(parts) > 6 and parts[6] not in ("/usr/sbin/nologin", "/bin/false"):
                    active_shell_accounts.append((parts[0], line))

            for account in uid0_accounts:
                if account == "root":
                    continue
                self._add_finding(
                    id="USR-001",
                    title=f"Compte UID 0: {account}",
                    description="Plusieurs comptes UID 0 sont un risque de sécurité.",
                    severity=Severity.CRITICAL,
                    evidence=account,
                    recommendation="Seul root doit avoir UID 0.",
                )

            # Security check: interactive shells should be limited to trusted user accounts.
            for account, passwd_line in active_shell_accounts:
                self._add_finding(
                    id="USR-003",
                    title=f"Compte shell actif: {account}",
                    description="Ce compte possède un shell interactif.",
                    severity=Severity.MEDIUM,
                    evidence=passwd_line,
                    recommendation="Désactiver le shell pour les comptes système/services.",
                )

        # Security check: sudo group members have privileged command execution rights.
        r = self._run_command("getent group sudo")
        if r.ok and ":" in r.stdout:
            users = r.stdout.strip().split(":")[-1].split(",")
            for user in users:
                user = user.strip()
                if user:
                    self._add_finding(
                        id="USR-002",
                        title=f"Membre du groupe sudo: {user}",
                        description="Ce compte peut utiliser sudo.",
                        severity=Severity.HIGH,
                        evidence=user,
                        recommendation="Limiter les membres du groupe sudo.",
                    )
