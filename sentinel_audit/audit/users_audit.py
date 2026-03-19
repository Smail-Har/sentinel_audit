"""
sentinel_audit/audit/users_audit.py
─────────────────────────────────────
Check for UID 0 accounts, NOPASSWD sudo, password-less accounts.
Inventory (user list, sudo members) goes to SystemInfo — not as findings.
"""

from __future__ import annotations

import logging

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

logger = logging.getLogger(__name__)

# Shells that indicate a non-interactive (service) account
_NOLOGIN_SHELLS = frozenset({
    "/usr/sbin/nologin", "/bin/false", "/sbin/nologin", "/bin/nologin",
})


class UsersAuditor(BaseAuditor):
    """Audit user accounts and privilege configurations."""

    name = "Users Audit"
    category = "users"

    def run(self) -> None:
        self._check_uid0_accounts()
        self._check_nopasswd_sudo()
        self._check_empty_passwords()
        self._collect_user_inventory()

    def _check_uid0_accounts(self) -> None:
        """Only root should have UID 0."""
        r = self._read_file("/etc/passwd")
        if not r.ok:
            self._record_error("Cannot read /etc/passwd")
            return

        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) > 2 and parts[2] == "0" and parts[0] != "root":
                self._add_finding(
                    id="USR-001",
                    title=f"Non-root account with UID 0: {parts[0]}",
                    description=(
                        f"Account '{parts[0]}' has UID 0, giving it full root "
                        f"privileges. Only the root account should have UID 0."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"{parts[0]}:x:0:...",
                    recommendation=f"Remove or change the UID of account '{parts[0]}'.",
                )

    def _check_nopasswd_sudo(self) -> None:
        """Detect NOPASSWD entries in sudoers."""
        r = self._run_command("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>&1 || true")
        if self._is_permission_denied(r):
            self._add_finding(
                id="USR-002",
                title="Cannot check sudoers — insufficient privileges",
                description="Cannot read /etc/sudoers. NOPASSWD entries could not be verified.",
                severity=Severity.INFO,
                evidence="Permission denied reading /etc/sudoers",
                recommendation="Re-run audit as root to check sudoers configuration.",
            )
            return
        if r.ok and r.stdout.strip():
            lines = [
                ln for ln in r.stdout.splitlines()
                if "NOPASSWD" in ln and not ln.strip().startswith("#")
            ]
            if lines:
                self._add_finding(
                    id="USR-002",
                    title="NOPASSWD sudo entries detected",
                    description=(
                        "One or more sudoers entries allow command execution "
                        "without password confirmation, reducing accountability."
                    ),
                    severity=Severity.HIGH,
                    evidence="\n".join(lines[:5]),
                    recommendation=(
                        "Remove NOPASSWD from sudoers entries unless strictly "
                        "required for automated processes."
                    ),
                )

    def _check_empty_passwords(self) -> None:
        """Detect accounts with empty password fields in /etc/shadow."""
        r = self._run_command("awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>&1")
        if self._is_permission_denied(r):
            self._add_finding(
                id="USR-003",
                title="Cannot check empty passwords — insufficient privileges",
                description="/etc/shadow is not readable. Cannot verify empty password accounts.",
                severity=Severity.INFO,
                evidence="Permission denied reading /etc/shadow",
                recommendation="Re-run audit as root or grant read access to /etc/shadow.",
            )
            return
        if r.ok and r.stdout.strip():
            accounts = [a.strip() for a in r.stdout.splitlines() if a.strip()]
            if accounts:
                self._add_finding(
                    id="USR-003",
                    title="Accounts with empty passwords",
                    description=(
                        f"The following accounts have no password set: "
                        f"{', '.join(accounts)}. Anyone can log in without credentials."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Empty password accounts: {', '.join(accounts)}",
                    recommendation="Set passwords or lock these accounts: passwd -l <user>",
                )

    def _collect_user_inventory(self) -> None:
        """Populate SystemInfo with user account inventory (not findings)."""
        r = self._read_file("/etc/passwd")
        if not r.ok:
            return

        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username = parts[0]
            uid = parts[2]
            shell = parts[6]
            is_interactive = shell not in _NOLOGIN_SHELLS
            self.result.system_info.user_accounts.append({
                "username": username,
                "uid": uid,
                "shell": shell,
                "interactive": str(is_interactive),
            })
