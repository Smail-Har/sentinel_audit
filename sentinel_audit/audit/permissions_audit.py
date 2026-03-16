"""
sentinel_audit/audit/permissions_audit.py
───────────────────────────────────────────
Check permissions of sensitive files: /etc/passwd, /etc/shadow, etc.
"""

from __future__ import annotations
import logging
from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity

logger = logging.getLogger(__name__)

FILES = [
    ("/etc/passwd", "644", Severity.MEDIUM),
    ("/etc/shadow", "640", Severity.CRITICAL),
    ("/etc/sudoers", "440", Severity.CRITICAL),
    ("/etc/ssh/sshd_config", "600", Severity.HIGH),
]

class PermissionsAuditor(BaseAuditor):
    """Validate permissions on high-sensitivity system files."""

    name = "Permissions Audit"
    category = "permissions"

    def run(self) -> None:
        """Check expected permission modes and emit findings on mismatch."""
        for path, expected, severity in FILES:
            # Security check: weak permissions on auth/sudo files can enable privilege abuse.
            r = self._run_command(f"stat -c '%a' {path}")
            if r.ok:
                actual = r.stdout.strip()
                if actual != expected:
                    self._add_finding(
                        id=f"PERM-{path.replace('/', '_')}",
                        title=f"Permissions incorrectes: {path}",
                        description=f"Le fichier {path} a des permissions {actual} au lieu de {expected}.",
                        severity=severity,
                        evidence=f"{path}: {actual}",
                        recommendation=f"chmod {expected} {path}",
                    )
            else:
                self._add_finding(
                    id=f"PERM-NOACCESS-{path.replace('/', '_')}",
                    title=f"Impossible de lire les permissions: {path}",
                    description=f"Impossible de lire les permissions de {path}.",
                    severity=Severity.INFO,
                    evidence=r.stderr,
                    recommendation="Vérifiez l'existence et les droits d'accès au fichier.",
                )
