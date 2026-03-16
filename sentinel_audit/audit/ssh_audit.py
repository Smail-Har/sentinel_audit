"""
sentinel_audit/audit/ssh_audit.py
───────────────────────────────────
Analyse /etc/ssh/sshd_config against the rules defined in
sentinel_audit/config/default_rules.yaml.
"""

from __future__ import annotations
import logging
from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity
from sentinel_audit.core.utils import parse_sshd_config

logger = logging.getLogger(__name__)

class SSHAuditor(BaseAuditor):
    """Audit SSH hardening directives in ``/etc/ssh/sshd_config``."""

    name = "SSH Audit"
    category = "ssh"

    def run(self) -> None:
        """Evaluate SSH directives and register findings for insecure values."""
        r = self._read_file("/etc/ssh/sshd_config")
        if not r.ok:
            self._add_finding(
                id="SSH-000",
                title="Impossible de lire sshd_config",
                description="Le fichier /etc/ssh/sshd_config n'est pas accessible.",
                severity=Severity.INFO,
                evidence=r.stderr,
                recommendation="Vérifiez les permissions du fichier.",
            )
            return
        config = parse_sshd_config(r.stdout)
        # Security check: direct root login must be disabled to reduce brute-force impact.
        val = config.get("PermitRootLogin", "yes")
        if val.lower() == "yes":
            self._add_finding(
                id="SSH-001",
                title="SSH: PermitRootLogin activé",
                description="L'accès root SSH est autorisé.",
                severity=Severity.CRITICAL,
                evidence=f"PermitRootLogin {val}",
                recommendation="Désactivez PermitRootLogin (no ou prohibit-password).",
            )
        # Security check: password auth increases brute-force surface.
        val = config.get("PasswordAuthentication", "yes")
        if val.lower() == "yes":
            self._add_finding(
                id="SSH-002",
                title="SSH: PasswordAuthentication activé",
                description="L'authentification par mot de passe SSH est activée.",
                severity=Severity.HIGH,
                evidence=f"PasswordAuthentication {val}",
                recommendation="Désactivez PasswordAuthentication et utilisez les clés SSH.",
            )
        # Security check: public-key auth is required for stronger authentication.
        val = config.get("PubkeyAuthentication", "no")
        if val.lower() != "yes":
            self._add_finding(
                id="SSH-003",
                title="SSH: PubkeyAuthentication désactivé",
                description="L'authentification par clé publique SSH est désactivée.",
                severity=Severity.MEDIUM,
                evidence=f"PubkeyAuthentication {val}",
                recommendation="Activez PubkeyAuthentication yes.",
            )
        # Security check: too many auth attempts facilitate credential stuffing.
        val = config.get("MaxAuthTries", "6")
        try:
            if int(val) > 3:
                self._add_finding(
                    id="SSH-004",
                    title="SSH: MaxAuthTries trop élevé",
                    description="MaxAuthTries autorise trop d'essais d'authentification.",
                    severity=Severity.MEDIUM,
                    evidence=f"MaxAuthTries {val}",
                    recommendation="Réduisez MaxAuthTries à 3 ou moins.",
                )
        except Exception:
            pass
