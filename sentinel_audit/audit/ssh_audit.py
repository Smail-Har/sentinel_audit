"""
sentinel_audit/audit/ssh_audit.py
───────────────────────────────────
Analyse /etc/ssh/sshd_config against rules from default_rules.yaml.
All findings in English.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity
from sentinel_audit.core.utils import parse_sshd_config

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent / "config" / "default_rules.yaml"

# sshd defaults used when a directive is absent from the config file
_SSHD_DEFAULTS: dict[str, str] = {
    "PermitRootLogin": "prohibit-password",
    "PasswordAuthentication": "yes",
    "PubkeyAuthentication": "yes",
    "X11Forwarding": "no",
    "MaxAuthTries": "6",
    "PermitEmptyPasswords": "no",
    "UsePAM": "yes",
    "Protocol": "2",
}


class SSHAuditor(BaseAuditor):
    """Audit SSH hardening directives against YAML rules."""

    name = "SSH Audit"
    category = "ssh"

    def run(self) -> None:
        r = self._read_file("/etc/ssh/sshd_config")
        if not r.ok:
            self._add_finding(
                id="SSH-000",
                title="Cannot read sshd_config",
                description="/etc/ssh/sshd_config is not accessible.",
                severity=Severity.INFO,
                evidence=r.stderr,
                recommendation="Check file permissions or run audit with appropriate privileges.",
            )
            return

        config = parse_sshd_config(r.stdout)
        rules = self._load_ssh_rules()

        for rule in rules:
            directive = rule["directive"]
            actual = config.get(directive, _SSHD_DEFAULTS.get(directive, ""))

            # Check dangerous_values (exact match)
            if "dangerous_values" in rule:
                if actual.lower() in [v.lower() for v in rule["dangerous_values"]]:
                    self._add_finding(
                        id=rule["id"],
                        title=f"SSH: {directive} set to insecure value",
                        description=rule["description"],
                        severity=Severity(rule["severity"]),
                        evidence=f"{directive} {actual}",
                        recommendation=rule["recommendation"],
                    )

            # Check max_value (integer comparison)
            if "max_value" in rule:
                try:
                    if int(actual) > rule["max_value"]:
                        self._add_finding(
                            id=rule["id"],
                            title=f"SSH: {directive} too high ({actual})",
                            description=rule["description"],
                            severity=Severity(rule["severity"]),
                            evidence=f"{directive} {actual}",
                            recommendation=rule["recommendation"],
                        )
                except (ValueError, TypeError):
                    pass

    def _load_ssh_rules(self) -> list[dict[str, object]]:
        try:
            with open(_RULES_PATH, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data.get("ssh_rules", [])  # type: ignore[no-any-return]
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Cannot load SSH rules: {exc}")
            return []
