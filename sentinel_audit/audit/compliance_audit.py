"""
sentinel_audit/audit/compliance_audit.py
─────────────────────────────────────────
Run compliance checks (CIS, etc.) from YAML rules.
"""

from __future__ import annotations

import yaml
from pathlib import Path

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity

_RULES_PATH = Path(__file__).parent.parent / "config" / "default_rules.yaml"


class ComplianceAuditor(BaseAuditor):
    """Run compliance checks from YAML rules (CIS, etc.)."""

    name = "Compliance Audit"
    category = "compliance"

    def run(self) -> None:
        rules = self._load_compliance_checks()
        for rule in rules:
            cmd = rule["command"]
            r = self._run_command(cmd)
            if r.ok and rule["pass_pattern"] not in r.stdout:
                self._add_finding(
                    id=rule["id"],
                    title=rule["title"],
                    description=f"Compliance check failed: {rule['title']}",
                    severity=Severity(rule["severity"]),
                    evidence=r.stdout,
                    recommendation=rule["recommendation"],
                )

    def _load_compliance_checks(self):
        try:
            with open(_RULES_PATH, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data.get("compliance_checks", [])
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Cannot load compliance checks: {exc}")
            return []
