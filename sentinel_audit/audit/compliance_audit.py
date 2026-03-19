"""
sentinel_audit/audit/compliance_audit.py
─────────────────────────────────────────
Run compliance checks (CIS, etc.) from YAML rules using regex matching.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

_RULES_PATH = Path(__file__).parent.parent / "config" / "default_rules.yaml"


class ComplianceAuditor(BaseAuditor):
    """Run compliance checks from YAML rules (CIS benchmarks)."""

    name = "Compliance Audit"
    category = "compliance"

    def run(self) -> None:
        rules = self._load_compliance_checks()
        for rule in rules:
            cmd = rule["command"]
            pass_pattern = rule["pass_pattern"]

            r = self._run_command(cmd)
            if not r.ok:
                if self._is_permission_denied(r):
                    self._add_finding(
                        id=rule["id"],
                        title=f"Cannot verify: {rule['title']} — insufficient privileges",
                        description=(f"Compliance check skipped due to insufficient privileges: {rule['title']}"),
                        severity=Severity.INFO,
                        evidence=f"Permission denied: {cmd}",
                        recommendation="Re-run audit with elevated privileges.",
                    )
                else:
                    self._record_error(f"Compliance check {rule['id']} command failed: {r.stderr}")
                continue

            # Use regex matching (not substring)
            if not re.search(pass_pattern, r.stdout):
                self._add_finding(
                    id=rule["id"],
                    title=rule["title"],
                    description=f"Compliance check failed: {rule['title']}",
                    severity=Severity(rule["severity"]),
                    evidence=r.stdout[:200] if r.stdout else "No output",
                    recommendation=rule["recommendation"],
                )

    def _load_compliance_checks(self) -> list[dict[str, str]]:
        try:
            with open(_RULES_PATH, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data.get("compliance_checks", [])  # type: ignore[no-any-return]
        except Exception as exc:
            self._record_error(f"Cannot load compliance checks: {exc}")
            return []
