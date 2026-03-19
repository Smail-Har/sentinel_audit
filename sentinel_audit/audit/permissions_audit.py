"""
sentinel_audit/audit/permissions_audit.py
───────────────────────────────────────────
Check permissions of sensitive files against YAML rules.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

logger = logging.getLogger(__name__)

_RULES_PATH = Path(__file__).parent.parent / "config" / "default_rules.yaml"


class PermissionsAuditor(BaseAuditor):
    """Validate permissions on high-sensitivity system files using YAML rules."""

    name = "Permissions Audit"
    category = "permissions"

    def run(self) -> None:
        rules = self._load_permission_rules()
        if not rules:
            self._record_error("No permission rules loaded.")
            return

        for rule in rules:
            path = rule["path"]
            expected = rule["expected_mode"]
            r = self._run_command(f"stat -c '%a' {path}")
            if r.ok:
                actual = r.stdout.strip().strip("'")
                if actual != expected:
                    self._add_finding(
                        id=rule["id"],
                        title=f"Incorrect permissions on {path}",
                        description=rule["description"],
                        severity=Severity(rule["severity"]),
                        evidence=f"{path}: mode {actual} (expected {expected})",
                        recommendation=rule["recommendation"],
                    )
            else:
                self._add_finding(
                    id=f"{rule['id']}-NOACCESS",
                    title=f"Cannot read permissions: {path}",
                    description=f"Unable to stat {path}. File may not exist or access is denied.",
                    severity=Severity.INFO,
                    evidence=r.stderr,
                    recommendation="Verify the file exists and audit user has read access.",
                )

    def _load_permission_rules(self) -> list[dict[str, str]]:
        try:
            with open(_RULES_PATH, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data.get("file_permission_rules", [])  # type: ignore[no-any-return]
        except Exception as exc:
            self._record_error(f"Cannot load permission rules: {exc}")
            return []
