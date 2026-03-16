"""
sentinel_audit/audit/kernel_audit.py
─────────────────────────────────────
Check kernel parameters and sysctl settings against rules.
"""

from __future__ import annotations

import yaml
from pathlib import Path

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity

_RULES_PATH = Path(__file__).parent.parent / "config" / "default_rules.yaml"


class KernelAuditor(BaseAuditor):
    """Audit kernel and sysctl parameters."""

    name = "Kernel Audit"
    category = "kernel"

    def run(self) -> None:
        rules = self._load_sysctl_rules()
        for rule in rules:
            key = rule["key"]
            expected = rule["expected_value"]
            r = self._run_command(f"sysctl -n {key}")
            if r.ok:
                actual = r.stdout.strip()
                if actual != expected:
                    self._add_finding(
                        id=rule["id"],
                        title=f"Sysctl {key} = {actual} (expected {expected})",
                        description=rule["description"],
                        severity=Severity(rule["severity"]),
                        evidence=f"{key} = {actual}",
                        recommendation=rule["recommendation"],
                    )
            else:
                self._record_error(f"Cannot read sysctl {key}: {r.stderr}")

    def _load_sysctl_rules(self):
        try:
            with open(_RULES_PATH, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data.get("sysctl_rules", [])
        except Exception as exc:  # noqa: BLE001
            self._record_error(f"Cannot load sysctl rules: {exc}")
            return []
