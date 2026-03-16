"""
sentinel_audit/audit/lynis_adapter.py
──────────────────────────────────────
If Lynis is installed, run a quick audit and import results.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity


class LynisAdapterAuditor(BaseAuditor):
    """Integrate Lynis results if available."""

    name = "Lynis Adapter"
    category = "lynis"

    def run(self) -> None:
        # ── check for lynis ──────────────────
        r = self._run_command("which lynis")
        if not r.ok or not r.stdout:
            return  # Lynis not present

        # ── run lynis audit ───────────────────
        r = self._run_command("lynis audit system --quick --no-colors")
        if r.ok and r.stdout:
            for line in r.stdout.splitlines():
                if line.startswith("Warning"):
                    self._add_finding(
                        id="LYNIS-001",
                        title="Lynis warning",
                        description="Lynis reported a warning.",
                        severity=Severity.HIGH,
                        evidence=line,
                    )
                elif line.startswith("Suggestion"):
                    self._add_finding(
                        id="LYNIS-002",
                        title="Lynis suggestion",
                        description="Lynis suggested an improvement.",
                        severity=Severity.MEDIUM,
                        evidence=line,
                    )
