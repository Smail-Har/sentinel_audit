"""
sentinel_audit/audit/network_audit.py
──────────────────────────────────────
List open ports, associated services, and processes.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity
from sentinel_audit.core.utils import parse_ss_output


class NetworkAuditor(BaseAuditor):
    """Audit open network ports and associated processes."""

    name = "Network Audit"
    category = "network"

    def run(self) -> None:
        r = self._run_command("ss -tlnup 2>/dev/null")
        if r.ok:
            entries = parse_ss_output(r.stdout)
            for entry in entries:
                self._add_finding(
                    id="NET-001",
                    title=f"Open port: {entry['local_address']}:{entry['local_port']}",
                    description="A process is listening on a network port.",
                    severity=Severity.HIGH,
                    evidence=str(entry),
                    recommendation="Restrict open ports to required services only.",
                )
