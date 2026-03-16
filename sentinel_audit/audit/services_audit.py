"""
sentinel_audit/audit/services_audit.py
───────────────────────────────────────
List active services, services exposed on the network, and boot services.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity


class ServicesAuditor(BaseAuditor):
    """Audit running and enabled services."""

    name = "Services Audit"
    category = "services"

    def run(self) -> None:
        # ── active services ──────────────────
        r = self._run_command("systemctl list-units --type=service --state=running --no-pager")
        if r.ok:
            for line in r.stdout.splitlines():
                if ".service" in line:
                    self._add_finding(
                        id="SRV-001",
                        title="Active service detected",
                        description="A service is running.",
                        severity=Severity.INFO,
                        evidence=line,
                        recommendation="Review running services and disable unnecessary ones.",
                    )

        # ── enabled at boot ──────────────────
        r = self._run_command("systemctl list-unit-files --type=service --state=enabled --no-pager")
        if r.ok:
            for line in r.stdout.splitlines():
                if ".service" in line:
                    self._add_finding(
                        id="SRV-002",
                        title="Service enabled at boot",
                        description="A service is enabled to start at boot.",
                        severity=Severity.LOW,
                        evidence=line,
                        recommendation="Disable unnecessary services at boot.",
                    )

        # ── network-exposed services ─────────
        r = self._run_command("ss -tlnup 2>/dev/null")
        if r.ok:
            for line in r.stdout.splitlines():
                if "/" in line:
                    self._add_finding(
                        id="SRV-003",
                        title="Network-exposed service",
                        description="A service is listening on a network port.",
                        severity=Severity.HIGH,
                        evidence=line,
                        recommendation="Restrict network exposure to required services only.",
                    )
