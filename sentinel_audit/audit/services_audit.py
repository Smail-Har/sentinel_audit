"""
sentinel_audit/audit/services_audit.py
───────────────────────────────────────
Collect running/enabled services as **inventory**.
Only produce findings for known-dangerous services.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

# Services that should generally NOT be running on a hardened server
_DANGEROUS_SERVICES: frozenset[str] = frozenset(
    {
        "telnet",
        "telnetd",
        "rsh",
        "rshd",
        "rlogin",
        "rlogind",
        "tftp",
        "tftpd",
        "vsftpd",
        "proftpd",
        "pure-ftpd",
        "xinetd",
        "rpcbind",
        "avahi-daemon",
        "cups",
    }
)


class ServicesAuditor(BaseAuditor):
    """Audit running and enabled services.

    Running/enabled services are collected as inventory.
    Only known-dangerous or legacy services generate findings.
    """

    name = "Services Audit"
    category = "services"

    def run(self) -> None:
        self._collect_running_services()
        self._collect_enabled_services()
        self._check_dangerous_services()

    def _collect_running_services(self) -> None:
        """Collect running services into SystemInfo inventory."""
        r = self._run_command(
            "systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null"
        )
        if r.ok and r.stdout.strip():
            for line in r.stdout.splitlines():
                svc = line.split()[0] if line.split() else ""
                if svc:
                    self.result.system_info.running_services.append(svc)

    def _collect_enabled_services(self) -> None:
        """Collect boot-enabled services into SystemInfo inventory."""
        r = self._run_command(
            "systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend --plain 2>/dev/null"
        )
        if r.ok and r.stdout.strip():
            for line in r.stdout.splitlines():
                svc = line.split()[0] if line.split() else ""
                if svc:
                    self.result.system_info.enabled_services.append(svc)

    def _check_dangerous_services(self) -> None:
        """Flag known-dangerous or legacy services."""
        all_services = self.result.system_info.running_services + self.result.system_info.enabled_services
        flagged: set[str] = set()
        for svc in all_services:
            svc_name = svc.replace(".service", "").lower()
            if svc_name in _DANGEROUS_SERVICES and svc_name not in flagged:
                flagged.add(svc_name)
                self._add_finding(
                    id="SRV-001",
                    title=f"Dangerous service active: {svc_name}",
                    description=(
                        f"The service '{svc_name}' is known to be insecure or unnecessary on a hardened server."
                    ),
                    severity=Severity.HIGH,
                    evidence=svc,
                    recommendation=(f"Disable and stop this service: systemctl disable --now {svc_name}"),
                )
