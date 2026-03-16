"""
sentinel_audit/audit/packages_audit.py
───────────────────────────────────────
Collect package manager, installed packages, and available updates.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity
from sentinel_audit.core.utils import detect_os_family


class PackagesAuditor(BaseAuditor):
    """Audit installed packages and update status."""

    name = "Packages Audit"
    category = "packages"

    def run(self) -> None:
        # ── detect package manager ────────────
        r = self._run_command("cat /etc/os-release")
        os_id = "unknown"
        if r.ok:
            for line in r.stdout.splitlines():
                if line.startswith("ID="):
                    os_id = line.split("=", 1)[1].strip().strip('"')
        family = detect_os_family(os_id)

        if family == "debian":
            self._audit_debian()
        elif family == "rhel":
            self._audit_rhel()
        else:
            self._record_error("Unknown or unsupported OS family for package audit.")

    def _audit_debian(self):
        # List installed packages
        r = self._run_command("dpkg-query -W -f='${Package}\n'")
        if r.ok:
            for pkg in r.stdout.splitlines():
                self._add_finding(
                    id="PKG-001",
                    title=f"Installed package: {pkg}",
                    description="Package is installed.",
                    severity=Severity.INFO,
                    evidence=pkg,
                )
        # Check for available updates
        r = self._run_command("apt list --upgradable 2>/dev/null | tail -n +2")
        if r.ok and r.stdout:
            for line in r.stdout.splitlines():
                pkg = line.split("/", 1)[0]
                self._add_finding(
                    id="PKG-002",
                    title=f"Upgradable package: {pkg}",
                    description="A newer version is available.",
                    severity=Severity.LOW,
                    evidence=line,
                    recommendation="Update this package.",
                )

    def _audit_rhel(self):
        # List installed packages
        r = self._run_command("rpm -qa --qf '%{NAME}\n'")
        if r.ok:
            for pkg in r.stdout.splitlines():
                self._add_finding(
                    id="PKG-003",
                    title=f"Installed package: {pkg}",
                    description="Package is installed.",
                    severity=Severity.INFO,
                    evidence=pkg,
                )
        # Check for available updates
        r = self._run_command("yum check-update 2>/dev/null")
        if r.ok and r.stdout:
            for line in r.stdout.splitlines():
                if not line or line.startswith("Loaded plugins") or ".x86_64" not in line:
                    continue
                pkg = line.split()[0]
                self._add_finding(
                    id="PKG-004",
                    title=f"Upgradable package: {pkg}",
                    description="A newer version is available.",
                    severity=Severity.LOW,
                    evidence=line,
                    recommendation="Update this package.",
                )
