"""
sentinel_audit/audit/packages_audit.py
───────────────────────────────────────
Collect package inventory and check for pending security updates.
Package list → inventory (SystemInfo).
Pending updates → ONE aggregated finding (not one per package).
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity
from sentinel_audit.core.utils import detect_os_family


class PackagesAuditor(BaseAuditor):
    """Audit installed packages and update status."""

    name = "Packages Audit"
    category = "packages"

    def run(self) -> None:
        os_id = self._detect_os_id()
        family = detect_os_family(os_id)

        if family == "debian":
            self._audit_debian()
        elif family == "rhel":
            self._audit_rhel()
        elif family == "alpine":
            self._audit_alpine()
        else:
            self._record_error(f"Unknown OS family '{os_id}' — package audit skipped.")

    def _detect_os_id(self) -> str:
        r = self._run_command("cat /etc/os-release 2>/dev/null")
        if r.ok:
            for line in r.stdout.splitlines():
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip().strip('"')
        return "unknown"

    def _audit_debian(self) -> None:
        # Collect installed package count (inventory)
        r = self._run_command("dpkg-query -W -f='${Package}\\n' 2>/dev/null | wc -l")
        if r.ok:
            try:
                self.result.system_info.installed_packages_count = int(r.stdout.strip())
            except ValueError:
                pass

        # Check for upgradable packages
        r = self._run_command("apt list --upgradable 2>/dev/null | tail -n +2")
        if r.ok and r.stdout.strip():
            upgradable = []
            for line in r.stdout.splitlines():
                pkg = line.split("/", 1)[0].strip()
                if pkg:
                    upgradable.append(pkg)

            if upgradable:
                self.result.system_info.upgradable_packages = upgradable
                self._add_finding(
                    id="PKG-001",
                    title=f"{len(upgradable)} package update(s) available",
                    description=(
                        f"There are {len(upgradable)} packages with pending updates. Some may include security patches."
                    ),
                    severity=Severity.MEDIUM if len(upgradable) > 10 else Severity.LOW,
                    evidence=f"Upgradable: {', '.join(upgradable[:10])}"
                    + (f" ... and {len(upgradable) - 10} more" if len(upgradable) > 10 else ""),
                    recommendation="apt update && apt upgrade -y",
                )

    def _audit_rhel(self) -> None:
        # Collect installed package count (inventory)
        r = self._run_command("rpm -qa --qf '%{NAME}\\n' 2>/dev/null | wc -l")
        if r.ok:
            try:
                self.result.system_info.installed_packages_count = int(r.stdout.strip())
            except ValueError:
                pass

        # Check for security updates
        r = self._run_command("yum check-update --security 2>/dev/null | grep -E '\\.(x86_64|noarch|i686)' || true")
        if r.ok and r.stdout.strip():
            upgradable = []
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts:
                    upgradable.append(parts[0])

            if upgradable:
                self.result.system_info.upgradable_packages = upgradable
                self._add_finding(
                    id="PKG-002",
                    title=f"{len(upgradable)} security update(s) available",
                    description=(f"There are {len(upgradable)} packages with pending security updates."),
                    severity=Severity.MEDIUM if len(upgradable) > 5 else Severity.LOW,
                    evidence=f"Upgradable: {', '.join(upgradable[:10])}"
                    + (f" ... and {len(upgradable) - 10} more" if len(upgradable) > 10 else ""),
                    recommendation="yum update --security -y",
                )

    def _audit_alpine(self) -> None:
        # Collect installed package count
        r = self._run_command("apk list --installed 2>/dev/null | wc -l")
        if r.ok:
            try:
                self.result.system_info.installed_packages_count = int(r.stdout.strip())
            except ValueError:
                pass

        # Check for upgradable packages
        r = self._run_command("apk version -l '<' 2>/dev/null")
        if r.ok and r.stdout.strip():
            upgradable = []
            for line in r.stdout.splitlines():
                pkg = line.split("<")[0].strip().split("-")[0] if "<" in line else ""
                if pkg:
                    upgradable.append(pkg)

            if upgradable:
                self.result.system_info.upgradable_packages = upgradable
                self._add_finding(
                    id="PKG-003",
                    title=f"{len(upgradable)} package update(s) available",
                    description=f"{len(upgradable)} packages have newer versions available.",
                    severity=Severity.LOW,
                    evidence=f"Upgradable: {', '.join(upgradable[:10])}",
                    recommendation="apk update && apk upgrade",
                )
