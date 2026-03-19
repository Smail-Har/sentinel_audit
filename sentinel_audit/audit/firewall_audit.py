"""
sentinel_audit/audit/firewall_audit.py
────────────────────────────────────────
Detect which firewall is active (ufw, firewalld, iptables, nftables).

Handles non-root execution gracefully: when a command fails due to
missing privileges, the module falls back to non-root alternatives
(``systemctl is-active``, ``sudo -n``) before concluding no firewall
is present.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity


class FirewallAuditor(BaseAuditor):
    """Check firewall presence and status."""

    name = "Firewall Audit"
    category = "firewall"

    def run(self) -> None:
        active: list[str] = []
        privilege_issues: list[str] = []

        # ── ufw ──────────────────────────────────────────────────────
        detected, denied = self._check_ufw()
        if detected:
            active.append("ufw")
        if denied:
            privilege_issues.append("ufw")

        # ── firewalld ────────────────────────────────────────────────
        r = self._run_command("systemctl is-active firewalld 2>/dev/null")
        if r.ok and r.stdout.strip() == "active":
            active.append("firewalld")

        # ── iptables ─────────────────────────────────────────────────
        detected, denied = self._check_iptables()
        if detected:
            active.append("iptables")
        if denied:
            privilege_issues.append("iptables")

        # ── nftables ─────────────────────────────────────────────────
        detected, denied = self._check_nftables()
        if detected:
            active.append("nftables")
        if denied:
            privilege_issues.append("nftables")

        # ── Verdict ──────────────────────────────────────────────────
        if active:
            self.result.system_info.running_services.extend([f"firewall:{fw}" for fw in active])
        elif privilege_issues:
            # Could not verify because of missing privileges — NOT a CRITICAL
            self._add_finding(
                id="FW-001",
                title="Cannot verify firewall status — insufficient privileges",
                description=(
                    "Firewall check commands failed due to insufficient privileges. "
                    "The firewall may well be active, but the audit user cannot verify it. "
                    f"Affected: {', '.join(privilege_issues)}."
                ),
                severity=Severity.INFO,
                evidence=f"Permission denied for: {', '.join(privilege_issues)}",
                recommendation=(
                    "Re-run the audit as root, or grant the audit user passwordless sudo for firewall status commands."
                ),
            )
        else:
            self._add_finding(
                id="FW-001",
                title="No active firewall detected",
                description=(
                    "No active firewall (ufw, firewalld, iptables, nftables) "
                    "was detected. The system may be entirely exposed to "
                    "inbound traffic."
                ),
                severity=Severity.CRITICAL,
                evidence="ufw/firewalld/iptables/nftables — none active",
                recommendation=(
                    "Install and enable a firewall. "
                    "Debian/Ubuntu: apt install ufw && ufw enable && ufw default deny incoming. "
                    "RHEL/CentOS: systemctl enable --now firewalld"
                ),
            )

        # ── Check default INPUT policy (best-effort) ────────────────
        r = self._run_command("iptables -L INPUT -n 2>/dev/null | head -1")
        if r.ok and "policy ACCEPT" in r.stdout:
            self._add_finding(
                id="FW-002",
                title="iptables INPUT default policy is ACCEPT",
                description=(
                    "The default policy for the INPUT chain is ACCEPT. "
                    "All traffic is allowed unless explicitly blocked."
                ),
                severity=Severity.HIGH,
                evidence=r.stdout.strip(),
                recommendation=(
                    "Set the default policy to DROP: iptables -P INPUT DROP, then whitelist required inbound traffic."
                ),
            )

    # ── Private helpers ──────────────────────────────────────────────

    def _check_ufw(self) -> tuple[bool, bool]:
        """Return (is_active, permission_denied)."""
        r = self._run_command("ufw status 2>&1")
        if r.ok and "active" in r.stdout.lower():
            return True, False
        if self._is_permission_denied(r):
            # Fallback 1: sudo -n (non-interactive)
            r2 = self._run_command("sudo -n ufw status 2>&1")
            if r2.ok and "active" in r2.stdout.lower():
                return True, False
            # Fallback 2: systemctl (does not require root)
            r3 = self._run_command("systemctl is-active ufw 2>/dev/null")
            if r3.ok and r3.stdout.strip() == "active":
                return True, False
            return False, True
        return False, False

    def _check_iptables(self) -> tuple[bool, bool]:
        """Return (has_rules, permission_denied)."""
        r = self._run_command("iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l")
        if r.ok:
            try:
                if int(r.stdout.strip()) > 0:
                    return True, False
            except ValueError:
                pass
            return False, False
        if self._is_permission_denied(r):
            r2 = self._run_command("sudo -n iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l")
            if r2.ok:
                try:
                    if int(r2.stdout.strip()) > 0:
                        return True, False
                except ValueError:
                    pass
            return False, True
        return False, False

    def _check_nftables(self) -> tuple[bool, bool]:
        """Return (has_rules, permission_denied)."""
        r = self._run_command("nft list ruleset 2>&1 | wc -l")
        if r.ok:
            try:
                if int(r.stdout.strip()) > 2:
                    return True, False
            except ValueError:
                pass
            return False, False
        if self._is_permission_denied(r):
            r2 = self._run_command("sudo -n nft list ruleset 2>&1 | wc -l")
            if r2.ok:
                try:
                    if int(r2.stdout.strip()) > 2:
                        return True, False
                except ValueError:
                    pass
            # Check systemctl as last resort
            r3 = self._run_command("systemctl is-active nftables 2>/dev/null")
            if r3.ok and r3.stdout.strip() == "active":
                return True, False
            return False, True
        return False, False
