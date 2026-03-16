"""
sentinel_audit/audit/firewall_audit.py
────────────────────────────────────────
Detect which firewall is active (ufw, firewalld, iptables, nftables).
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity


class FirewallAuditor(BaseAuditor):
    """Check firewall presence and status."""

    name = "Firewall Audit"
    category = "firewall"

    def run(self) -> None:
        active: list[str] = []

        # ── ufw ──────────────────────────────
        r = self._run_command("ufw status 2>/dev/null")
        if r.ok and "active" in r.stdout.lower():
            active.append("ufw")

        # ── firewalld ─────────────────────────
        r = self._run_command("systemctl is-active firewalld 2>/dev/null")
        if r.ok and r.stdout.strip() == "active":
            active.append("firewalld")

        # ── iptables (has at least one non-default rule) ──────────────────────
        r = self._run_command("iptables -L -n 2>/dev/null | grep -v '^Chain\\|^target\\|^$' | wc -l")
        if r.ok:
            try:
                count = int(r.stdout.strip())
                if count > 0:
                    active.append("iptables")
            except ValueError:
                pass

        # ── nftables ──────────────────────────
        r = self._run_command("nft list ruleset 2>/dev/null | wc -l")
        if r.ok:
            try:
                if int(r.stdout.strip()) > 2:
                    active.append("nftables")
            except ValueError:
                pass

        if not active:
            self._add_finding(
                id="FW-001",
                title="No active firewall detected",
                description=(
                    "No active firewall (ufw, firewalld, iptables, nftables) "
                    "was detected. The system may be entirely exposed."
                ),
                severity=Severity.CRITICAL,
                evidence="ufw/firewalld/iptables/nftables — none active",
                recommendation=(
                    "Install and enable a firewall. "
                    "Example for Ubuntu/Debian: ufw enable && ufw default deny incoming"
                ),
            )
        else:
            # Informational — record which firewall is active
            self._add_finding(
                id="FW-000",
                title=f"Active firewall detected: {', '.join(active)}",
                description="At least one firewall solution is active on this host.",
                severity=Severity.INFO,
                evidence=", ".join(active),
            )

        # ── check default INPUT policy ────────────────────────────────────────
        r = self._run_command("iptables -L INPUT -n 2>/dev/null | head -1")
        if r.ok and "policy ACCEPT" in r.stdout:
            self._add_finding(
                id="FW-002",
                title="iptables INPUT chain default policy is ACCEPT",
                description=(
                    "The default policy for the INPUT chain is ACCEPT. "
                    "Traffic is allowed unless explicitly blocked."
                ),
                severity=Severity.HIGH,
                evidence=r.stdout,
                recommendation=(
                    "Set the default policy to DROP: iptables -P INPUT DROP "
                    "then whitelist only required inbound traffic."
                ),
            )
