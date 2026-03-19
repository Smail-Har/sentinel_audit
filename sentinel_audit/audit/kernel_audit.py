"""
sentinel_audit/audit/kernel_audit.py
─────────────────────────────────────
Check kernel sysctl parameters against YAML rules.
Detects VPN software (WireGuard) to downgrade ip_forward findings.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

_RULES_PATH = Path(__file__).parent.parent / "config" / "default_rules.yaml"

# Sysctl keys where IP forwarding is justified by a VPN
_VPN_FORWARDING_KEYS: frozenset[str] = frozenset(
    {
        "net.ipv4.ip_forward",
        "net.ipv6.conf.all.forwarding",
    }
)


class KernelAuditor(BaseAuditor):
    """Audit kernel and sysctl parameters against hardening rules."""

    name = "Kernel Audit"
    category = "kernel"

    def run(self) -> None:
        vpn_active = self._detect_wireguard()
        rules = self._load_sysctl_rules()

        for rule in rules:
            key = rule["key"]
            expected = str(rule["expected_value"])
            r = self._run_command(f"sysctl -n {key} 2>/dev/null")
            if r.ok:
                actual = r.stdout.strip()
                if actual != expected:
                    severity = Severity(rule["severity"])
                    description = rule["description"]

                    # Downgrade ip_forward to INFO when WireGuard is present
                    recommendation = rule["recommendation"]
                    if vpn_active and key in _VPN_FORWARDING_KEYS:
                        severity = Severity.INFO
                        description = "IP forwarding enabled — consistent with WireGuard VPN configuration"
                        recommendation = (
                            "No action required — IP forwarding is expected for WireGuard VPN. Verify if intentional."
                        )

                    self._add_finding(
                        id=rule["id"],
                        title=f"Sysctl {key} = {actual} (expected {expected})",
                        description=description,
                        severity=severity,
                        evidence=f"{key} = {actual}",
                        recommendation=recommendation,
                    )
            else:
                self._record_error(f"Cannot read sysctl {key}: {r.stderr}")

    def _detect_wireguard(self) -> bool:
        """Return True if WireGuard interfaces or processes are detected."""
        # Method 1: ip link show type wireguard
        r = self._run_command("ip link show type wireguard 2>/dev/null")
        if r.ok and r.stdout.strip():
            return True
        # Method 2: wg show (may need root, but worth trying)
        r = self._run_command("wg show interfaces 2>/dev/null")
        if r.ok and r.stdout.strip():
            return True
        # Method 3: check for wireguard kernel module
        r = self._run_command("lsmod 2>/dev/null | grep -q wireguard && echo yes")
        if r.ok and "yes" in r.stdout:
            return True
        return False

    def _load_sysctl_rules(self) -> list[dict[str, str]]:
        try:
            with open(_RULES_PATH, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            return data.get("sysctl_rules", [])  # type: ignore[no-any-return]
        except Exception as exc:
            self._record_error(f"Cannot load sysctl rules: {exc}")
            return []
