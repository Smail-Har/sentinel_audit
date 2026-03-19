"""
sentinel_audit/audit/network_audit.py
──────────────────────────────────────
Audit open network ports with contextual severity.
Listening ports go to inventory.  Only externally-exposed services on
non-standard ports produce findings.

WireGuard ports (default 51820) are downgraded to INFO when a WireGuard
interface is detected.  IPv4/IPv6 duplicates for the same port are merged
into a single finding.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity
from sentinel_audit.core.utils import is_address_exposed, parse_ss_output

# Ports that are expected on most servers (not flagged as HIGH)
_COMMON_PORTS: frozenset[str] = frozenset(
    {
        "22",
        "80",
        "443",
        "53",
    }
)

# Ports that are concerning if externally exposed
_SENSITIVE_PORTS: dict[str, str] = {
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "6379": "Redis",
    "27017": "MongoDB",
    "11211": "Memcached",
    "9200": "Elasticsearch",
    "2375": "Docker API (unencrypted)",
    "2376": "Docker API",
    "5900": "VNC",
    "23": "Telnet",
    "21": "FTP",
    "1433": "MSSQL",
    "8080": "HTTP-alt",
    "8443": "HTTPS-alt",
}

# Default WireGuard listen port
_WIREGUARD_PORT: str = "51820"


class NetworkAuditor(BaseAuditor):
    """Audit open network ports with contextual severity."""

    name = "Network Audit"
    category = "network"

    def run(self) -> None:
        r = self._run_command("ss -tlnup 2>/dev/null")
        if not r.ok:
            self._record_error("Cannot run ss — network audit skipped.")
            return

        entries = parse_ss_output(r.stdout)

        # Collect all listening ports as inventory
        for entry in entries:
            self.result.system_info.listening_ports.append(entry)

        # Detect WireGuard for contextual downgrade
        wg_active = self._detect_wireguard()
        wg_ports = self._detect_wireguard_ports() if wg_active else set()

        # Deduplicate: track which ports we already reported
        reported_ports: set[str] = set()

        for entry in entries:
            addr = entry["local_address"]
            port = entry["local_port"]

            if not is_address_exposed(addr):
                continue

            if port in _SENSITIVE_PORTS:
                if port in reported_ports:
                    continue
                reported_ports.add(port)
                service_name = _SENSITIVE_PORTS[port]
                self._add_finding(
                    id="NET-001",
                    title=f"Sensitive service exposed: {service_name} on port {port}",
                    description=(
                        f"{service_name} (port {port}) is listening on {addr}, "
                        f"making it reachable from the network. Database and "
                        f"cache services should not be exposed externally."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"{addr}:{port} ({entry.get('process', 'unknown')})",
                    recommendation=(
                        f"Bind {service_name} to 127.0.0.1 or use a firewall to restrict access to port {port}."
                    ),
                )
            elif port not in _COMMON_PORTS:
                if port in reported_ports:
                    continue
                reported_ports.add(port)

                # Downgrade WireGuard ports to INFO
                if wg_active and port in wg_ports:
                    self._add_finding(
                        id="NET-002",
                        title=f"WireGuard VPN port: {port}",
                        description=(f"Port {port} is used by WireGuard VPN — expected."),
                        severity=Severity.INFO,
                        evidence=f"{addr}:{port} ({entry.get('process', 'unknown')})",
                        recommendation="No action needed — WireGuard VPN port.",
                    )
                else:
                    self._add_finding(
                        id="NET-002",
                        title=f"Non-standard port exposed: {port}",
                        description=(
                            f"Port {port} is listening on {addr}. Verify this "
                            f"service is intentional and properly secured."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=f"{addr}:{port} ({entry.get('process', 'unknown')})",
                        recommendation=f"Review whether port {port} needs to be externally accessible.",
                    )

    # ── WireGuard detection ──────────────────────────────────────────

    def _detect_wireguard(self) -> bool:
        """Return True if WireGuard interfaces or processes are detected."""
        r = self._run_command("ip link show type wireguard 2>/dev/null")
        if r.ok and r.stdout.strip():
            return True
        r = self._run_command("wg show interfaces 2>/dev/null")
        if r.ok and r.stdout.strip():
            return True
        r = self._run_command("lsmod 2>/dev/null | grep -q wireguard && echo yes")
        if r.ok and "yes" in r.stdout:
            return True
        return False

    def _detect_wireguard_ports(self) -> set[str]:
        """Return the set of WireGuard listen ports."""
        ports: set[str] = set()
        r = self._run_command("wg show all listen-port 2>/dev/null")
        if r.ok and r.stdout.strip():
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ports.add(parts[-1].strip())
        # Always include default port
        if not ports:
            ports.add(_WIREGUARD_PORT)
        return ports
