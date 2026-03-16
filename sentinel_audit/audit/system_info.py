"""
sentinel_audit/audit/system_info.py
─────────────────────────────────────
Collect system inventory: hostname, OS, kernel, CPU, RAM, disk, network.
"""

from __future__ import annotations
import logging
from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import SystemInfo

logger = logging.getLogger(__name__)

class SystemInfoAuditor(BaseAuditor):
    """Collecte les informations système principales."""
    name = "System Info"
    category = "system_info"

    def run(self) -> None:
        """Collect inventory fields used by scoring/reporting layers."""
        info = SystemInfo()
        # Hostname
        r = self._run_command("hostname -f 2>/dev/null || hostname")
        if r.ok:
            info.hostname = r.stdout.strip()
        # OS
        r = self._read_file("/etc/os-release")
        if r.ok:
            for line in r.stdout.splitlines():
                if line.startswith("PRETTY_NAME="):
                    info.os_name = line.split("=",1)[1].strip('"')
                if line.startswith("ID="):
                    info.os_id = line.split("=",1)[1].strip('"')
                if line.startswith("VERSION_ID="):
                    info.os_version = line.split("=",1)[1].strip('"')
        # Kernel
        r = self._run_command("uname -r")
        if r.ok:
            info.kernel_version = r.stdout.strip()
        # Uptime
        r = self._run_command("uptime -p 2>/dev/null || uptime")
        if r.ok:
            info.uptime = r.stdout.strip()
        # IP addresses
        r = self._run_command("hostname -I 2>/dev/null || ip addr")
        if r.ok:
            info.network_interfaces = [{"address": ip} for ip in r.stdout.strip().split()]
        self.result.system_info = info
        logger.info("System info collected: %s", info.to_dict())
