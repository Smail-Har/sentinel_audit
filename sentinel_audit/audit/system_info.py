"""
sentinel_audit/audit/system_info.py
─────────────────────────────────────
Collect system inventory: hostname, OS, kernel, CPU, RAM, disk, network.
This module populates SystemInfo (inventory) — it does NOT produce findings.
"""

from __future__ import annotations

import logging

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import SystemInfo

logger = logging.getLogger(__name__)


class SystemInfoAuditor(BaseAuditor):
    """Collect system inventory information."""

    name = "System Info"
    category = "system_info"

    def run(self) -> None:
        info = SystemInfo()

        # Hostname
        r = self._run_command("hostname -f 2>/dev/null || hostname")
        if r.ok:
            info.hostname = r.stdout.strip()

        # OS release
        r = self._read_file("/etc/os-release")
        if r.ok:
            for line in r.stdout.splitlines():
                if line.startswith("PRETTY_NAME="):
                    info.os_name = line.split("=", 1)[1].strip('"')
                elif line.startswith("ID="):
                    info.os_id = line.split("=", 1)[1].strip('"')
                elif line.startswith("VERSION_ID="):
                    info.os_version = line.split("=", 1)[1].strip('"')

        # Kernel
        r = self._run_command("uname -r")
        if r.ok:
            info.kernel_version = r.stdout.strip()

        # Architecture
        r = self._run_command("uname -m")
        if r.ok:
            info.architecture = r.stdout.strip()

        # Uptime
        r = self._run_command("uptime -p 2>/dev/null || uptime")
        if r.ok:
            info.uptime = r.stdout.strip()

        # CPU
        r = self._run_command("grep -c ^processor /proc/cpuinfo 2>/dev/null || nproc")
        if r.ok:
            try:
                info.cpu_count = int(r.stdout.strip())
            except ValueError:
                pass

        r = self._run_command("grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2")
        if r.ok and r.stdout.strip():
            info.cpu_model = r.stdout.strip()

        # Memory
        r = self._run_command("grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}'")
        if r.ok and r.stdout.strip():
            try:
                info.total_memory_mb = int(r.stdout.strip()) // 1024
            except ValueError:
                pass

        # Disk usage
        r = self._run_command("df -h --output=target,size,used,avail,pcent 2>/dev/null | tail -n +2")
        if r.ok and r.stdout.strip():
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    info.disk_usage.append(
                        {
                            "mount": parts[0],
                            "size": parts[1],
                            "used": parts[2],
                            "avail": parts[3],
                            "use_percent": parts[4],
                        }
                    )

        # Network interfaces
        r = self._run_command("hostname -I 2>/dev/null")
        if r.ok and r.stdout.strip():
            info.network_interfaces = [{"address": ip} for ip in r.stdout.strip().split()]

        self.result.system_info = info
        logger.info("System info collected for %s", info.hostname)
