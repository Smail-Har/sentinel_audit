"""
sentinel_audit/audit/container_audit.py
────────────────────────────────────────
If Docker is present, collect container inventory and flag privileged mode.
"""

from __future__ import annotations

import logging

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

logger = logging.getLogger(__name__)


class ContainerAuditor(BaseAuditor):
    """Audit Docker containers if present."""

    name = "Container Audit"
    category = "container"

    def run(self) -> None:
        # Check for docker binary
        r = self._run_command("which docker 2>/dev/null")
        if not r.ok or not r.stdout.strip():
            return  # Docker not present — nothing to audit

        # Verify we can talk to the Docker daemon
        r = self._run_command("docker info 2>&1")
        if self._is_permission_denied(r):
            self._add_finding(
                id="CTR-000",
                title="Cannot audit Docker — insufficient privileges",
                description=(
                    "Docker is installed but the audit user cannot access the "
                    "Docker daemon. Container security checks were skipped."
                ),
                severity=Severity.INFO,
                evidence="Permission denied accessing Docker daemon",
                recommendation=("Add the audit user to the 'docker' group or run as root."),
            )
            return

        self._collect_container_inventory()
        self._check_privileged_containers()
        self._check_docker_socket()

    def _collect_container_inventory(self) -> None:
        """Collect running containers into inventory."""
        r = self._run_command("docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}|{{.Status}}' 2>/dev/null")
        if r.ok and r.stdout.strip():
            for line in r.stdout.splitlines():
                parts = line.split("|", 4)
                if len(parts) >= 3:
                    self.result.system_info.containers.append(
                        {
                            "id": parts[0],
                            "image": parts[1],
                            "name": parts[2],
                            "ports": parts[3] if len(parts) > 3 else "",
                            "status": parts[4] if len(parts) > 4 else "",
                        }
                    )

    def _check_privileged_containers(self) -> None:
        """Use docker inspect to detect privileged containers."""
        r = self._run_command("docker ps -q 2>/dev/null")
        if not r.ok or not r.stdout.strip():
            return

        container_ids = r.stdout.strip().splitlines()
        for cid in container_ids[:20]:  # Cap to avoid excessive API calls
            r = self._run_command(
                f"docker inspect --format '{{{{.HostConfig.Privileged}}}}|{{{{.Name}}}}' {cid} 2>/dev/null"
            )
            if r.ok and r.stdout.strip():
                parts = r.stdout.strip().split("|", 1)
                is_privileged = parts[0].strip().lower() == "true"
                name = parts[1].strip("/") if len(parts) > 1 else cid
                if is_privileged:
                    self._add_finding(
                        id="CTR-001",
                        title=f"Privileged container: {name}",
                        description=(
                            f"Container '{name}' is running in privileged mode, "
                            f"giving it near-full host access. This is a critical "
                            f"security risk."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=f"Container {name} ({cid}): Privileged=true",
                        recommendation=(
                            f"Remove --privileged from container '{name}'. "
                            f"Use specific capabilities (--cap-add) instead."
                        ),
                    )

    def _check_docker_socket(self) -> None:
        """Check if Docker socket is world-readable."""
        r = self._run_command("stat -c '%a' /var/run/docker.sock 2>/dev/null")
        if r.ok:
            mode = r.stdout.strip().strip("'")
            if mode and len(mode) >= 3 and mode[-1] not in ("0",):
                self._add_finding(
                    id="CTR-002",
                    title="Docker socket has broad permissions",
                    description=(
                        "The Docker socket /var/run/docker.sock has loose "
                        "permissions. Any user with access can control Docker, "
                        "effectively gaining root."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"/var/run/docker.sock mode: {mode}",
                    recommendation="chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock",
                )
