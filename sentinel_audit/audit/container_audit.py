"""
sentinel_audit/audit/container_audit.py
────────────────────────────────────────
If Docker is present, list containers, exposed ports, privileged mode.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.models import Severity


class ContainerAuditor(BaseAuditor):
    """Audit Docker containers if present."""

    name = "Container Audit"
    category = "container"

    def run(self) -> None:
        # ── check for docker ─────────────────
        r = self._run_command("which docker")
        if not r.ok or not r.stdout:
            return  # Docker not present

        # ── list running containers ───────────
        r = self._run_command("docker ps --format '{{.ID}} {{.Image}} {{.Ports}} {{.Names}} {{.Status}}'")
        if r.ok and r.stdout.strip():
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    cid, image, ports, name = parts[:4]
                    self._add_finding(
                        id="CTR-001",
                        title=f"Running container: {name}",
                        description=f"Container {name} ({image}) is running.",
                        severity=Severity.INFO,
                        evidence=line,
                    )
                    if ":" in ports:
                        self._add_finding(
                            id="CTR-002",
                            title=f"Container exposes port: {ports}",
                            description=f"Container {name} exposes a network port.",
                            severity=Severity.HIGH,
                            evidence=ports,
                        )
        # ── privileged containers ─────────────
        r = self._run_command("docker ps --filter 'privileged=true' --format '{{.Names}}'")
        if r.ok and r.stdout.strip():
            for name in r.stdout.splitlines():
                self._add_finding(
                    id="CTR-003",
                    title=f"Privileged container: {name}",
                    description=f"Container {name} is running in privileged mode.",
                    severity=Severity.CRITICAL,
                    evidence=name,
                )
