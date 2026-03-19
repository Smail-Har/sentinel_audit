"""
sentinel_audit/core/models.py
─────────────────────────────
Central data-model definitions for SentinelAudit.

All structures are plain dataclasses so they carry no external runtime
dependency and are trivially serialisable to dict / JSON.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from sentinel_audit.core.constants import Severity

# Re-export so existing imports keep working
__all__ = [
    "AuditResult",
    "CommandResult",
    "Finding",
    "InventoryTarget",
    "SecurityScore",
    "Severity",
    "SystemInfo",
]


# ──────────────────────────────────────────────
# Individual finding
# ──────────────────────────────────────────────


@dataclass
class Finding:
    """A single security finding produced by an audit module.

    Findings represent *real security issues* — not inventory items.
    """

    id: str
    """Unique identifier, e.g. ``SSH-001``."""

    title: str
    """Short human-readable title (English)."""

    description: str
    """Full explanation of the issue (English)."""

    severity: Severity
    """Impact level."""

    category: str
    """Audit category, e.g. ``ssh``, ``permissions``, ``users``."""

    evidence: str = ""
    """Raw evidence collected from the system (sanitised — no secrets)."""

    recommendation: str = ""
    """Concrete remediation command or advice (English)."""

    reference: str = ""
    """Optional URL to CIS benchmark / CVE / upstream docs."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "reference": self.reference,
        }


# ──────────────────────────────────────────────
# Command execution result
# ──────────────────────────────────────────────


@dataclass
class CommandResult:
    """Encapsulates the result of running a shell command."""

    command: str
    stdout: str
    stderr: str
    return_code: int
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """Return True when the command exited with code 0."""
        return self.return_code == 0

    @property
    def output(self) -> str:
        """Convenience alias for ``stdout``."""
        return self.stdout


# ──────────────────────────────────────────────
# System inventory (informational, not scored)
# ──────────────────────────────────────────────


@dataclass
class SystemInfo:
    """Hardware and OS inventory collected during the System Info audit."""

    hostname: str = "unknown"
    os_name: str = "unknown"
    os_version: str = "unknown"
    os_id: str = "unknown"
    kernel_version: str = "unknown"
    architecture: str = "unknown"
    uptime: str = "unknown"
    cpu_model: str = "unknown"
    cpu_count: int = 0
    total_memory_mb: int = 0
    disk_usage: list[dict[str, str]] = field(default_factory=list)
    network_interfaces: list[dict[str, str]] = field(default_factory=list)
    installed_packages_count: int = 0
    upgradable_packages: list[str] = field(default_factory=list)
    running_services: list[str] = field(default_factory=list)
    enabled_services: list[str] = field(default_factory=list)
    listening_ports: list[dict[str, str]] = field(default_factory=list)
    user_accounts: list[dict[str, str]] = field(default_factory=list)
    cron_jobs: list[str] = field(default_factory=list)
    containers: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_id": self.os_id,
            "kernel_version": self.kernel_version,
            "architecture": self.architecture,
            "uptime": self.uptime,
            "cpu_model": self.cpu_model,
            "cpu_count": self.cpu_count,
            "total_memory_mb": self.total_memory_mb,
            "disk_usage": self.disk_usage,
            "network_interfaces": self.network_interfaces,
            "installed_packages_count": self.installed_packages_count,
            "upgradable_packages": self.upgradable_packages,
            "running_services": self.running_services,
            "enabled_services": self.enabled_services,
            "listening_ports": self.listening_ports,
            "user_accounts": self.user_accounts,
            "cron_jobs": self.cron_jobs,
            "containers": self.containers,
        }


# ──────────────────────────────────────────────
# Security score
# ──────────────────────────────────────────────


@dataclass
class SecurityScore:
    """Aggregated security score for the target system."""

    raw_score: float = 100.0
    score: int = 100
    grade: str = "A"
    risk_summary: str = "Very low risk posture"
    total_findings: int = 0
    breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "risk_summary": self.risk_summary,
            "total_findings": self.total_findings,
            "breakdown": self.breakdown,
        }


# ──────────────────────────────────────────────
# Top-level audit result
# ──────────────────────────────────────────────


@dataclass
class AuditResult:
    """Container for the complete result of one audit run."""

    target: str
    label: str = ""
    started_at: datetime.datetime = field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
    )
    finished_at: datetime.datetime | None = None

    system_info: SystemInfo = field(default_factory=SystemInfo)
    findings: list[Finding] = field(default_factory=list)
    score: SecurityScore = field(default_factory=SecurityScore)
    audit_errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        """Append a finding."""
        self.findings.append(finding)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "label": self.label,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "system_info": self.system_info.to_dict(),
            "score": self.score.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "audit_errors": self.audit_errors,
        }


# ──────────────────────────────────────────────
# Inventory target (from YAML inventory file)
# ──────────────────────────────────────────────


@dataclass
class InventoryTarget:
    """A single target parsed from the inventory YAML file."""

    host: str
    label: str = ""
    ssh_user: str = "root"
    ssh_key: str | None = None
    ssh_password: str | None = None
    ssh_port: int = 22
    modules: list[str] = field(default_factory=list)
    exclude_modules: list[str] = field(default_factory=list)
