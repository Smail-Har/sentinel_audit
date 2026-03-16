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
from enum import Enum
from typing import Any


_SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ──────────────────────────────────────────────
# Severity levels
# ──────────────────────────────────────────────

class Severity(str, Enum):
    """Finding severity levels, ordered from lowest to highest impact."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] < _SEVERITY_RANK[other.value]

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] <= _SEVERITY_RANK[other.value]

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] > _SEVERITY_RANK[other.value]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] >= _SEVERITY_RANK[other.value]


# ──────────────────────────────────────────────
# Individual finding
# ──────────────────────────────────────────────

@dataclass
class Finding:
    """A single security / configuration finding produced by an audit module."""

    id: str
    """Unique identifier, e.g. ``SSH-001``."""

    title: str
    """Short human-readable title."""

    description: str
    """Full explanation of the issue."""

    severity: Severity
    """Impact level."""

    category: str
    """Audit category, e.g. ``ssh``, ``permissions``, ``users``."""

    evidence: str = ""
    """Raw evidence collected from the system (command output, file snippet…)."""

    recommendation: str = ""
    """Concrete remediation advice."""

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
# System inventory
# ──────────────────────────────────────────────

@dataclass
class SystemInfo:
    """Hardware and OS inventory collected during the System Info audit."""

    hostname: str = "unknown"
    os_name: str = "unknown"
    os_version: str = "unknown"
    os_id: str = "unknown"          # e.g. ubuntu, debian, rhel
    kernel_version: str = "unknown"
    architecture: str = "unknown"
    uptime: str = "unknown"
    cpu_model: str = "unknown"
    cpu_count: int = 0
    total_memory_mb: int = 0
    disk_usage: list[dict[str, str]] = field(default_factory=list)
    network_interfaces: list[dict[str, str]] = field(default_factory=list)

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
        }


# ──────────────────────────────────────────────
# Security score
# ──────────────────────────────────────────────

@dataclass
class SecurityScore:
    """Aggregated security score for the target system."""

    raw_score: float = 100.0
    """Score before capping, may go below 0 in heavily-penalised systems."""

    score: int = 100
    """Final score clamped to [0, 100]."""

    grade: str = "A"
    """Letter grade derived from the final score."""

    risk_summary: str = "Very low risk posture"
    """Human-readable risk summary derived from score and findings."""

    total_findings: int = 0
    breakdown: dict[str, int] = field(default_factory=dict)
    """Count of findings per severity level."""

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
    """Host that was audited (hostname, IP, or ``localhost``)."""

    started_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)
    finished_at: datetime.datetime | None = None

    system_info: SystemInfo = field(default_factory=SystemInfo)
    findings: list[Finding] = field(default_factory=list)
    score: SecurityScore = field(default_factory=SecurityScore)

    # Warnings or non-fatal errors produced during the audit
    audit_errors: list[str] = field(default_factory=list)

    # ── helpers ──────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        """Append a finding and keep the list sorted by descending severity."""
        self.findings.append(finding)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings matching *severity*."""
        return [f for f in self.findings if f.severity == severity]

    def findings_by_category(self, category: str) -> list[Finding]:
        """Return all findings matching *category*."""
        return [f for f in self.findings if f.category == category]

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "system_info": self.system_info.to_dict(),
            "score": self.score.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "audit_errors": self.audit_errors,
        }
