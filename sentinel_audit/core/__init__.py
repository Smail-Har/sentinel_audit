# sentinel_audit/core/__init__.py
from sentinel_audit.core.executor import LocalExecutor, RemoteExecutor
from sentinel_audit.core.models import AuditResult, Finding, SecurityScore, Severity, SystemInfo
from sentinel_audit.core.scoring import compute_score
from sentinel_audit.core.ssh_client import SSHClient

__all__ = [
    "AuditResult",
    "Finding",
    "LocalExecutor",
    "RemoteExecutor",
    "SecurityScore",
    "Severity",
    "SSHClient",
    "SystemInfo",
    "compute_score",
]
