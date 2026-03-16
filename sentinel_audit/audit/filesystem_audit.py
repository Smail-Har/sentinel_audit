"""
sentinel_audit/audit/filesystem_audit.py
─────────────────────────────────────────
Placeholder for future filesystem checks (e.g. world-writable dirs).
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor


class FilesystemAuditor(BaseAuditor):
    """Filesystem checks (not yet implemented)."""

    name = "Filesystem Audit"
    category = "filesystem"

    def run(self) -> None:
        # Placeholder: implement world-writable dir checks, SUID/SGID, etc.
        pass
