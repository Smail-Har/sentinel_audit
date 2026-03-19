"""
sentinel_audit/audit/filesystem_audit.py
─────────────────────────────────────────
Check SUID/SGID binaries, world-writable directories, and mount options.
"""

from __future__ import annotations

from sentinel_audit.audit.base import BaseAuditor
from sentinel_audit.core.constants import Severity

# SUID binaries that are expected and safe on most systems
_EXPECTED_SUID: frozenset[str] = frozenset({
    "/usr/bin/passwd", "/usr/bin/chage", "/usr/bin/gpasswd",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp",
    "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/mount",
    "/usr/bin/umount", "/usr/bin/pkexec", "/usr/bin/crontab",
    "/usr/bin/at", "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/sbin/pam_timestamp_check",
    "/usr/sbin/unix_chkpwd",
    "/usr/bin/expiry",
    "/usr/bin/wall",
    "/usr/bin/ssh-agent",
    "/usr/bin/write",
    "/bin/su", "/bin/mount", "/bin/umount", "/bin/ping",
    "/usr/bin/ping", "/usr/bin/traceroute",
    "/sbin/mount.nfs",
})


class FilesystemAuditor(BaseAuditor):
    """Audit filesystem security: SUID/SGID, world-writable dirs, mount options."""

    name = "Filesystem Audit"
    category = "filesystem"

    def run(self) -> None:
        self._check_suid_binaries()
        self._check_world_writable_dirs()
        self._check_mount_options()

    def _check_suid_binaries(self) -> None:
        """Find unexpected SUID/SGID binaries."""
        r = self._run_command(
            "find / -type f \\( -perm -4000 -o -perm -2000 \\) "
            "-not -path '/proc/*' -not -path '/sys/*' "
            "-not -path '/snap/*' 2>/dev/null | head -50"
        )
        if not r.ok:
            return

        unexpected: list[str] = []
        for line in r.stdout.splitlines():
            binary = line.strip()
            if binary and binary not in _EXPECTED_SUID:
                unexpected.append(binary)

        if unexpected:
            self._add_finding(
                id="FS-001",
                title=f"{len(unexpected)} unexpected SUID/SGID binary(ies)",
                description=(
                    "SUID/SGID binaries run with elevated privileges. "
                    "Unexpected entries may be exploited for privilege escalation."
                ),
                severity=Severity.HIGH if len(unexpected) > 3 else Severity.MEDIUM,
                evidence="\n".join(unexpected[:10]),
                recommendation=(
                    "Review each binary. Remove SUID/SGID bit if not needed: "
                    "chmod u-s,g-s <file>"
                ),
            )

    def _check_world_writable_dirs(self) -> None:
        """Find world-writable directories outside /tmp and /var/tmp."""
        r = self._run_command(
            "find / -type d -perm -0002 "
            "-not -path '/tmp*' -not -path '/var/tmp*' "
            "-not -path '/proc/*' -not -path '/sys/*' "
            "-not -path '/dev/*' -not -path '/run/*' "
            "-not -path '/snap/*' 2>/dev/null | head -20"
        )
        if not r.ok:
            return

        dirs = [d.strip() for d in r.stdout.splitlines() if d.strip()]
        if dirs:
            self._add_finding(
                id="FS-002",
                title=f"{len(dirs)} world-writable directory(ies) found",
                description=(
                    "World-writable directories outside of /tmp allow any user "
                    "to create or modify files, which can lead to privilege "
                    "escalation or data tampering."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(dirs[:10]),
                recommendation=(
                    "Remove world-writable permission: chmod o-w <directory>, "
                    "or set the sticky bit: chmod +t <directory>"
                ),
            )

    def _check_mount_options(self) -> None:
        """Check that /tmp and /var/tmp have restrictive mount options."""
        r = self._run_command("mount | grep -E '/tmp|/var/tmp'")
        if not r.ok or not r.stdout.strip():
            self._add_finding(
                id="FS-003",
                title="/tmp is not a separate mount point",
                description=(
                    "/tmp is not mounted as a separate filesystem. "
                    "This prevents applying noexec,nosuid,nodev options."
                ),
                severity=Severity.LOW,
                evidence="No separate mount for /tmp found",
                recommendation=(
                    "Mount /tmp as a separate partition with options: "
                    "noexec,nosuid,nodev"
                ),
            )
            return

        for line in r.stdout.splitlines():
            mount_point = line.split()[2] if len(line.split()) > 2 else ""
            if "noexec" not in line and mount_point in ("/tmp", "/var/tmp"):
                self._add_finding(
                    id="FS-004",
                    title=f"{mount_point} missing noexec mount option",
                    description=(
                        f"{mount_point} is mounted without 'noexec', allowing "
                        f"execution of binaries from this directory."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=line.strip(),
                    recommendation=f"Remount with noexec: mount -o remount,noexec {mount_point}",
                )
