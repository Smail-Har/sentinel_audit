"""Tests for filesystem audit module."""

from __future__ import annotations

from conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.filesystem_audit import FilesystemAuditor
from sentinel_audit.core.constants import Severity

_FIND_SUID = (
    "find / -type f \\( -perm -4000 -o -perm -2000 \\) "
    "-not -path '/proc/*' -not -path '/sys/*' "
    "-not -path '/snap/*' 2>/dev/null | head -50"
)
_FIND_WRITABLE = (
    "find / -type d -perm -0002 "
    "-not -path '/tmp*' -not -path '/var/tmp*' "
    "-not -path '/proc/*' -not -path '/sys/*' "
    "-not -path '/dev/*' -not -path '/run/*' "
    "-not -path '/snap/*' 2>/dev/null | head -20"
)
_MOUNT_TMP = "mount | grep -E '/tmp|/var/tmp'"


def test_unexpected_suid_detected() -> None:
    executor = FakeExecutor(
        command_map={
            _FIND_SUID: cmd("/usr/bin/passwd\n/usr/bin/sudo\n/opt/suspicious_binary"),
            _FIND_WRITABLE: cmd(""),
            _MOUNT_TMP: cmd(rc=1),
        }
    )
    result = make_result()
    FilesystemAuditor(executor, result).run()

    suid_finding = [f for f in result.findings if f.id == "FS-001"]
    assert len(suid_finding) == 1
    assert "suspicious_binary" in suid_finding[0].evidence


def test_world_writable_dirs_detected() -> None:
    executor = FakeExecutor(
        command_map={
            _FIND_SUID: cmd(""),
            _FIND_WRITABLE: cmd("/opt/shared\n/home/public"),
            _MOUNT_TMP: cmd(rc=1),
        }
    )
    result = make_result()
    FilesystemAuditor(executor, result).run()

    assert any(f.id == "FS-002" for f in result.findings)


def test_tmp_not_separate_mount() -> None:
    executor = FakeExecutor(
        command_map={
            _FIND_SUID: cmd(""),
            _FIND_WRITABLE: cmd(""),
            _MOUNT_TMP: cmd(rc=1),
        }
    )
    result = make_result()
    FilesystemAuditor(executor, result).run()

    assert any(f.id == "FS-003" for f in result.findings)
    assert any(f.severity == Severity.LOW for f in result.findings if f.id == "FS-003")


def test_tmp_missing_noexec() -> None:
    executor = FakeExecutor(
        command_map={
            _FIND_SUID: cmd(""),
            _FIND_WRITABLE: cmd(""),
            _MOUNT_TMP: cmd("tmpfs on /tmp type tmpfs (rw,nosuid,nodev)"),
        }
    )
    result = make_result()
    FilesystemAuditor(executor, result).run()

    assert any(f.id == "FS-004" for f in result.findings)
