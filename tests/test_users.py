"""Tests for users audit module."""

from __future__ import annotations

from conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.users_audit import UsersAuditor
from sentinel_audit.core.constants import Severity


def _make_auditor(
    passwd: str = "root:x:0:0:root:/root:/bin/bash",
    shadow_cmd: str = "",
    nopasswd_cmd: str = "",
) -> UsersAuditor:
    result = make_result()
    executor = FakeExecutor(
        command_map={
            "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>&1 || true": cmd(nopasswd_cmd),
            "awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>&1": cmd(shadow_cmd),
        },
        file_map={
            "/etc/passwd": cmd(passwd),
        },
    )
    return UsersAuditor(executor, result)


def test_uid0_non_root_detected() -> None:
    passwd = "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0:toor:/root:/bin/bash"
    auditor = _make_auditor(passwd=passwd)
    auditor.run()

    ids = {f.id for f in auditor.result.findings}
    assert "USR-001" in ids
    assert any(f.severity == Severity.CRITICAL for f in auditor.result.findings if f.id == "USR-001")


def test_uid0_only_root_is_ok() -> None:
    auditor = _make_auditor(passwd="root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin")
    auditor.run()

    assert not any(f.id == "USR-001" for f in auditor.result.findings)


def test_nopasswd_sudo_detected() -> None:
    auditor = _make_auditor(nopasswd_cmd="user ALL=(ALL) NOPASSWD: ALL")
    auditor.run()

    ids = {f.id for f in auditor.result.findings}
    assert "USR-002" in ids


def test_empty_passwords_detected() -> None:
    auditor = _make_auditor(shadow_cmd="testuser\n")
    auditor.run()

    ids = {f.id for f in auditor.result.findings}
    assert "USR-003" in ids
    assert any(f.severity == Severity.CRITICAL for f in auditor.result.findings if f.id == "USR-003")


def test_user_inventory_collected() -> None:
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    auditor = _make_auditor(passwd=passwd)
    auditor.run()

    accounts = auditor.result.system_info.user_accounts
    assert len(accounts) == 2
    assert accounts[0]["username"] == "root"
    assert accounts[0]["interactive"] == "True"
    assert accounts[1]["interactive"] == "False"
