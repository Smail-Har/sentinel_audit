from __future__ import annotations

from sentinel_audit.audit.permissions_audit import PermissionsAuditor
from sentinel_audit.core.models import AuditResult, CommandResult, Severity


class FakeExecutor:
    def __init__(self, command_map: dict[str, CommandResult]) -> None:
        self.command_map = command_map

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        return self.command_map.get(
            command,
            CommandResult(command=command, stdout="", stderr="unexpected command", return_code=1),
        )

    def read_file(self, path: str) -> CommandResult:
        return CommandResult(command=f"read_file:{path}", stdout="", stderr="", return_code=0)


def test_permissions_audit_detects_mismatched_modes() -> None:
    result = AuditResult(target="localhost")
    command_map = {
        "stat -c '%a' /etc/passwd": CommandResult("", "644", "", 0),
        "stat -c '%a' /etc/shadow": CommandResult("", "644", "", 0),
        "stat -c '%a' /etc/sudoers": CommandResult("", "444", "", 0),
        "stat -c '%a' /etc/ssh/sshd_config": CommandResult("", "600", "", 0),
    }
    auditor = PermissionsAuditor(FakeExecutor(command_map), result)

    auditor.run()

    finding_ids = {finding.id for finding in result.findings}
    assert "PERM-_etc_shadow" in finding_ids
    assert "PERM-_etc_sudoers" in finding_ids
    assert "PERM-_etc_passwd" not in finding_ids
    assert "PERM-_etc_ssh_sshd_config" not in finding_ids

    by_id = {finding.id: finding for finding in result.findings}
    assert by_id["PERM-_etc_shadow"].severity == Severity.CRITICAL
    assert by_id["PERM-_etc_sudoers"].severity == Severity.CRITICAL


def test_permissions_audit_reports_stat_failures() -> None:
    result = AuditResult(target="localhost")
    command_map = {
        "stat -c '%a' /etc/passwd": CommandResult("", "", "permission denied", 1),
        "stat -c '%a' /etc/shadow": CommandResult("", "640", "", 0),
        "stat -c '%a' /etc/sudoers": CommandResult("", "440", "", 0),
        "stat -c '%a' /etc/ssh/sshd_config": CommandResult("", "600", "", 0),
    }
    auditor = PermissionsAuditor(FakeExecutor(command_map), result)

    auditor.run()

    info_findings = [finding for finding in result.findings if finding.id.startswith("PERM-NOACCESS")]
    assert len(info_findings) == 1
    assert info_findings[0].severity == Severity.INFO
    assert "/etc/passwd" in info_findings[0].title
