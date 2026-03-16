from __future__ import annotations

from sentinel_audit.audit.ssh_audit import SSHAuditor
from sentinel_audit.core.models import AuditResult, CommandResult, Severity


class FakeExecutor:
    def __init__(self, file_content: str = "", read_ok: bool = True, stderr: str = "") -> None:
        self.file_content = file_content
        self.read_ok = read_ok
        self.stderr = stderr

    def run(self, command: str, timeout: int = 30) -> CommandResult:
        return CommandResult(command=command, stdout="", stderr="", return_code=0)

    def read_file(self, path: str) -> CommandResult:
        if self.read_ok:
            return CommandResult(command=f"read_file:{path}", stdout=self.file_content, stderr="", return_code=0)
        return CommandResult(command=f"read_file:{path}", stdout="", stderr=self.stderr, return_code=1)


def test_ssh_audit_detects_insecure_directives() -> None:
    insecure_config = "\n".join(
        [
            "PermitRootLogin yes",
            "PasswordAuthentication yes",
            "PubkeyAuthentication no",
            "MaxAuthTries 6",
        ]
    )
    result = AuditResult(target="localhost")
    auditor = SSHAuditor(FakeExecutor(file_content=insecure_config), result)

    auditor.run()

    finding_ids = {finding.id for finding in result.findings}
    assert {"SSH-001", "SSH-002", "SSH-003", "SSH-004"}.issubset(finding_ids)

    severities = {finding.id: finding.severity for finding in result.findings}
    assert severities["SSH-001"] == Severity.CRITICAL
    assert severities["SSH-002"] == Severity.HIGH
    assert severities["SSH-003"] == Severity.MEDIUM
    assert severities["SSH-004"] == Severity.MEDIUM


def test_ssh_audit_handles_unreadable_config() -> None:
    result = AuditResult(target="localhost")
    auditor = SSHAuditor(FakeExecutor(read_ok=False, stderr="permission denied"), result)

    auditor.run()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.id == "SSH-000"
    assert finding.severity == Severity.INFO
    assert "permission denied" in finding.evidence
