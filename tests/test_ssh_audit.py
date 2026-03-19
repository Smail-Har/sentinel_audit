"""Tests for the SSH audit module."""

from __future__ import annotations

from conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.ssh_audit import SSHAuditor
from sentinel_audit.core.constants import Severity


def _make_auditor(sshd_config: str, *, read_ok: bool = True) -> tuple[SSHAuditor, FakeExecutor]:
    result = make_result()
    file_map = {
        "/etc/ssh/sshd_config": cmd(stdout=sshd_config) if read_ok else cmd(stderr="permission denied", rc=1),
    }
    executor = FakeExecutor(file_map=file_map)
    return SSHAuditor(executor, result), executor


def test_ssh_audit_detects_insecure_directives() -> None:
    insecure_config = "\n".join(
        [
            "PermitRootLogin yes",  # SSH-001 CRITICAL
            "PasswordAuthentication yes",  # SSH-002 HIGH
            "X11Forwarding yes",  # SSH-003 MEDIUM
            "MaxAuthTries 10",  # SSH-004 MEDIUM (max_value: 3)
        ]
    )
    auditor, _ = _make_auditor(insecure_config)
    auditor.run()

    finding_ids = {f.id for f in auditor.result.findings}
    assert "SSH-001" in finding_ids  # PermitRootLogin yes
    assert "SSH-002" in finding_ids  # PasswordAuthentication yes
    assert "SSH-003" in finding_ids  # X11Forwarding yes
    assert "SSH-004" in finding_ids  # MaxAuthTries too high

    by_id = {f.id: f for f in auditor.result.findings}
    assert by_id["SSH-001"].severity == Severity.CRITICAL
    assert by_id["SSH-002"].severity == Severity.HIGH
    assert by_id["SSH-003"].severity == Severity.MEDIUM


def test_ssh_secure_config_produces_no_findings() -> None:
    secure_config = "\n".join(
        [
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "PubkeyAuthentication yes",
            "MaxAuthTries 3",
            "X11Forwarding no",
        ]
    )
    auditor, _ = _make_auditor(secure_config)
    auditor.run()

    assert len(auditor.result.findings) == 0


def test_ssh_audit_uses_defaults_when_directive_absent() -> None:
    """If PasswordAuthentication is absent, sshd defaults to 'yes' → should flag."""
    # Config with no PasswordAuthentication directive
    config = "PubkeyAuthentication yes\nPermitRootLogin no"
    auditor, _ = _make_auditor(config)
    auditor.run()

    finding_ids = {f.id for f in auditor.result.findings}
    assert "SSH-002" in finding_ids  # PasswordAuthentication defaults to yes


def test_ssh_audit_handles_unreadable_config() -> None:
    auditor, _ = _make_auditor("", read_ok=False)
    auditor.run()

    assert len(auditor.result.findings) == 1
    finding = auditor.result.findings[0]
    assert finding.id == "SSH-000"
    assert finding.severity == Severity.INFO
    assert "permission denied" in finding.evidence
