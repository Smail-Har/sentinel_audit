"""Tests for the permissions audit module."""

from __future__ import annotations

from unittest.mock import patch

from tests.conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.permissions_audit import PermissionsAuditor
from sentinel_audit.core.constants import Severity


# Mock YAML rules for test isolation
_TEST_RULES = [
    {
        "id": "PERM-001",
        "path": "/etc/passwd",
        "expected_mode": "644",
        "severity": "HIGH",
        "description": "/etc/passwd should be 644",
        "recommendation": "chmod 644 /etc/passwd",
    },
    {
        "id": "PERM-002",
        "path": "/etc/shadow",
        "expected_mode": "640",
        "severity": "CRITICAL",
        "description": "/etc/shadow should be 640",
        "recommendation": "chmod 640 /etc/shadow",
    },
]


def _make_auditor(command_map: dict[str, object]) -> PermissionsAuditor:
    result = make_result()
    executor = FakeExecutor(command_map=command_map)
    return PermissionsAuditor(executor, result)


@patch.object(PermissionsAuditor, "_load_permission_rules", return_value=_TEST_RULES)
def test_detects_wrong_permissions(mock_rules: object) -> None:
    auditor = _make_auditor({
        "stat -c '%a' /etc/passwd": cmd("644"),
        "stat -c '%a' /etc/shadow": cmd("644"),  # Wrong: should be 640
    })
    auditor.run()

    ids = {f.id for f in auditor.result.findings}
    assert "PERM-002" in ids
    assert "PERM-001" not in ids

    finding = auditor.result.findings[0]
    assert finding.severity == Severity.CRITICAL
    assert "644" in finding.evidence


@patch.object(PermissionsAuditor, "_load_permission_rules", return_value=_TEST_RULES)
def test_correct_permissions_no_findings(mock_rules: object) -> None:
    auditor = _make_auditor({
        "stat -c '%a' /etc/passwd": cmd("644"),
        "stat -c '%a' /etc/shadow": cmd("640"),
    })
    auditor.run()

    assert len(auditor.result.findings) == 0


@patch.object(PermissionsAuditor, "_load_permission_rules", return_value=_TEST_RULES)
def test_stat_failure_produces_info_finding(mock_rules: object) -> None:
    auditor = _make_auditor({
        "stat -c '%a' /etc/passwd": cmd(stderr="permission denied", rc=1),
        "stat -c '%a' /etc/shadow": cmd("640"),
    })
    auditor.run()

    noaccess = [f for f in auditor.result.findings if "NOACCESS" in f.id]
    assert len(noaccess) == 1
    assert noaccess[0].severity == Severity.INFO
