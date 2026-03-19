"""Tests for services audit module."""

from __future__ import annotations

from tests.conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.services_audit import ServicesAuditor
from sentinel_audit.core.constants import Severity


def test_dangerous_service_flagged() -> None:
    executor = FakeExecutor(command_map={
        "systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null": cmd(
            "ssh.service loaded active running\ntelnet.service loaded active running"
        ),
        "systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend --plain 2>/dev/null": cmd(""),
    })
    result = make_result()
    ServicesAuditor(executor, result).run()

    ids = {f.id for f in result.findings}
    assert "SRV-001" in ids
    assert any("telnet" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_safe_services_no_findings() -> None:
    executor = FakeExecutor(command_map={
        "systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null": cmd(
            "sshd.service loaded active running\nnginx.service loaded active running"
        ),
        "systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend --plain 2>/dev/null": cmd(""),
    })
    result = make_result()
    ServicesAuditor(executor, result).run()

    assert len(result.findings) == 0


def test_services_collected_as_inventory() -> None:
    executor = FakeExecutor(command_map={
        "systemctl list-units --type=service --state=running --no-pager --no-legend --plain 2>/dev/null": cmd(
            "sshd.service\nnginx.service"
        ),
        "systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend --plain 2>/dev/null": cmd(
            "sshd.service\ncron.service"
        ),
    })
    result = make_result()
    ServicesAuditor(executor, result).run()

    assert "sshd.service" in result.system_info.running_services
    assert "cron.service" in result.system_info.enabled_services
