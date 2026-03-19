"""Tests for container audit module."""

from __future__ import annotations

from tests.conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.container_audit import ContainerAuditor
from sentinel_audit.core.constants import Severity


def test_no_docker_skips_audit() -> None:
    executor = FakeExecutor(command_map={
        "which docker 2>/dev/null": cmd(rc=1),
    })
    result = make_result()
    ContainerAuditor(executor, result).run()

    assert len(result.findings) == 0


def test_privileged_container_detected() -> None:
    executor = FakeExecutor(command_map={
        "which docker 2>/dev/null": cmd("/usr/bin/docker"),
        "docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}|{{.Status}}' 2>/dev/null": cmd(
            "abc123|nginx:latest|web|80->80|Up 2h"
        ),
        "docker ps -q 2>/dev/null": cmd("abc123"),
        "docker inspect --format '{{.HostConfig.Privileged}}|{{.Name}}' abc123 2>/dev/null": cmd(
            "true|/web"
        ),
        "stat -c '%a' /var/run/docker.sock 2>/dev/null": cmd("660"),
    })
    result = make_result()
    ContainerAuditor(executor, result).run()

    ids = {f.id for f in result.findings}
    assert "CTR-001" in ids
    assert any(f.severity == Severity.CRITICAL for f in result.findings if f.id == "CTR-001")


def test_docker_socket_loose_permissions() -> None:
    executor = FakeExecutor(command_map={
        "which docker 2>/dev/null": cmd("/usr/bin/docker"),
        "docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}|{{.Status}}' 2>/dev/null": cmd(""),
        "docker ps -q 2>/dev/null": cmd(""),
        "stat -c '%a' /var/run/docker.sock 2>/dev/null": cmd("666"),
    })
    result = make_result()
    ContainerAuditor(executor, result).run()

    ids = {f.id for f in result.findings}
    assert "CTR-002" in ids
    assert any(f.severity == Severity.HIGH for f in result.findings if f.id == "CTR-002")


def test_containers_collected_as_inventory() -> None:
    executor = FakeExecutor(command_map={
        "which docker 2>/dev/null": cmd("/usr/bin/docker"),
        "docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}|{{.Status}}' 2>/dev/null": cmd(
            "abc|nginx|web|80|Up\ndef|redis|cache|6379|Up"
        ),
        "docker ps -q 2>/dev/null": cmd("abc\ndef"),
        "docker inspect --format '{{.HostConfig.Privileged}}|{{.Name}}' abc 2>/dev/null": cmd("false|/web"),
        "docker inspect --format '{{.HostConfig.Privileged}}|{{.Name}}' def 2>/dev/null": cmd("false|/cache"),
        "stat -c '%a' /var/run/docker.sock 2>/dev/null": cmd("660"),
    })
    result = make_result()
    ContainerAuditor(executor, result).run()

    assert len(result.system_info.containers) == 2
