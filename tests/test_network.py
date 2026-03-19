"""Tests for network audit module."""

from __future__ import annotations

from conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.network_audit import NetworkAuditor
from sentinel_audit.core.constants import Severity

_SS_HEADER = "Netid  State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"


def test_exposed_mysql_flagged() -> None:
    ss_output = f"""{_SS_HEADER}
tcp   LISTEN 0      128    0.0.0.0:3306  0.0.0.0:*     users:(("mysqld",pid=1234,fd=3))
tcp   LISTEN 0      128    127.0.0.1:22  0.0.0.0:*     users:(("sshd",pid=100,fd=3))"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd(rc=1),
            "wg show interfaces 2>/dev/null": cmd(rc=1),
            "lsmod 2>/dev/null | grep -q wireguard && echo yes": cmd(rc=1),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    ids = {f.id for f in result.findings}
    assert "NET-001" in ids
    assert any("MySQL" in f.title for f in result.findings)


def test_loopback_ports_not_flagged() -> None:
    ss_output = f"""{_SS_HEADER}
tcp   LISTEN 0      128    127.0.0.1:3306  0.0.0.0:*     users:(("mysqld",pid=1234,fd=3))
tcp   LISTEN 0      128    ::1:6379        :::*           users:(("redis",pid=1235,fd=3))"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd(rc=1),
            "wg show interfaces 2>/dev/null": cmd(rc=1),
            "lsmod 2>/dev/null | grep -q wireguard && echo yes": cmd(rc=1),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    assert len(result.findings) == 0


def test_non_standard_port_exposed() -> None:
    ss_output = f"""{_SS_HEADER}
tcp   LISTEN 0      128    0.0.0.0:9999   0.0.0.0:*     users:(("app",pid=500,fd=3))"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd(rc=1),
            "wg show interfaces 2>/dev/null": cmd(rc=1),
            "lsmod 2>/dev/null | grep -q wireguard && echo yes": cmd(rc=1),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    ids = {f.id for f in result.findings}
    assert "NET-002" in ids
    assert result.findings[0].severity == Severity.MEDIUM


def test_common_ports_not_flagged() -> None:
    ss_output = f"""{_SS_HEADER}
tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*     users:(("sshd",pid=100,fd=3))
tcp   LISTEN 0      128    0.0.0.0:443   0.0.0.0:*     users:(("nginx",pid=200,fd=3))"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd(rc=1),
            "wg show interfaces 2>/dev/null": cmd(rc=1),
            "lsmod 2>/dev/null | grep -q wireguard && echo yes": cmd(rc=1),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    assert len(result.findings) == 0


def test_ports_collected_as_inventory() -> None:
    ss_output = f"""{_SS_HEADER}
tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*     users:(("sshd",pid=100,fd=3))"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd(rc=1),
            "wg show interfaces 2>/dev/null": cmd(rc=1),
            "lsmod 2>/dev/null | grep -q wireguard && echo yes": cmd(rc=1),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    assert len(result.system_info.listening_ports) >= 1


def test_wireguard_port_downgraded_to_info() -> None:
    """WireGuard port 51820 should be INFO, not MEDIUM, when WG is detected."""
    ss_output = f"""{_SS_HEADER}
udp   UNCONN 0      0      0.0.0.0:51820  0.0.0.0:*
udp   UNCONN 0      0      [::]:51820     [::]:*"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd("3: wg0: <POINTOPOINT,NOARP,UP> mtu 1420"),
            "wg show all listen-port 2>/dev/null": cmd("wg0\t51820"),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    net_findings = [f for f in result.findings if f.id == "NET-002"]
    # Should be exactly 1 (dedup IPv4+IPv6) and INFO severity
    assert len(net_findings) == 1
    assert net_findings[0].severity == Severity.INFO
    assert "WireGuard" in net_findings[0].title


def test_ipv4_ipv6_dedup() -> None:
    """Same port on both IPv4 and IPv6 should produce only one finding."""
    ss_output = f"""{_SS_HEADER}
tcp   LISTEN 0      128    0.0.0.0:9999   0.0.0.0:*     users:(("app",pid=500,fd=3))
tcp   LISTEN 0      128    [::]:9999      [::]:*        users:(("app",pid=500,fd=3))"""

    executor = FakeExecutor(
        command_map={
            "ss -tlnup 2>/dev/null": cmd(ss_output),
            "ip link show type wireguard 2>/dev/null": cmd(rc=1),
            "wg show interfaces 2>/dev/null": cmd(rc=1),
            "lsmod 2>/dev/null | grep -q wireguard && echo yes": cmd(rc=1),
        }
    )
    result = make_result()
    NetworkAuditor(executor, result).run()

    net_findings = [f for f in result.findings if f.id == "NET-002"]
    assert len(net_findings) == 1
