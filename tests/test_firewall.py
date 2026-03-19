"""Tests for firewall audit module."""

from __future__ import annotations

from tests.conftest import FakeExecutor, cmd, make_result

from sentinel_audit.audit.firewall_audit import FirewallAuditor
from sentinel_audit.core.constants import Severity


def test_no_firewall_produces_critical() -> None:
    executor = FakeExecutor(command_map={
        "ufw status 2>&1": cmd(rc=1),
        "systemctl is-active firewalld 2>/dev/null": cmd(rc=1),
        "iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd("0"),
        "nft list ruleset 2>&1 | wc -l": cmd("0"),
        "iptables -L INPUT -n 2>/dev/null | head -1": cmd(rc=1),
    })
    result = make_result()
    auditor = FirewallAuditor(executor, result)
    auditor.run()

    ids = {f.id for f in result.findings}
    assert "FW-001" in ids
    assert result.findings[0].severity == Severity.CRITICAL


def test_ufw_active_no_finding() -> None:
    executor = FakeExecutor(command_map={
        "ufw status 2>&1": cmd("Status: active\nTo Action From\n-- ------ ----"),
        "systemctl is-active firewalld 2>/dev/null": cmd(rc=1),
        "iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd("0"),
        "nft list ruleset 2>&1 | wc -l": cmd("0"),
        "iptables -L INPUT -n 2>/dev/null | head -1": cmd("Chain INPUT (policy DROP)"),
    })
    result = make_result()
    FirewallAuditor(executor, result).run()

    assert not any(f.id == "FW-001" for f in result.findings)
    assert "firewall:ufw" in result.system_info.running_services


def test_accept_policy_produces_high() -> None:
    executor = FakeExecutor(command_map={
        "ufw status 2>&1": cmd("Status: active\n"),
        "systemctl is-active firewalld 2>/dev/null": cmd(rc=1),
        "iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd("0"),
        "nft list ruleset 2>&1 | wc -l": cmd("0"),
        "iptables -L INPUT -n 2>/dev/null | head -1": cmd("Chain INPUT (policy ACCEPT)"),
    })
    result = make_result()
    FirewallAuditor(executor, result).run()

    ids = {f.id for f in result.findings}
    assert "FW-002" in ids
    assert any(f.severity == Severity.HIGH for f in result.findings if f.id == "FW-002")


def test_permission_denied_downgrades_to_info() -> None:
    """When ufw/iptables/nft fail with permission errors, emit INFO not CRITICAL."""
    executor = FakeExecutor(command_map={
        "ufw status 2>&1": cmd(
            stdout="ERROR: You need to be root to run this script", rc=1),
        "sudo -n ufw status 2>&1": cmd(rc=1),  # sudo not available
        "systemctl is-active ufw 2>/dev/null": cmd(rc=3),  # ufw service unknown
        "systemctl is-active firewalld 2>/dev/null": cmd(rc=3),
        "iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd(
            stdout="iptables: Permission denied", rc=4),
        "sudo -n iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd(rc=1),
        "nft list ruleset 2>&1 | wc -l": cmd(
            stdout="Error: Operation not permitted", rc=1),
        "sudo -n nft list ruleset 2>&1 | wc -l": cmd(rc=1),
        "systemctl is-active nftables 2>/dev/null": cmd(rc=3),
        "iptables -L INPUT -n 2>/dev/null | head -1": cmd(rc=1),
    })
    result = make_result()
    FirewallAuditor(executor, result).run()

    fw_findings = [f for f in result.findings if f.id == "FW-001"]
    assert len(fw_findings) == 1
    assert fw_findings[0].severity == Severity.INFO
    assert "insufficient privileges" in fw_findings[0].title.lower()


def test_sudo_fallback_detects_ufw() -> None:
    """When ufw status fails but sudo -n ufw status succeeds, detect firewall."""
    executor = FakeExecutor(command_map={
        "ufw status 2>&1": cmd(
            stdout="ERROR: You need to be root to run this script", rc=1),
        "sudo -n ufw status 2>&1": cmd("Status: active\nDefault: deny (incoming)"),
        "systemctl is-active firewalld 2>/dev/null": cmd(rc=3),
        "iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd("0"),
        "nft list ruleset 2>&1 | wc -l": cmd("0"),
        "iptables -L INPUT -n 2>/dev/null | head -1": cmd(rc=1),
    })
    result = make_result()
    FirewallAuditor(executor, result).run()

    assert not any(f.id == "FW-001" for f in result.findings)
    assert "firewall:ufw" in result.system_info.running_services


def test_systemctl_fallback_detects_ufw() -> None:
    """When ufw status and sudo both fail, systemctl is-active ufw works."""
    executor = FakeExecutor(command_map={
        "ufw status 2>&1": cmd(
            stdout="ERROR: You need to be root to run this script", rc=1),
        "sudo -n ufw status 2>&1": cmd(rc=1),
        "systemctl is-active ufw 2>/dev/null": cmd("active"),
        "systemctl is-active firewalld 2>/dev/null": cmd(rc=3),
        "iptables -L -n 2>&1 | grep -v '^Chain\\|^target\\|^$' | wc -l": cmd("0"),
        "nft list ruleset 2>&1 | wc -l": cmd("0"),
        "iptables -L INPUT -n 2>/dev/null | head -1": cmd(rc=1),
    })
    result = make_result()
    FirewallAuditor(executor, result).run()

    assert not any(f.id == "FW-001" for f in result.findings)
    assert "firewall:ufw" in result.system_info.running_services
