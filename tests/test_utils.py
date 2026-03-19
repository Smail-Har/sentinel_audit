"""Tests for core utility functions."""

from __future__ import annotations

from sentinel_audit.core.utils import (
    detect_os_family,
    is_address_exposed,
    parse_key_value,
    parse_sshd_config,
    parse_ss_output,
    sanitise_evidence,
)


# ── parse_key_value ──

def test_parse_key_value_basic() -> None:
    text = "KEY1=value1\nKEY2=value2\n# comment\n\nKEY3=value with spaces"
    result = parse_key_value(text)
    assert result == {"KEY1": "value1", "KEY2": "value2", "KEY3": "value with spaces"}


def test_parse_key_value_custom_separator() -> None:
    text = "host:localhost\nport:22"
    result = parse_key_value(text, separator=":")
    assert result == {"host": "localhost", "port": "22"}


# ── parse_sshd_config ──

def test_parse_sshd_config_first_wins() -> None:
    text = "PermitRootLogin no\nPermitRootLogin yes\n# PermitRootLogin maybe"
    result = parse_sshd_config(text)
    assert result["PermitRootLogin"] == "no"


def test_parse_sshd_config_skips_comments() -> None:
    text = "# PasswordAuthentication yes\nPasswordAuthentication no"
    result = parse_sshd_config(text)
    assert result["PasswordAuthentication"] == "no"


# ── is_address_exposed ──

def test_loopback_not_exposed() -> None:
    assert not is_address_exposed("127.0.0.1")
    assert not is_address_exposed("::1")
    assert not is_address_exposed("[::1]")
    assert not is_address_exposed("localhost")
    assert not is_address_exposed("127.0.0.2")


def test_external_is_exposed() -> None:
    assert is_address_exposed("0.0.0.0")
    assert is_address_exposed("192.168.1.1")
    assert is_address_exposed("::")
    assert is_address_exposed("*")


# ── detect_os_family ──

def test_os_family_detection() -> None:
    assert detect_os_family("ubuntu") == "debian"
    assert detect_os_family("debian") == "debian"
    assert detect_os_family("centos") == "rhel"
    assert detect_os_family("rocky") == "rhel"
    assert detect_os_family("alpine") == "alpine"
    assert detect_os_family("something_else") == "unknown"
    assert detect_os_family('"ubuntu"') == "debian"  # handles quotes


# ── parse_ss_output ──

def test_parse_ss_output() -> None:
    output = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*     users:(("sshd",pid=100))
tcp   LISTEN 0      128    127.0.0.1:3306 0.0.0.0:*    users:(("mysqld",pid=200))"""

    entries = parse_ss_output(output)
    assert len(entries) == 2
    assert entries[0]["local_port"] == "22"
    assert entries[1]["local_address"] == "127.0.0.1"


# ── sanitise_evidence ──

def test_sanitise_strips_password_hash() -> None:
    text = "root:$6$salt$hashedpassword:19000:0:99999:7:::"
    result = sanitise_evidence(text)
    assert "$6$" not in result
    assert "HASH_REDACTED" in result


def test_sanitise_strips_private_key() -> None:
    text = "Found key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n-----END RSA PRIVATE KEY-----\nEnd."
    result = sanitise_evidence(text)
    assert "PRIVATE_KEY_REDACTED" in result
    assert "MIIEpAIB" not in result


def test_sanitise_leaves_normal_text() -> None:
    text = "PermitRootLogin yes"
    assert sanitise_evidence(text) == text
