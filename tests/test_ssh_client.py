"""Tests for SSH client — agent authentication logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel_audit.core.exceptions import AuthenticationError
from sentinel_audit.core.ssh_client import SSHClient

# ── Helpers ───────────────────────────────────────────────────


def _make_client(
    *,
    key_path: str | None = None,
    password: str | None = None,
) -> SSHClient:
    """Build an SSHClient without connecting."""
    return SSHClient(
        host="10.0.0.1",
        username="auditor",
        key_path=key_path,
        password=password,
        known_hosts_path="/dev/null",
    )


def _stub_paramiko_client(mock_ssh_client_cls: MagicMock) -> MagicMock:
    """Return a mock paramiko.SSHClient instance wired to the class mock."""
    mock_instance = MagicMock()
    mock_ssh_client_cls.return_value = mock_instance
    return mock_instance


# ── Agent available with keys ─────────────────────────────────


@patch.dict("os.environ", {"SSH_AUTH_SOCK": "/tmp/agent.sock"})
@patch("sentinel_audit.core.ssh_client.paramiko.SSHClient")
@patch("sentinel_audit.core.ssh_client.paramiko.RejectPolicy")
@patch("sentinel_audit.core.ssh_client.paramiko.Agent")
def test_agent_with_keys(
    mock_agent_cls: MagicMock,
    _mock_reject: MagicMock,
    mock_ssh_cls: MagicMock,
) -> None:
    """When no key/password and SSH_AUTH_SOCK is set with keys, connect via agent."""
    mock_agent_cls.return_value.get_keys.return_value = [MagicMock()]
    mock_client = _stub_paramiko_client(mock_ssh_cls)

    client = _make_client()
    client.connect()

    # Agent was instantiated and keys checked BEFORE connect()
    mock_agent_cls.assert_called_once()
    mock_agent_cls.return_value.get_keys.assert_called_once()

    call_kwargs = mock_client.connect.call_args[1]
    assert call_kwargs["allow_agent"] is True
    assert "key_filename" not in call_kwargs
    assert "password" not in call_kwargs

    # get_keys() must have been called before client.connect()
    get_keys_order = mock_agent_cls.return_value.get_keys.call_count
    connect_order = mock_client.connect.call_count
    assert get_keys_order == 1
    assert connect_order == 1


# ── Agent available but no keys ───────────────────────────────


@patch.dict("os.environ", {"SSH_AUTH_SOCK": "/tmp/agent.sock"})
@patch("sentinel_audit.core.ssh_client.paramiko.SSHClient")
@patch("sentinel_audit.core.ssh_client.paramiko.RejectPolicy")
@patch("sentinel_audit.core.ssh_client.paramiko.Agent")
def test_agent_without_keys(
    mock_agent_cls: MagicMock,
    _mock_reject: MagicMock,
    _mock_ssh_cls: MagicMock,
) -> None:
    """When agent has no keys, raise AuthenticationError immediately."""
    mock_agent_cls.return_value.get_keys.return_value = []

    client = _make_client()

    with pytest.raises(AuthenticationError, match="agent contains no keys"):
        client.connect()


# ── Agent unavailable + key file provided ─────────────────────


@patch.dict("os.environ", {}, clear=True)
@patch("sentinel_audit.core.ssh_client.paramiko.SSHClient")
@patch("sentinel_audit.core.ssh_client.paramiko.RejectPolicy")
@patch("sentinel_audit.core.ssh_client.paramiko.Agent")
def test_key_file_without_agent(
    mock_agent_cls: MagicMock,
    _mock_reject: MagicMock,
    mock_ssh_cls: MagicMock,
) -> None:
    """When key_path is provided, use key file regardless of agent."""
    mock_client = _stub_paramiko_client(mock_ssh_cls)

    client = _make_client(key_path="/home/auditor/.ssh/id_ed25519")
    client.connect()

    call_kwargs = mock_client.connect.call_args[1]
    assert call_kwargs["key_filename"] == "/home/auditor/.ssh/id_ed25519"
    assert call_kwargs["allow_agent"] is False
    mock_agent_cls.assert_not_called()


# ── Agent unavailable + no auth method ────────────────────────


@patch.dict("os.environ", {}, clear=True)
@patch("sentinel_audit.core.ssh_client.paramiko.SSHClient")
@patch("sentinel_audit.core.ssh_client.paramiko.RejectPolicy")
def test_no_auth_method(
    _mock_reject: MagicMock,
    _mock_ssh_cls: MagicMock,
) -> None:
    """When no key, no password, no agent → clear AuthenticationError."""
    client = _make_client()

    with pytest.raises(AuthenticationError, match="No SSH authentication method"):
        client.connect()


# ── Password takes priority over agent ────────────────────────


@patch.dict("os.environ", {"SSH_AUTH_SOCK": "/tmp/agent.sock"})
@patch("sentinel_audit.core.ssh_client.paramiko.SSHClient")
@patch("sentinel_audit.core.ssh_client.paramiko.RejectPolicy")
@patch("sentinel_audit.core.ssh_client.paramiko.Agent")
def test_password_priority_over_agent(
    mock_agent_cls: MagicMock,
    _mock_reject: MagicMock,
    mock_ssh_cls: MagicMock,
) -> None:
    """When password is provided, use password even if agent is available."""
    mock_client = _stub_paramiko_client(mock_ssh_cls)

    client = _make_client(password="s3cret")
    client.connect()

    call_kwargs = mock_client.connect.call_args[1]
    assert call_kwargs["password"] == "s3cret"
    assert call_kwargs["allow_agent"] is False
    mock_agent_cls.assert_not_called()


# ── Key file takes priority over agent ────────────────────────


@patch.dict("os.environ", {"SSH_AUTH_SOCK": "/tmp/agent.sock"})
@patch("sentinel_audit.core.ssh_client.paramiko.SSHClient")
@patch("sentinel_audit.core.ssh_client.paramiko.RejectPolicy")
@patch("sentinel_audit.core.ssh_client.paramiko.Agent")
def test_key_file_priority_over_agent(
    mock_agent_cls: MagicMock,
    _mock_reject: MagicMock,
    mock_ssh_cls: MagicMock,
) -> None:
    """When key_path is provided, use key file even if agent is available."""
    mock_client = _stub_paramiko_client(mock_ssh_cls)

    client = _make_client(key_path="~/.ssh/id_rsa")
    client.connect()

    call_kwargs = mock_client.connect.call_args[1]
    assert "key_filename" in call_kwargs
    assert call_kwargs["allow_agent"] is False
    mock_agent_cls.assert_not_called()
