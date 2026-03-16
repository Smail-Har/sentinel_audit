"""
sentinel_audit/core/ssh_client.py
──────────────────────────────────
Thin Paramiko wrapper that provides an authenticated SSH session to a
remote host and exposes a single :meth:`exec` method used by
:class:`~sentinel_audit.core.executor.RemoteExecutor`.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from sentinel_audit.core.exceptions import AuthenticationError
from sentinel_audit.core.exceptions import ConnectionError as SAConnectionError
from sentinel_audit.core.models import CommandResult

logger = logging.getLogger(__name__)


class SSHClient:
    """
    Authenticated SSH session to a remote Linux host.

    Parameters
    ----------
    host:
        Hostname or IP address of the target.
    username:
        Remote user.
    port:
        SSH port (default 22).
    key_path:
        Path to an unencrypted PEM private key file.  Expanded with
        :func:`os.path.expanduser` so ``~/.ssh/id_rsa`` works.
    password:
        Plaintext password (used only when *key_path* is not set).
    connect_timeout:
        TCP connection timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        key_path: Optional[str] = None,
        password: Optional[str] = None,
        connect_timeout: int = 15,
    ) -> None:
        self.host = host
        self.username = username
        self.port = port
        self.key_path = os.path.expanduser(key_path) if key_path else None
        self.password = password
        self.connect_timeout = connect_timeout
        self._client: Optional[object] = None   # paramiko.SSHClient

    # ── connection lifecycle ──────────────────

    def connect(self) -> None:
        """Open and authenticate the SSH connection.

        Raises
        ------
        sentinel_audit.core.exceptions.ConnectionError
            If the TCP connection fails.
        sentinel_audit.core.exceptions.AuthenticationError
            If authentication fails.
        """
        try:
            import paramiko  # local import – optional dependency
        except ImportError as exc:
            raise SAConnectionError(
                "paramiko is not installed. Run: pip install paramiko"
            ) from exc

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.connect_timeout,
            "allow_agent": True,
            "look_for_keys": True,
        }

        if self.key_path:
            connect_kwargs["key_filename"] = self.key_path
            connect_kwargs["look_for_keys"] = False
        elif self.password:
            connect_kwargs["password"] = self.password
            connect_kwargs["look_for_keys"] = False

        try:
            client.connect(**connect_kwargs)
            logger.info("SSH connected to %s@%s:%s", self.username, self.host, self.port)
            self._client = client
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(
                f"Authentication failed for {self.username}@{self.host}"
            ) from exc
        except Exception as exc:
            raise SAConnectionError(
                f"Cannot connect to {self.host}:{self.port} — {exc}"
            ) from exc

    def disconnect(self) -> None:
        """Close the SSH session."""
        if self._client:
            self._client.close()  # type: ignore[union-attr]
            self._client = None
            logger.info("SSH disconnected from %s", self.host)

    def __enter__(self) -> "SSHClient":
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()

    # ── command execution ─────────────────────

    def exec(self, command: str, timeout: int = 30) -> CommandResult:
        """
        Execute a command on the remote host and return a
        :class:`~sentinel_audit.core.models.CommandResult`.

        The command is run in a non-interactive, non-login shell.
        """
        if self._client is None:
            raise SAConnectionError("SSH client is not connected. Call connect() first.")

        try:
            _, stdout, stderr = self._client.exec_command(  # type: ignore[union-attr]
                command, timeout=timeout
            )
            exit_code: int = stdout.channel.recv_exit_status()
            return CommandResult(
                command=command,
                stdout=stdout.read().decode("utf-8", errors="replace").strip(),
                stderr=stderr.read().decode("utf-8", errors="replace").strip(),
                return_code=exit_code,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("SSH exec failed [%s]: %s", command, exc)
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(exc),
                return_code=-1,
            )
