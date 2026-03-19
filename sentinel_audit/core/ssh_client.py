"""
sentinel_audit/core/ssh_client.py
──────────────────────────────────
Thin Paramiko wrapper providing an authenticated SSH session.

Security:
- Uses RejectPolicy by default — unknown hosts are **rejected**.
- Loads system and user known_hosts files.
- Supports explicit known_hosts path via constructor.
- Password auth triggers a CLI warning (visible in logs).
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from sentinel_audit.core.constants import DEFAULT_SSH_CONNECT_TIMEOUT
from sentinel_audit.core.exceptions import (
    AuthenticationError,
    HostKeyVerificationError,
)
from sentinel_audit.core.exceptions import (
    ConnectionError as SAConnectionError,
)
from sentinel_audit.core.models import CommandResult

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import paramiko

# Well-known known_hosts locations
_SYSTEM_KNOWN_HOSTS = "/etc/ssh/ssh_known_hosts"
_USER_KNOWN_HOSTS = os.path.expanduser("~/.ssh/known_hosts")


class SSHClient:
    """Authenticated SSH session to a remote Linux host.

    Args:
        host: Hostname or IP address of the target.
        username: Remote user.
        port: SSH port (default 22).
        key_path: Path to a PEM private key file.
        password: Plaintext password (avoid — key-based auth preferred).
        connect_timeout: TCP connection timeout in seconds.
        known_hosts_path: Explicit path to a known_hosts file.
            If None, the system and user defaults are loaded.
    """

    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        key_path: str | None = None,
        password: str | None = None,
        passphrase: str | None = None,
        connect_timeout: int = DEFAULT_SSH_CONNECT_TIMEOUT,
        known_hosts_path: str | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.port = port
        self.key_path = os.path.expanduser(key_path) if key_path else None
        self.password = password
        self.passphrase = passphrase
        self.connect_timeout = connect_timeout
        self.known_hosts_path = known_hosts_path
        self._client: paramiko.SSHClient | None = None

    # ── connection lifecycle ──────────────────

    def connect(self) -> None:
        """Open and authenticate the SSH connection.

        Raises:
            HostKeyVerificationError: If the host key is not in known_hosts.
            AuthenticationError: If authentication fails.
            ConnectionError: If the TCP connection fails.
        """
        try:
            import paramiko
        except ImportError as exc:
            raise SAConnectionError("paramiko is not installed. Run: pip install paramiko") from exc

        if self.password:
            logger.warning(
                "Password authentication is used for %s@%s. Key-based auth is strongly recommended.",
                self.username,
                self.host,
            )

        client = paramiko.SSHClient()

        # SECURITY: Reject unknown host keys by default
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        # Load known_hosts files
        if self.known_hosts_path:
            try:
                client.load_host_keys(self.known_hosts_path)
            except (OSError, paramiko.SSHException) as exc:
                raise HostKeyVerificationError(f"Cannot load known_hosts from {self.known_hosts_path}: {exc}") from exc
        else:
            # Load system-wide and user known_hosts
            if os.path.isfile(_SYSTEM_KNOWN_HOSTS):
                try:
                    client.load_system_host_keys(_SYSTEM_KNOWN_HOSTS)
                except (OSError, paramiko.SSHException):
                    logger.debug("Could not load system known_hosts: %s", _SYSTEM_KNOWN_HOSTS)

            if os.path.isfile(_USER_KNOWN_HOSTS):
                try:
                    client.load_host_keys(_USER_KNOWN_HOSTS)
                except (OSError, paramiko.SSHException):
                    logger.debug("Could not load user known_hosts: %s", _USER_KNOWN_HOSTS)

        connect_kwargs: dict[str, object] = {
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
            if self.passphrase:
                connect_kwargs["passphrase"] = self.passphrase
        elif self.password:
            connect_kwargs["password"] = self.password
            connect_kwargs["look_for_keys"] = False

        try:
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
            logger.info("SSH connected to %s@%s:%s", self.username, self.host, self.port)
            self._client = client
        except paramiko.PasswordRequiredException:
            # Key is encrypted and no passphrase was provided — prompt interactively
            import getpass

            passphrase = getpass.getpass(f"Passphrase for {self.key_path}: ")
            connect_kwargs["passphrase"] = passphrase
            client.connect(**connect_kwargs)  # type: ignore[arg-type]
            logger.info("SSH connected to %s@%s:%s (passphrase)", self.username, self.host, self.port)
            self._client = client
            return
        except paramiko.SSHException as exc:
            error_msg = str(exc).lower()
            if "host key" in error_msg or "not found in known_hosts" in error_msg:
                raise HostKeyVerificationError(
                    f"Host key verification failed for {self.host}:{self.port}. "
                    f"Add the host key to known_hosts first: "
                    f"ssh-keyscan -p {self.port} {self.host} >> ~/.ssh/known_hosts"
                ) from exc
            raise SAConnectionError(f"SSH error connecting to {self.host}:{self.port} — {exc}") from exc
        except paramiko.AuthenticationException as exc:
            raise AuthenticationError(f"Authentication failed for {self.username}@{self.host}") from exc
        except Exception as exc:
            raise SAConnectionError(f"Cannot connect to {self.host}:{self.port} — {exc}") from exc

    def disconnect(self) -> None:
        """Close the SSH session."""
        if self._client:
            self._client.close()
            self._client = None
            logger.info("SSH disconnected from %s", self.host)

    def __enter__(self) -> SSHClient:
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()

    # ── command execution ─────────────────────

    def exec(self, command: str, timeout: int = 30) -> CommandResult:
        """Execute a command on the remote host.

        The command is run in a non-interactive, non-login shell.
        """
        if self._client is None:
            raise SAConnectionError("SSH client is not connected. Call connect() first.")

        try:
            _, stdout, stderr = self._client.exec_command(
                command,
                timeout=timeout,
            )
            exit_code: int = stdout.channel.recv_exit_status()
            return CommandResult(
                command=command,
                stdout=stdout.read().decode("utf-8", errors="replace").strip(),
                stderr=stderr.read().decode("utf-8", errors="replace").strip(),
                return_code=exit_code,
            )
        except Exception as exc:
            logger.error("SSH exec failed [%s]: %s", command, exc)
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(exc),
                return_code=-1,
            )
