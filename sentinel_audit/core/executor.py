"""
sentinel_audit/core/executor.py
────────────────────────────────
Abstraction layer for running shell commands either locally (subprocess)
or remotely (via an SSHClient instance).

Usage
─────
    # Local
    executor = LocalExecutor()
    result = executor.run("id")

    # Remote
    from sentinel_audit.core.ssh_client import SSHClient
    client = SSHClient("192.168.1.10", "admin", key_path="~/.ssh/id_rsa")
    client.connect()
    executor = RemoteExecutor(client)
    result = executor.run("id")
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from sentinel_audit.core.models import CommandResult

if TYPE_CHECKING:
    from sentinel_audit.core.ssh_client import SSHClient

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds


class BaseExecutor(ABC):
    """Abstract command executor."""

    @abstractmethod
    def run(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """Execute *command* and return a :class:`CommandResult`."""
        ...

    @abstractmethod
    def read_file(self, path: str) -> CommandResult:
        """Read the content of a remote or local file."""
        ...

    def run_many(
        self, *commands: str, timeout: int = DEFAULT_TIMEOUT
    ) -> list[CommandResult]:
        """Run multiple commands sequentially and return all results."""
        return [self.run(cmd, timeout=timeout) for cmd in commands]


# ──────────────────────────────────────────────
# Local executor (subprocess)
# ──────────────────────────────────────────────

class LocalExecutor(BaseExecutor):
    """Execute commands on the local machine using :mod:`subprocess`."""

    def run(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        """
        Run *command* via ``/bin/sh -c`` and return the captured output.

        The shell is never called with user-controlled input without
        validation; audit commands are all hard-coded strings.
        """
        logger.debug("LOCAL » %s", command)
        try:
            proc = subprocess.run(
                command,
                shell=True,          # noqa: S602  (intended: hard-coded cmds)
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CommandResult(
                command=command,
                stdout=proc.stdout.strip(),
                stderr=proc.stderr.strip(),
                return_code=proc.returncode,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out after %ds: %s", timeout, command)
            return CommandResult(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                return_code=-1,
                timed_out=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Command failed: %s — %s", command, exc)
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(exc),
                return_code=-1,
            )

    def read_file(self, path: str) -> CommandResult:
        """Read a local file using :func:`open`."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            return CommandResult(
                command=f"read_file:{path}",
                stdout=content,
                stderr="",
                return_code=0,
            )
        except PermissionError:
            return CommandResult(
                command=f"read_file:{path}",
                stdout="",
                stderr=f"Permission denied: {path}",
                return_code=1,
            )
        except FileNotFoundError:
            return CommandResult(
                command=f"read_file:{path}",
                stdout="",
                stderr=f"File not found: {path}",
                return_code=2,
            )
        except Exception as exc:  # noqa: BLE001
            return CommandResult(
                command=f"read_file:{path}",
                stdout="",
                stderr=str(exc),
                return_code=-1,
            )


# ──────────────────────────────────────────────
# Remote executor (SSH)
# ──────────────────────────────────────────────

class RemoteExecutor(BaseExecutor):
    """Execute commands on a remote host via an established :class:`SSHClient`."""

    def __init__(self, ssh_client: "SSHClient") -> None:
        self._ssh = ssh_client

    def run(self, command: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        logger.debug("SSH[%s] » %s", self._ssh.host, command)
        return self._ssh.exec(command, timeout=timeout)

    def read_file(self, path: str) -> CommandResult:
        """Read a remote file via ``cat``."""
        return self.run(f"cat {shlex.quote(path)}")
