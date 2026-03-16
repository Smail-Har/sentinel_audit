"""
sentinel_audit/core/utils.py
─────────────────────────────
General-purpose helper functions used across audit modules.
"""

from __future__ import annotations

import logging
import re
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Text helpers
# ──────────────────────────────────────────────

def parse_key_value(text: str, separator: str = "=") -> dict[str, str]:
    """
    Parse a block of ``key=value`` (or ``key: value``) lines into a dict.

    Lines starting with ``#`` and blank lines are ignored.

    >>> parse_key_value("PORT=22\\n# comment\\nProtocol 2", separator=" ")
    {'PORT': '22', 'Protocol': '2'}
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(separator, 1)
        if len(parts) == 2:
            result[parts[0].strip()] = parts[1].strip()
    return result


def parse_sshd_config(text: str) -> dict[str, str]:
    """
    Parse ``sshd_config``-style directives (space-separated key value).

    Only the first occurrence of each directive is kept (matching sshd
    behaviour where the first definition wins).
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)   # split on first whitespace
        if len(parts) == 2:
            key = parts[0]
            if key not in result:          # first definition wins
                result[key] = parts[1]
    return result


def octal_permissions(mode: int) -> str:
    """Convert a raw ``st_mode`` integer to an octal string like ``0o644``."""
    return oct(stat.S_IMODE(mode))


def parse_octal(octal_str: str) -> int:
    """Parse an octal string (e.g. ``'644'``) into an integer."""
    return int(octal_str, 8)


# ──────────────────────────────────────────────
# OS detection helpers
# ──────────────────────────────────────────────

def detect_os_family(os_id: str) -> str:
    """
    Return a normalised OS family string from an ``/etc/os-release`` ID.

    Returns ``'debian'``, ``'rhel'``, or ``'unknown'``.
    """
    debian_like = {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}
    rhel_like = {"rhel", "centos", "rocky", "almalinux", "fedora", "ol"}
    lower = os_id.lower()
    if lower in debian_like:
        return "debian"
    if lower in rhel_like:
        return "rhel"
    return "unknown"


# ──────────────────────────────────────────────
# Port / network helpers
# ──────────────────────────────────────────────

def parse_ss_output(output: str) -> list[dict[str, str]]:
    """
    Parse ``ss -tlnup`` output into a list of dicts with keys:
    ``proto``, ``local_address``, ``local_port``, ``process``.
    """
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        # Skip header lines
        if line.startswith("Netid") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        process = parts[-1] if len(parts) > 5 else ""
        # local is like  0.0.0.0:22  or  [::]:22
        if ":" in local:
            addr, port = local.rsplit(":", 1)
        else:
            addr, port = local, ""
        entries.append(
            {
                "proto": proto,
                "local_address": addr,
                "local_port": port,
                "process": process,
            }
        )
    return entries


def parse_netstat_output(output: str) -> list[dict[str, str]]:
    """Parse ``netstat -tlnup`` output similarly to :func:`parse_ss_output`."""
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        if not line or line.startswith(("Active", "Proto", "Netid")):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        local = parts[3]
        if ":" in local:
            addr, port = local.rsplit(":", 1)
        else:
            addr, port = local, ""
        process = parts[-1] if len(parts) >= 7 else ""
        entries.append(
            {
                "proto": proto,
                "local_address": addr,
                "local_port": port,
                "process": process,
            }
        )
    return entries


# ──────────────────────────────────────────────
# Misc
# ──────────────────────────────────────────────

def truncate(text: str, max_len: int = 500) -> str:
    """Truncate *text* to *max_len* characters, appending ``'…'`` if clipped."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def safe_get(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Traverse nested dicts safely, returning *default* on any missing key."""
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current
