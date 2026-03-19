"""
sentinel_audit/core/utils.py
─────────────────────────────
General-purpose helper functions used across audit modules.
"""

from __future__ import annotations

import logging
import re
import stat
from typing import Any

from sentinel_audit.core.constants import ALPINE_LIKE, DEBIAN_LIKE, RHEL_LIKE

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Text helpers
# ──────────────────────────────────────────────


def parse_key_value(text: str, separator: str = "=") -> dict[str, str]:
    """Parse ``key=value`` lines into a dict.  Comments and blanks are skipped."""
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
    """Parse ``sshd_config``-style directives.  First definition wins."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key = parts[0]
            if key not in result:
                result[key] = parts[1]
    return result


def octal_permissions(mode: int) -> str:
    """Convert a raw ``st_mode`` integer to an octal string like ``644``."""
    return oct(stat.S_IMODE(mode))[2:]


def parse_octal(octal_str: str) -> int:
    """Parse an octal string (e.g. ``'644'``) into an integer."""
    return int(octal_str, 8)


# ──────────────────────────────────────────────
# OS detection helpers
# ──────────────────────────────────────────────


def detect_os_family(os_id: str) -> str:
    """Return ``'debian'``, ``'rhel'``, ``'alpine'``, or ``'unknown'``."""
    lower = os_id.lower().strip('"').strip("'")
    if lower in DEBIAN_LIKE:
        return "debian"
    if lower in RHEL_LIKE:
        return "rhel"
    if lower in ALPINE_LIKE:
        return "alpine"
    return "unknown"


# ──────────────────────────────────────────────
# Port / network helpers
# ──────────────────────────────────────────────


def parse_ss_output(output: str) -> list[dict[str, str]]:
    """Parse ``ss -tlnup`` output into structured entries."""
    entries: list[dict[str, str]] = []
    for line in output.splitlines():
        if line.startswith("Netid") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0]
        local = parts[4]
        process = parts[-1] if len(parts) > 5 else ""
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


def is_address_exposed(address: str) -> bool:
    """Return True if the address is externally reachable (not loopback)."""
    loopback = {"127.0.0.1", "::1", "[::1]", "localhost"}
    cleaned = address.strip("[]")
    return cleaned not in loopback and not cleaned.startswith("127.")


# ──────────────────────────────────────────────
# Misc
# ──────────────────────────────────────────────


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate *text* to *max_len* characters."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"


def sanitise_evidence(text: str) -> str:
    """Remove potentially sensitive data from evidence strings.

    Strips anything that looks like a password hash, private key content,
    or token.
    """
    # Mask password hashes ($6$..., $y$...)
    text = re.sub(r"\$[0-9a-z]+\$[^\s:]+", "<HASH_REDACTED>", text, flags=re.IGNORECASE)
    # Mask private key contents
    text = re.sub(
        r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----",
        "<PRIVATE_KEY_REDACTED>",
        text,
        flags=re.DOTALL,
    )
    return text


def safe_get(mapping: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Traverse nested dicts safely."""
    current: Any = mapping
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current
