"""
sentinel_audit/core/constants.py
─────────────────────────────────
Central constants: severity weights, grade thresholds, command whitelist.
"""

from __future__ import annotations

from enum import StrEnum

# ──────────────────────────────────────────────
# Severity weights for scoring
# ──────────────────────────────────────────────


class Severity(StrEnum):
    """Finding severity levels, ordered from lowest to highest impact."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] < _SEVERITY_RANK[other.value]

    def __le__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] <= _SEVERITY_RANK[other.value]

    def __gt__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] > _SEVERITY_RANK[other.value]

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_RANK[self.value] >= _SEVERITY_RANK[other.value]


_SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Scoring penalties: (first_finding_penalty, subsequent_penalty, cap_per_severity)
SCORING_PENALTIES: dict[Severity, tuple[int, int, int]] = {
    Severity.CRITICAL: (15, 10, 40),
    Severity.HIGH: (8, 5, 30),
    Severity.MEDIUM: (3, 2, 20),
    Severity.LOW: (1, 1, 10),
    Severity.INFO: (0, 0, 0),
}

SCORE_FLOOR: int = 5
SCORE_CEILING: int = 100

GRADE_THRESHOLDS: list[tuple[int, str]] = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (45, "D"),
    (0, "F"),
]


# ──────────────────────────────────────────────
# Supported report formats
# ──────────────────────────────────────────────

VALID_FORMATS: frozenset[str] = frozenset({"json", "md", "html", "pdf", "console", "all"})
ALL_REPORT_FORMATS: list[str] = ["json", "md", "html", "console"]


# ──────────────────────────────────────────────
# OS family detection
# ──────────────────────────────────────────────

DEBIAN_LIKE: frozenset[str] = frozenset(
    {
        "debian",
        "ubuntu",
        "linuxmint",
        "pop",
        "kali",
        "raspbian",
    }
)

RHEL_LIKE: frozenset[str] = frozenset(
    {
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "fedora",
        "ol",
    }
)

ALPINE_LIKE: frozenset[str] = frozenset({"alpine"})


# ──────────────────────────────────────────────
# Default timeouts
# ──────────────────────────────────────────────

DEFAULT_CMD_TIMEOUT: int = 30
DEFAULT_SSH_CONNECT_TIMEOUT: int = 15
