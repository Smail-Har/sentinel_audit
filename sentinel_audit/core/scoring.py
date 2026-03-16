"""
sentinel_audit/core/scoring.py
───────────────────────────────
Security scoring engine.

Each finding reduces the global score based on its severity. The final
score is clamped to [0, 100] and converted to a letter grade.

Penalty table (configurable via *ScoringConfig*):

    CRITICAL  → −20
    HIGH      → −10
    MEDIUM    →  −5
    LOW       →  −2
    INFO      →   0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sentinel_audit.core.models import AuditResult, SecurityScore, Severity

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Penalty weights
# ──────────────────────────────────────────────

@dataclass
class ScoringConfig:
    """Penalty weights applied per severity level."""

    penalties: dict[Severity, int] = field(
        default_factory=lambda: {
            Severity.CRITICAL: 20,
            Severity.HIGH: 10,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
    )

    def penalty(self, severity: Severity) -> int:
        return self.penalties.get(severity, 0)


DEFAULT_SCORING = ScoringConfig()


# ──────────────────────────────────────────────
# Grade thresholds
# ──────────────────────────────────────────────

_GRADE_THRESHOLDS = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (45, "D"),
    (0,  "F"),
]


def compute_grade(score: int) -> str:
    """Return a letter grade for the given integer score."""
    for threshold, grade in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _build_risk_summary(score: int, breakdown: dict[str, int]) -> str:
    """Build a concise risk summary based on score and severity distribution."""
    critical = breakdown.get(Severity.CRITICAL.value, 0)
    high = breakdown.get(Severity.HIGH.value, 0)
    medium = breakdown.get(Severity.MEDIUM.value, 0)
    low = breakdown.get(Severity.LOW.value, 0)

    if critical > 0:
        return (
            f"Critical risk posture: {critical} critical finding(s) require immediate remediation."
        )
    if high >= 3:
        return (
            f"High risk posture: {high} high-severity findings materially increase exposure."
        )
    if high > 0 or medium >= 5:
        return "Elevated risk posture: prioritize high and medium findings."
    if medium > 0 or low >= 5:
        return "Moderate risk posture: hardening is recommended."
    if low > 0:
        return "Low risk posture: minor hardening opportunities detected."

    if score >= 90:
        return "Very low risk posture: no significant findings detected."
    return "Low risk posture: limited findings detected."


# ──────────────────────────────────────────────
# Public scoring function
# ──────────────────────────────────────────────

def compute_score(result: AuditResult, config: ScoringConfig = DEFAULT_SCORING) -> SecurityScore:
    """
    Compute and attach a :class:`~sentinel_audit.core.models.SecurityScore`
    to *result*.

    The calculation starts at 100 and deducts a penalty for every finding
    according to its severity.  Duplicate-penalty protection: a single
    severity level cannot remove more than 40 points total, preventing
    a flood of low-severity findings from decimating the score unfairly.

    Returns
    -------
    SecurityScore
        The computed score (also stored as ``result.score``).
    """
    breakdown: dict[str, int] = {s.value: 0 for s in Severity}
    raw = 100.0

    for finding in result.findings:
        breakdown[finding.severity.value] += 1
        base_penalty = config.penalty(finding.severity)
        raw -= base_penalty

    final_score = max(0, min(100, int(raw)))
    grade = compute_grade(final_score)
    risk_summary = _build_risk_summary(final_score, breakdown)

    security_score = SecurityScore(
        raw_score=raw,
        score=final_score,
        grade=grade,
        risk_summary=risk_summary,
        total_findings=len(result.findings),
        breakdown=breakdown,
    )

    logger.info(
        "Scoring complete: %d/100 (%s) — %d findings — %s",
        final_score,
        grade,
        len(result.findings),
        risk_summary,
    )

    result.score = security_score
    return security_score
