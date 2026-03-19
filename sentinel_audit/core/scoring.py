"""
sentinel_audit/core/scoring.py
───────────────────────────────
Security scoring engine with diminishing returns and per-severity caps.

Penalty table (first / subsequent / cap per severity):

    CRITICAL  → 15 / 10 / 40
    HIGH      →  8 /  5 / 30
    MEDIUM    →  3 /  2 / 20
    LOW       →  1 /  1 / 10
    INFO      →  0 /  0 /  0

The final score is clamped to [5, 100] — a score of 0 would imply the
system is actively compromised, which is a different claim from "poorly
configured".
"""

from __future__ import annotations

import logging

from sentinel_audit.core.constants import (
    GRADE_THRESHOLDS,
    SCORE_CEILING,
    SCORE_FLOOR,
    SCORING_PENALTIES,
    Severity,
)
from sentinel_audit.core.models import AuditResult, SecurityScore

logger = logging.getLogger(__name__)


def compute_grade(score: int) -> str:
    """Return a letter grade for the given integer score."""
    for threshold, grade in GRADE_THRESHOLDS:
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
        return f"Critical risk posture: {critical} critical finding(s) require immediate remediation."
    if high >= 3:
        return f"High risk posture: {high} high-severity findings materially increase exposure."
    if high > 0 or medium >= 5:
        return "Elevated risk posture: prioritize high and medium findings."
    if medium > 0 or low >= 5:
        return "Moderate risk posture: hardening is recommended."
    if low > 0:
        return "Low risk posture: minor hardening opportunities detected."

    if score >= 90:
        return "Very low risk posture: no significant findings detected."
    return "Low risk posture: limited findings detected."


def compute_score(result: AuditResult) -> SecurityScore:
    """Compute and attach a SecurityScore to *result*.

    Uses diminishing returns: the first finding of a given severity costs
    more than subsequent ones.  Each severity level has a hard cap to
    prevent a flood of low-severity items from destroying the score.

    Returns the computed SecurityScore (also stored as ``result.score``).
    """
    breakdown: dict[str, int] = {s.value: 0 for s in Severity}
    severity_totals: dict[Severity, float] = dict.fromkeys(Severity, 0.0)

    # Count findings per severity
    for finding in result.findings:
        breakdown[finding.severity.value] += 1

    # Compute penalties with diminishing returns and caps
    raw = 100.0
    for severity in Severity:
        count = breakdown[severity.value]
        if count == 0:
            continue

        first_pen, subseq_pen, cap = SCORING_PENALTIES[severity]
        total_penalty = 0.0

        for i in range(count):
            penalty: float = first_pen if i == 0 else subseq_pen
            if total_penalty + penalty > cap:
                penalty = max(0.0, cap - total_penalty)
            total_penalty += penalty

        severity_totals[severity] = total_penalty
        raw -= total_penalty

    clamped = max(SCORE_FLOOR, min(SCORE_CEILING, int(raw)))
    final_score = int(clamped)
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
