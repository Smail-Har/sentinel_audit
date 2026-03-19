"""Tests for the scoring engine with diminishing returns and caps."""

from __future__ import annotations

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult, Finding
from sentinel_audit.core.scoring import compute_grade, compute_score


def _finding(identifier: str, severity: Severity) -> Finding:
    return Finding(
        id=identifier,
        title=f"Finding {identifier}",
        description="Test finding",
        severity=severity,
        category="test",
        evidence="evidence",
        recommendation="recommendation",
    )


# ── Grade thresholds ──


def test_compute_grade_thresholds() -> None:
    assert compute_grade(95) == "A"
    assert compute_grade(90) == "A"
    assert compute_grade(80) == "B"
    assert compute_grade(75) == "B"
    assert compute_grade(65) == "C"
    assert compute_grade(60) == "C"
    assert compute_grade(50) == "D"
    assert compute_grade(45) == "D"
    assert compute_grade(30) == "F"
    assert compute_grade(5) == "F"


# ── Score computation ──


def test_one_of_each_severity() -> None:
    """One finding per severity: 100 - 15 - 8 - 3 - 1 - 0 = 73."""
    result = AuditResult(target="localhost")
    result.add_finding(_finding("C1", Severity.CRITICAL))
    result.add_finding(_finding("H1", Severity.HIGH))
    result.add_finding(_finding("M1", Severity.MEDIUM))
    result.add_finding(_finding("L1", Severity.LOW))
    result.add_finding(_finding("I1", Severity.INFO))

    score = compute_score(result)

    # 100 - 15 - 8 - 3 - 1 - 0 = 73
    assert score.score == 73
    assert score.grade == "C"
    assert score.total_findings == 5
    assert score.breakdown == {
        "INFO": 1,
        "LOW": 1,
        "MEDIUM": 1,
        "HIGH": 1,
        "CRITICAL": 1,
    }


def test_diminishing_returns_critical() -> None:
    """3 CRITICALs: 15 + 10 + 10 = 35 → score 65."""
    result = AuditResult(target="localhost")
    for i in range(3):
        result.add_finding(_finding(f"C{i}", Severity.CRITICAL))

    score = compute_score(result)
    assert score.score == 65
    assert score.grade == "C"


def test_critical_cap_at_40() -> None:
    """Many CRITICALs hit the 40-point cap: score = 100 - 40 = 60."""
    result = AuditResult(target="localhost")
    for i in range(10):
        result.add_finding(_finding(f"C{i}", Severity.CRITICAL))

    score = compute_score(result)
    assert score.score == 60
    assert score.breakdown["CRITICAL"] == 10


def test_high_cap_at_30() -> None:
    """Many HIGHs hit the 30-point cap: score = 100 - 30 = 70."""
    result = AuditResult(target="localhost")
    for i in range(20):
        result.add_finding(_finding(f"H{i}", Severity.HIGH))

    score = compute_score(result)
    assert score.score == 70


def test_medium_cap_at_20() -> None:
    """Many MEDIUMs hit the 20-point cap: score = 100 - 20 = 80."""
    result = AuditResult(target="localhost")
    for i in range(30):
        result.add_finding(_finding(f"M{i}", Severity.MEDIUM))

    score = compute_score(result)
    assert score.score == 80


def test_low_cap_at_10() -> None:
    """Many LOWs hit the 10-point cap: score = 100 - 10 = 90."""
    result = AuditResult(target="localhost")
    for i in range(50):
        result.add_finding(_finding(f"L{i}", Severity.LOW))

    score = compute_score(result)
    assert score.score == 90


def test_info_has_zero_penalty() -> None:
    """INFO findings have no penalty at all."""
    result = AuditResult(target="localhost")
    for i in range(100):
        result.add_finding(_finding(f"I{i}", Severity.INFO))

    score = compute_score(result)
    assert score.score == 100
    assert score.grade == "A"


def test_score_floor_at_5() -> None:
    """All caps combined: 40 + 30 + 20 + 10 = 100 → clamped to 5."""
    result = AuditResult(target="localhost")
    for i in range(10):
        result.add_finding(_finding(f"C{i}", Severity.CRITICAL))
    for i in range(20):
        result.add_finding(_finding(f"H{i}", Severity.HIGH))
    for i in range(30):
        result.add_finding(_finding(f"M{i}", Severity.MEDIUM))
    for i in range(50):
        result.add_finding(_finding(f"L{i}", Severity.LOW))

    score = compute_score(result)
    assert score.score == 5
    assert score.grade == "F"


def test_empty_findings_perfect_score() -> None:
    """No findings = perfect score."""
    result = AuditResult(target="localhost")
    score = compute_score(result)
    assert score.score == 100
    assert score.grade == "A"
    assert score.total_findings == 0


def test_risk_summary_critical() -> None:
    result = AuditResult(target="localhost")
    result.add_finding(_finding("C1", Severity.CRITICAL))
    score = compute_score(result)
    assert "Critical risk" in score.risk_summary


def test_risk_summary_high() -> None:
    result = AuditResult(target="localhost")
    for i in range(3):
        result.add_finding(_finding(f"H{i}", Severity.HIGH))
    score = compute_score(result)
    assert "High risk" in score.risk_summary


def test_risk_summary_perfect() -> None:
    result = AuditResult(target="localhost")
    score = compute_score(result)
    assert "Very low risk" in score.risk_summary
