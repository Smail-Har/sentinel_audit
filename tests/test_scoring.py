from __future__ import annotations

from sentinel_audit.core.models import AuditResult, Finding, Severity
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


def test_compute_grade_thresholds() -> None:
    assert compute_grade(95) == "A"
    assert compute_grade(80) == "B"
    assert compute_grade(65) == "C"
    assert compute_grade(50) == "D"
    assert compute_grade(10) == "F"


def test_compute_score_breakdown_and_final_score() -> None:
    result = AuditResult(target="localhost")
    result.add_finding(_finding("F-CRIT", Severity.CRITICAL))
    result.add_finding(_finding("F-HIGH", Severity.HIGH))
    result.add_finding(_finding("F-MED", Severity.MEDIUM))
    result.add_finding(_finding("F-LOW", Severity.LOW))
    result.add_finding(_finding("F-INFO", Severity.INFO))

    score = compute_score(result)

    assert score.score == 63  # 100 - (20 + 10 + 5 + 2 + 0)
    assert score.grade == "C"
    assert score.total_findings == 5
    assert score.breakdown == {
        "INFO": 1,
        "LOW": 1,
        "MEDIUM": 1,
        "HIGH": 1,
        "CRITICAL": 1,
    }
    assert "Critical risk posture" in score.risk_summary


def test_compute_score_is_clamped_to_zero() -> None:
    result = AuditResult(target="localhost")
    for index in range(10):
        result.add_finding(_finding(f"C-{index}", Severity.CRITICAL))

    score = compute_score(result)

    assert score.raw_score == -100
    assert score.score == 0
    assert score.grade == "F"
    assert score.breakdown["CRITICAL"] == 10
