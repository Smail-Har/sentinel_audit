"""Tests for reporting modules."""

from __future__ import annotations

from tests.conftest import make_finding, make_result

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.scoring import compute_score
from sentinel_audit.reporting.base import (
    collect_recommendations,
    findings_grouped_by_category,
    top_priority_findings,
)
from sentinel_audit.reporting.json_report import JsonReportGenerator
from sentinel_audit.reporting.markdown_report import MarkdownReportGenerator


def _build_result():
    result = make_result()
    result.add_finding(make_finding("C1", "Critical issue", Severity.CRITICAL, "ssh", recommendation="Fix SSH"))
    result.add_finding(make_finding("H1", "High issue", Severity.HIGH, "firewall", recommendation="Fix firewall"))
    result.add_finding(make_finding("M1", "Medium issue", Severity.MEDIUM, "users", recommendation="Fix users"))
    compute_score(result)
    return result


# ── base helpers ──

def test_collect_recommendations_deduped() -> None:
    result = make_result()
    result.add_finding(make_finding("A", recommendation="Do X"))
    result.add_finding(make_finding("B", recommendation="Do X"))  # Duplicate
    result.add_finding(make_finding("C", recommendation="Do Y"))

    recs = collect_recommendations(result)
    assert len(recs) == 2
    assert "Do X" in recs
    assert "Do Y" in recs


def test_collect_recommendations_excludes_info() -> None:
    """INFO findings should not appear in the recommendations list."""
    result = make_result()
    result.add_finding(make_finding("H1", severity=Severity.HIGH, recommendation="Fix this"))
    result.add_finding(make_finding("I1", severity=Severity.INFO, recommendation="No action needed"))
    result.add_finding(make_finding("I2", severity=Severity.INFO, recommendation="Informational only"))

    recs = collect_recommendations(result)
    assert len(recs) == 1
    assert "Fix this" in recs
    assert "No action needed" not in recs


def test_top_priority_findings_limit() -> None:
    result = make_result()
    for i in range(10):
        result.add_finding(make_finding(f"C{i}", severity=Severity.CRITICAL))

    top = top_priority_findings(result, limit=5)
    assert len(top) == 5


def test_top_priority_excludes_low() -> None:
    result = make_result()
    result.add_finding(make_finding("L1", severity=Severity.LOW))
    result.add_finding(make_finding("M1", severity=Severity.MEDIUM))

    top = top_priority_findings(result)
    assert len(top) == 0


def test_findings_grouped_by_category() -> None:
    result = _build_result()
    grouped = findings_grouped_by_category(result)
    assert "ssh" in grouped
    assert "firewall" in grouped
    assert len(grouped["ssh"]) == 1


def test_findings_dedup_same_file_same_remediation() -> None:
    """PERM-006 and CIS-5.2.1 point to same file — should be deduped."""
    result = make_result()
    result.add_finding(make_finding(
        "PERM-006", "Incorrect permissions on /etc/ssh/sshd_config",
        Severity.HIGH, "permissions",
        evidence="/etc/ssh/sshd_config: mode 644 (expected 600)",
        recommendation="chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config",
    ))
    result.add_finding(make_finding(
        "CIS-5.2.1", "Ensure permissions on /etc/ssh/sshd_config are configured",
        Severity.HIGH, "compliance",
        evidence="644",
        recommendation="chmod 600 /etc/ssh/sshd_config",
    ))

    grouped = findings_grouped_by_category(result)
    total = sum(len(fs) for fs in grouped.values())
    # One should be deduped — only 1 finding total
    assert total == 1


# ── JSON reporter ──

def test_json_report_is_valid_json() -> None:
    result = _build_result()
    data = JsonReportGenerator().generate(result)

    assert isinstance(data, dict)
    assert data["metadata"]["target"] == "localhost"
    assert "security_score" in data
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) == 3


# ── Markdown reporter ──

def test_markdown_report_structure() -> None:
    result = _build_result()
    md = MarkdownReportGenerator().generate(result)

    assert "# SentinelAudit Report" in md
    assert "## Executive Summary" in md
    assert "## Top Priority Actions" in md
    assert "## System Information" in md
    assert "## Detailed Findings" in md
    assert "## Recommendations" in md
    assert "Confidential" in md
