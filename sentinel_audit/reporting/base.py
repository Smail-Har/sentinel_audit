"""
sentinel_audit/reporting/base.py
─────────────────────────────────
Shared utilities for all report generators.
"""

from __future__ import annotations

import re

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult, Finding


def collect_recommendations(result: AuditResult) -> list[str]:
    """Deduplicated list of actionable recommendations (severity >= LOW)."""
    seen: set[str] = set()
    recommendations: list[str] = []
    sorted_findings = sorted(result.findings, key=lambda f: f.severity, reverse=True)
    for finding in sorted_findings:
        # Skip INFO findings — they are informational, not actionable
        if finding.severity == Severity.INFO:
            continue
        rec = finding.recommendation.strip()
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append(rec)
    return recommendations


def top_priority_findings(result: AuditResult, limit: int = 5) -> list[Finding]:
    """Return the top N critical/high findings for executive summary."""
    priority = [f for f in result.findings if f.severity in {Severity.CRITICAL, Severity.HIGH}]
    priority.sort(key=lambda f: f.severity, reverse=True)
    return priority[:limit]


def findings_grouped_by_category(result: AuditResult) -> dict[str, list[Finding]]:
    """Group findings by category, deduplicating overlapping findings."""
    deduped = _deduplicate_findings(result.findings)
    grouped: dict[str, list[Finding]] = {}
    for finding in deduped:
        grouped.setdefault(finding.category, []).append(finding)
    return grouped


# ── Deduplication helpers ─────────────────────────────────────────────

# Regex to extract file paths from evidence / recommendation strings
_PATH_RE = re.compile(r"(/etc/[\w./+-]+)")


def _dedup_key(finding: Finding) -> str | None:
    """Build a dedup key from file paths mentioned in evidence+recommendation.

    Two findings that reference the exact same set of config files are
    considered duplicates (e.g. PERM-006 and CIS-5.2.1 both target
    ``/etc/ssh/sshd_config``).  Returns None when no paths are found
    (no dedup possible).
    """
    paths = sorted(set(_PATH_RE.findall(finding.evidence + " " + finding.recommendation)))
    if not paths:
        return None
    return ",".join(paths)


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove findings that duplicate an already-seen file set.

    When two findings overlap, the one with the higher severity (or the
    first encountered) is kept; the other is dropped.
    """
    seen_keys: dict[str, Finding] = {}
    result: list[Finding] = []
    for f in findings:
        key = _dedup_key(f)
        if key is None:
            # No file paths — no dedup, always keep
            result.append(f)
            continue
        if key in seen_keys:
            existing = seen_keys[key]
            # Keep the higher-severity one
            if f.severity > existing.severity:
                result.remove(existing)
                seen_keys[key] = f
                result.append(f)
            # else: skip the duplicate
        else:
            seen_keys[key] = f
            result.append(f)
    return result
