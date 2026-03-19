"""Consolidated multi-target report generator for SentinelAudit."""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult
from sentinel_audit.reporting.base import top_priority_findings

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class ConsolidatedReportGenerator:
    """Generate a single HTML report summarising multiple audit targets."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "jinja2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, results: list[AuditResult], output_path: str) -> str:
        summaries = []
        for r in results:
            summaries.append(
                {
                    "target": r.label or r.target,
                    "score": r.score.score,
                    "grade": r.score.grade,
                    "risk": r.score.risk_summary,
                    "total_findings": len(r.findings),
                    "breakdown": r.score.breakdown,
                    "top_findings": [
                        {
                            "severity": f.severity.value,
                            "title": f.title,
                            "recommendation": f.recommendation,
                        }
                        for f in top_priority_findings(r, limit=3)
                    ],
                }
            )

        avg_score = round(sum(s["score"] for s in summaries) / len(summaries)) if summaries else 0

        template = self._env.get_template("consolidated_report.jinja2")
        html_report = template.render(
            summaries=summaries,
            avg_score=avg_score,
            total_targets=len(results),
            severities=[s.value for s in Severity],
        )

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_report, encoding="utf-8")
        logger.info("Consolidated report written to %s (%d targets)", path, len(results))
        return html_report
