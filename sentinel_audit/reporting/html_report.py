"""HTML report generator for SentinelAudit using Jinja2."""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult
from sentinel_audit.reporting.base import (
    collect_recommendations,
    findings_grouped_by_category,
    top_priority_findings,
)

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


class HtmlReportGenerator:
    """Generate a professional standalone HTML report via Jinja2."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "jinja2"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, result: AuditResult, output_path: str | None = None) -> str:
        si = result.system_info
        ip_addresses = [item.get("address", "") for item in si.network_interfaces if item.get("address")]

        template = self._env.get_template("html_report.jinja2")
        html_report = template.render(
            target=result.label or result.target,
            score=result.score,
            system_info=si,
            ip_addresses=ip_addresses,
            duration=result.duration_seconds,
            severities=[s.value for s in Severity],
            breakdown=result.score.breakdown,
            top_findings=top_priority_findings(result),
            grouped_findings=findings_grouped_by_category(result),
            recommendations=collect_recommendations(result),
            generated_at=result.started_at.strftime("%Y-%m-%d %H:%M UTC"),
        )

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html_report, encoding="utf-8")
            logger.info("HTML report written to %s", path)

        return html_report
