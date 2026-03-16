"""Simple and clean HTML report generator for SentinelAudit."""

from __future__ import annotations

import html
import logging
from pathlib import Path

from sentinel_audit.core.models import AuditResult, Severity

logger = logging.getLogger(__name__)


class HtmlReportGenerator:
    """Generate a lightweight standalone HTML report."""

    def generate(self, result: AuditResult, output_path: str | None = None) -> str:
        severity_rows = "\n".join(
            f"<tr><td>{severity.value}</td><td>{result.score.breakdown.get(severity.value, 0)}</td></tr>"
            for severity in Severity
        )

        findings_html = []
        for finding in result.findings:
            findings_html.append(
                """
                <div class="finding severity-{severity}">
                    <h3>[{severity}] {title} <span class="id">({id})</span></h3>
                    <p><strong>Description:</strong> {description}</p>
                    <p><strong>Evidence:</strong> <code>{evidence}</code></p>
                    <p><strong>Recommendation:</strong> {recommendation}</p>
                    <p><strong>Category:</strong> {category}</p>
                </div>
                """.format(
                    severity=html.escape(finding.severity.value.lower()),
                    title=html.escape(finding.title),
                    id=html.escape(finding.id),
                    description=html.escape(finding.description),
                    evidence=html.escape(finding.evidence or "N/A"),
                    recommendation=html.escape(finding.recommendation or "N/A"),
                    category=html.escape(finding.category),
                )
            )

        recommendations = self._collect_recommendations(result)
        recommendations_html = "\n".join(
            f"<li>{html.escape(rec)}</li>" for rec in recommendations
        ) or "<li>No specific recommendation.</li>"

        ip_addresses = [item.get("address", "") for item in result.system_info.network_interfaces if item.get("address")]

        html_report = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SentinelAudit Report - {html.escape(result.target)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }}
    h1, h2 {{ margin-bottom: 8px; }}
    .meta, .card {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin: 12px 0; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 8px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px; text-align: left; }}
    th {{ background: #f9fafb; }}
    .finding {{ border: 1px solid #e5e7eb; border-left-width: 6px; border-radius: 8px; padding: 10px; margin: 10px 0; }}
    .severity-critical {{ border-left-color: #dc2626; }}
    .severity-high {{ border-left-color: #f97316; }}
    .severity-medium {{ border-left-color: #eab308; }}
    .severity-low {{ border-left-color: #22c55e; }}
    .severity-info {{ border-left-color: #3b82f6; }}
    code {{ background: #f3f4f6; padding: 1px 4px; border-radius: 4px; }}
    .id {{ color: #6b7280; font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>SentinelAudit Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> {html.escape(result.target)}</p>
    <p><strong>Score:</strong> {result.score.score}/100 ({html.escape(result.score.grade)})</p>
    <p><strong>Risk:</strong> {html.escape(result.score.risk_summary)}</p>
    <p><strong>Total findings:</strong> {len(result.findings)}</p>
  </div>

  <h2>System Information</h2>
  <div class="card">
    <p><strong>Hostname:</strong> {html.escape(result.system_info.hostname)}</p>
    <p><strong>OS:</strong> {html.escape(result.system_info.os_name)} {html.escape(result.system_info.os_version)}</p>
    <p><strong>Kernel:</strong> {html.escape(result.system_info.kernel_version)}</p>
    <p><strong>Uptime:</strong> {html.escape(result.system_info.uptime)}</p>
    <p><strong>IP addresses:</strong> {html.escape(', '.join(ip_addresses) if ip_addresses else 'N/A')}</p>
  </div>

  <h2>Findings by Severity</h2>
  <table>
    <thead><tr><th>Severity</th><th>Count</th></tr></thead>
    <tbody>
      {severity_rows}
    </tbody>
  </table>

  <h2>Findings</h2>
  {''.join(findings_html) if findings_html else '<p>No findings detected.</p>'}

  <h2>Recommendations</h2>
  <ul>
    {recommendations_html}
  </ul>
</body>
</html>
"""

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(html_report, encoding="utf-8")
            logger.info("HTML report written to %s", path)

        return html_report

    @staticmethod
    def _collect_recommendations(result: AuditResult) -> list[str]:
        seen: set[str] = set()
        recommendations: list[str] = []
        for finding in result.findings:
            rec = finding.recommendation.strip()
            if rec and rec not in seen:
                seen.add(rec)
                recommendations.append(rec)
        return recommendations
