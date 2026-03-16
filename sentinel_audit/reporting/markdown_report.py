"""Markdown report generator for SentinelAudit (GitHub friendly)."""

from __future__ import annotations

import logging
from pathlib import Path

from sentinel_audit.core.models import AuditResult, Severity

logger = logging.getLogger(__name__)


class MarkdownReportGenerator:
    """Generate a GitHub-readable Markdown report."""

    def generate(self, result: AuditResult, output_path: str | None = None) -> str:
        lines: list[str] = []

        lines.append(f"# SentinelAudit Report — {result.target}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append(f"- **Score:** {result.score.score}/100 ({result.score.grade})")
        lines.append(f"- **Risk:** {result.score.risk_summary}")
        lines.append(f"- **Total findings:** {len(result.findings)}")
        lines.append("")

        lines.append("## System Information")
        lines.append("")
        lines.append(f"- **Hostname:** {result.system_info.hostname}")
        lines.append(f"- **OS:** {result.system_info.os_name} {result.system_info.os_version}")
        lines.append(f"- **Kernel:** {result.system_info.kernel_version}")
        lines.append(f"- **Uptime:** {result.system_info.uptime}")

        ip_addresses = [item.get("address", "") for item in result.system_info.network_interfaces if item.get("address")]
        lines.append(f"- **IP addresses:** {', '.join(ip_addresses) if ip_addresses else 'N/A'}")
        lines.append("")

        lines.append("## Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        for severity in Severity:
            lines.append(f"| {severity.value} | {result.score.breakdown.get(severity.value, 0)} |")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        if not result.findings:
            lines.append("No findings detected.")
            lines.append("")
        else:
            for finding in result.findings:
                lines.append(f"### [{finding.severity.value}] {finding.title} ({finding.id})")
                lines.append("")
                lines.append(f"- **Description:** {finding.description}")
                lines.append(f"- **Evidence:** `{finding.evidence or 'N/A'}`")
                lines.append(f"- **Recommendation:** {finding.recommendation or 'N/A'}")
                lines.append(f"- **Category:** {finding.category}")
                lines.append("")

        lines.append("## Recommendations")
        lines.append("")
        recommendations = self._collect_recommendations(result)
        if recommendations:
            for rec in recommendations:
                lines.append(f"- {rec}")
        else:
            lines.append("- No specific recommendation.")
        lines.append("")

        markdown = "\n".join(lines)
        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(markdown, encoding="utf-8")
            logger.info("Markdown report written to %s", path)

        return markdown

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
