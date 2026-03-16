"""Console summary reporter for SentinelAudit."""

from __future__ import annotations

import logging

from sentinel_audit.core.models import AuditResult, Severity

logger = logging.getLogger(__name__)


class ConsoleReportGenerator:
    """Generate a compact console-friendly summary report."""

    def generate(self, result: AuditResult) -> str:
        lines: list[str] = []

        lines.append(f"SentinelAudit | Target: {result.target}")
        lines.append("=" * 72)
        lines.append(
            f"Score: {result.score.score}/100 ({result.score.grade}) | Risk: {result.score.risk_summary}"
        )
        lines.append(
            f"System: {result.system_info.hostname} | {result.system_info.os_name} {result.system_info.os_version} | Kernel: {result.system_info.kernel_version}"
        )
        lines.append(f"Uptime: {result.system_info.uptime}")

        ip_addresses = [item.get("address", "") for item in result.system_info.network_interfaces if item.get("address")]
        lines.append(f"IP: {', '.join(ip_addresses) if ip_addresses else 'N/A'}")
        lines.append("-" * 72)

        lines.append("Findings by severity:")
        for severity in Severity:
            lines.append(f"  - {severity.value:8}: {result.score.breakdown.get(severity.value, 0)}")

        lines.append("-" * 72)
        lines.append("Top critical/high findings:")

        priority_findings = [
            finding
            for finding in result.findings
            if finding.severity in {Severity.CRITICAL, Severity.HIGH}
        ]

        if not priority_findings:
            lines.append("  - No findings detected.")
        else:
            ordered_findings = sorted(
                priority_findings,
                key=lambda finding: [
                    Severity.CRITICAL,
                    Severity.HIGH,
                ].index(finding.severity),
            )
            for finding in ordered_findings[:15]:
                lines.append(
                    f"  - [{finding.severity.value}] {finding.id} | {finding.title}"
                )

        lines.append("-" * 72)
        lines.append("Recommendations:")
        recommendations = self._collect_recommendations(result)
        if recommendations:
            for rec in recommendations[:10]:
                lines.append(f"  - {rec}")
        else:
            lines.append("  - No specific recommendation.")

        output = "\n".join(lines)
        logger.info("Console report generated for %s", result.target)
        return output

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
