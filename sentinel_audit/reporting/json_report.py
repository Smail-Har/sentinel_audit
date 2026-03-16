"""JSON report generator for SentinelAudit."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sentinel_audit.core.models import AuditResult, Severity

logger = logging.getLogger(__name__)


class JsonReportGenerator:
    """Generate a structured JSON report from an :class:`AuditResult`."""

    def generate(self, result: AuditResult, output_path: str | None = None) -> dict[str, Any]:
        """Build and optionally write the JSON-compatible report payload."""
        findings_by_severity = {
            severity.value: [f.to_dict() for f in result.findings_by_severity(severity)]
            for severity in Severity
        }

        payload: dict[str, Any] = {
            "metadata": {
                "tool": "SentinelAudit",
                "target": result.target,
                "started_at": result.started_at.isoformat(),
                "finished_at": result.finished_at.isoformat() if result.finished_at else None,
                "duration_seconds": result.duration_seconds,
            },
            "system_info": result.system_info.to_dict(),
            "security_score": result.score.to_dict(),
            "summary": {
                "total_findings": len(result.findings),
                "findings_by_severity": result.score.breakdown,
                "risk_summary": result.score.risk_summary,
                "audit_errors": result.audit_errors,
            },
            "findings": [finding.to_dict() for finding in result.findings],
            "grouped_findings": {
                "by_severity": findings_by_severity,
                "by_category": self._group_findings_by_category(result),
            },
            "recommendations": self._collect_recommendations(result),
        }

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("JSON report written to %s", path)

        return payload

    @staticmethod
    def _group_findings_by_category(result: AuditResult) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for finding in result.findings:
            grouped.setdefault(finding.category, []).append(finding.to_dict())
        return grouped

    @staticmethod
    def _collect_recommendations(result: AuditResult) -> list[str]:
        recommendations: list[str] = []
        seen: set[str] = set()
        for finding in result.findings:
            rec = finding.recommendation.strip()
            if rec and rec not in seen:
                seen.add(rec)
                recommendations.append(rec)
        return recommendations
