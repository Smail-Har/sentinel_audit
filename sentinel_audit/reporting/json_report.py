"""JSON report generator for SentinelAudit."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sentinel_audit.core.constants import Severity
from sentinel_audit.core.models import AuditResult
from sentinel_audit.reporting.base import collect_recommendations, findings_grouped_by_category

logger = logging.getLogger(__name__)


class JsonReportGenerator:
    """Generate a structured JSON report from an AuditResult."""

    def generate(self, result: AuditResult, output_path: str | None = None) -> dict[str, Any]:
        """Build and optionally write the JSON report payload."""
        findings_by_severity = {
            severity.value: [f.to_dict() for f in result.findings_by_severity(severity)] for severity in Severity
        }

        grouped = findings_grouped_by_category(result)
        by_category = {cat: [f.to_dict() for f in findings] for cat, findings in grouped.items()}

        payload: dict[str, Any] = {
            "metadata": {
                "tool": "SentinelAudit",
                "version": "1.0.0",
                "target": result.target,
                "label": result.label,
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
            "findings": [f.to_dict() for f in result.findings],
            "grouped_findings": {
                "by_severity": findings_by_severity,
                "by_category": by_category,
            },
            "recommendations": collect_recommendations(result),
        }

        if output_path:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("JSON report written to %s", path)

        return payload
